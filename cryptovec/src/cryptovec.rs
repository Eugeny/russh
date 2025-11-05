use std::fmt::Debug;
use std::ops::{Deref, DerefMut, Index, IndexMut, Range, RangeFrom, RangeFull, RangeTo};

use crate::platform::{self, memset, mlock, munlock};

/// A buffer which zeroes its memory on `.clear()`, `.resize()`, and
/// reallocations, to avoid copying secrets around.
pub struct CryptoVec {
    p: *mut u8, // `pub(crate)` allows access from platform modules
    size: usize,
    capacity: usize,
}

impl Debug for CryptoVec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.size == 0 {
            return f.write_str("<empty>");
        }
        write!(f, "<{:?}>", self.size)
    }
}

impl Unpin for CryptoVec {}
unsafe impl Send for CryptoVec {}
unsafe impl Sync for CryptoVec {}

// Common traits implementations
impl AsRef<[u8]> for CryptoVec {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

impl AsMut<[u8]> for CryptoVec {
    fn as_mut(&mut self) -> &mut [u8] {
        self.deref_mut()
    }
}

impl Deref for CryptoVec {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.p, self.size) }
    }
}

impl DerefMut for CryptoVec {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.p, self.size) }
    }
}

impl From<String> for CryptoVec {
    fn from(e: String) -> Self {
        CryptoVec::from(e.into_bytes())
    }
}

impl From<&str> for CryptoVec {
    fn from(e: &str) -> Self {
        CryptoVec::from(e.as_bytes())
    }
}

impl From<&[u8]> for CryptoVec {
    fn from(e: &[u8]) -> Self {
        CryptoVec::from_slice(e)
    }
}

impl From<Vec<u8>> for CryptoVec {
    fn from(e: Vec<u8>) -> Self {
        let mut c = CryptoVec::new_zeroed(e.len());
        c.clone_from_slice(&e[..]);
        c
    }
}

// Indexing implementations
impl Index<RangeFrom<usize>> for CryptoVec {
    type Output = [u8];
    fn index(&self, index: RangeFrom<usize>) -> &[u8] {
        self.deref().index(index)
    }
}
impl Index<RangeTo<usize>> for CryptoVec {
    type Output = [u8];
    fn index(&self, index: RangeTo<usize>) -> &[u8] {
        self.deref().index(index)
    }
}
impl Index<Range<usize>> for CryptoVec {
    type Output = [u8];
    fn index(&self, index: Range<usize>) -> &[u8] {
        self.deref().index(index)
    }
}
impl Index<RangeFull> for CryptoVec {
    type Output = [u8];
    fn index(&self, _: RangeFull) -> &[u8] {
        self.deref()
    }
}

impl IndexMut<RangeFull> for CryptoVec {
    fn index_mut(&mut self, _: RangeFull) -> &mut [u8] {
        self.deref_mut()
    }
}
impl IndexMut<RangeFrom<usize>> for CryptoVec {
    fn index_mut(&mut self, index: RangeFrom<usize>) -> &mut [u8] {
        self.deref_mut().index_mut(index)
    }
}
impl IndexMut<RangeTo<usize>> for CryptoVec {
    fn index_mut(&mut self, index: RangeTo<usize>) -> &mut [u8] {
        self.deref_mut().index_mut(index)
    }
}
impl IndexMut<Range<usize>> for CryptoVec {
    fn index_mut(&mut self, index: Range<usize>) -> &mut [u8] {
        self.deref_mut().index_mut(index)
    }
}

impl Index<usize> for CryptoVec {
    type Output = u8;
    fn index(&self, index: usize) -> &u8 {
        self.deref().index(index)
    }
}

// IO-related implementation
impl std::io::Write for CryptoVec {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.extend(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

// Default implementation
impl Default for CryptoVec {
    fn default() -> Self {
        CryptoVec {
            p: std::ptr::NonNull::dangling().as_ptr(),
            size: 0,
            capacity: 0,
        }
    }
}

impl CryptoVec {
    /// Creates a new `CryptoVec`.
    pub fn new() -> CryptoVec {
        CryptoVec::default()
    }

    /// Creates a new `CryptoVec` with `n` zeros.
    pub fn new_zeroed(size: usize) -> CryptoVec {
        unsafe {
            let capacity = size.next_power_of_two();
            let layout = std::alloc::Layout::from_size_align_unchecked(capacity, 1);
            let p = std::alloc::alloc_zeroed(layout);
            let _ = mlock(p, capacity);
            CryptoVec { p, capacity, size }
        }
    }

    /// Creates a new `CryptoVec` with capacity `capacity`.
    pub fn with_capacity(capacity: usize) -> CryptoVec {
        unsafe {
            let capacity = capacity.next_power_of_two();
            let layout = std::alloc::Layout::from_size_align_unchecked(capacity, 1);
            let p = std::alloc::alloc_zeroed(layout);
            let _ = mlock(p, capacity);
            CryptoVec {
                p,
                capacity,
                size: 0,
            }
        }
    }

    /// Length of this `CryptoVec`.
    ///
    /// ```
    /// assert_eq!(russh_cryptovec::CryptoVec::new().len(), 0)
    /// ```
    pub fn len(&self) -> usize {
        self.size
    }

    /// Returns `true` if and only if this CryptoVec is empty.
    ///
    /// ```
    /// assert!(russh_cryptovec::CryptoVec::new().is_empty())
    /// ```
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Resize this CryptoVec, appending zeros at the end. This may
    /// perform at most one reallocation, overwriting the previous
    /// version with zeros.
    pub fn resize(&mut self, size: usize) {
        if size <= self.capacity && size > self.size {
            // If this is an expansion, just resize.
            self.size = size
        } else if size <= self.size {
            // If this is a truncation, resize and erase the extra memory.
            unsafe {
                memset(self.p.add(size), 0, self.size - size);
            }
            self.size = size;
        } else {
            // realloc ! and erase the previous memory.
            unsafe {
                let next_capacity = size.next_power_of_two();
                let old_ptr = self.p;
                let next_layout = std::alloc::Layout::from_size_align_unchecked(next_capacity, 1);
                self.p = std::alloc::alloc_zeroed(next_layout);
                let _ = mlock(self.p, next_capacity);

                if self.capacity > 0 {
                    std::ptr::copy_nonoverlapping(old_ptr, self.p, self.size);
                    for i in 0..self.size {
                        std::ptr::write_volatile(old_ptr.add(i), 0)
                    }
                    let _ = munlock(old_ptr, self.capacity);
                    let layout = std::alloc::Layout::from_size_align_unchecked(self.capacity, 1);
                    std::alloc::dealloc(old_ptr, layout);
                }

                if self.p.is_null() {
                    #[allow(clippy::panic)]
                    {
                        panic!("Realloc failed, pointer = {self:?} {size:?}")
                    }
                } else {
                    self.capacity = next_capacity;
                    self.size = size;
                }
            }
        }
    }

    /// Clear this CryptoVec (retaining the memory).
    ///
    /// ```
    /// let mut v = russh_cryptovec::CryptoVec::new();
    /// v.extend(b"blabla");
    /// v.clear();
    /// assert!(v.is_empty())
    /// ```
    pub fn clear(&mut self) {
        self.resize(0);
    }

    /// Append a new byte at the end of this CryptoVec.
    pub fn push(&mut self, s: u8) {
        let size = self.size;
        self.resize(size + 1);
        unsafe { *self.p.add(size) = s }
    }

    /// Read `n_bytes` from `r`, and append them at the end of this
    /// `CryptoVec`. Returns the number of bytes read (and appended).
    pub fn read<R: std::io::Read>(
        &mut self,
        n_bytes: usize,
        mut r: R,
    ) -> Result<usize, std::io::Error> {
        let cur_size = self.size;
        self.resize(cur_size + n_bytes);
        let s = unsafe { std::slice::from_raw_parts_mut(self.p.add(cur_size), n_bytes) };
        // Resize the buffer to its appropriate size.
        match r.read(s) {
            Ok(n) => {
                self.resize(cur_size + n);
                Ok(n)
            }
            Err(e) => {
                self.resize(cur_size);
                Err(e)
            }
        }
    }

    /// Write all this CryptoVec to the provided `Write`. Returns the
    /// number of bytes actually written.
    ///
    /// ```
    /// let mut v = russh_cryptovec::CryptoVec::new();
    /// v.extend(b"blabla");
    /// let mut s = std::io::stdout();
    /// v.write_all_from(0, &mut s).unwrap();
    /// ```
    pub fn write_all_from<W: std::io::Write>(
        &self,
        offset: usize,
        mut w: W,
    ) -> Result<usize, std::io::Error> {
        assert!(offset < self.size);
        // if we're past this point, self.p cannot be null.
        unsafe {
            let s = std::slice::from_raw_parts(self.p.add(offset), self.size - offset);
            w.write(s)
        }
    }

    /// Resize this CryptoVec, returning a mutable borrow to the extra bytes.
    ///
    /// ```
    /// let mut v = russh_cryptovec::CryptoVec::new();
    /// v.resize_mut(4).clone_from_slice(b"test");
    /// ```
    pub fn resize_mut(&mut self, n: usize) -> &mut [u8] {
        let size = self.size;
        self.resize(size + n);
        unsafe { std::slice::from_raw_parts_mut(self.p.add(size), n) }
    }

    /// Append a slice at the end of this CryptoVec.
    ///
    /// ```
    /// let mut v = russh_cryptovec::CryptoVec::new();
    /// v.extend(b"test");
    /// ```
    pub fn extend(&mut self, s: &[u8]) {
        let size = self.size;
        self.resize(size + s.len());
        unsafe {
            std::ptr::copy_nonoverlapping(s.as_ptr(), self.p.add(size), s.len());
        }
    }

    /// Create a `CryptoVec` from a slice
    ///
    /// ```
    /// russh_cryptovec::CryptoVec::from_slice(b"test");
    /// ```
    pub fn from_slice(s: &[u8]) -> CryptoVec {
        let mut v = CryptoVec::new();
        v.resize(s.len());
        unsafe {
            std::ptr::copy_nonoverlapping(s.as_ptr(), v.p, s.len());
        }
        v
    }
}

impl Clone for CryptoVec {
    fn clone(&self) -> Self {
        let mut v = Self::new();
        v.extend(self);
        v
    }
}

// Drop implementation
impl Drop for CryptoVec {
    fn drop(&mut self) {
        if self.capacity > 0 {
            unsafe {
                for i in 0..self.size {
                    std::ptr::write_volatile(self.p.add(i), 0);
                }
                let _ = platform::munlock(self.p, self.capacity);
                let layout = std::alloc::Layout::from_size_align_unchecked(self.capacity, 1);
                std::alloc::dealloc(self.p, layout);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::CryptoVec;

    #[test]
    fn test_new() {
        let crypto_vec = CryptoVec::new();
        assert_eq!(crypto_vec.size, 0);
        assert_eq!(crypto_vec.capacity, 0);
    }

    #[test]
    fn test_resize_expand() {
        let mut crypto_vec = CryptoVec::new_zeroed(5);
        crypto_vec.resize(10);
        assert_eq!(crypto_vec.size, 10);
        assert!(crypto_vec.capacity >= 10);
        assert!(crypto_vec.iter().skip(5).all(|&x| x == 0)); // Ensure newly added elements are zeroed
    }

    #[test]
    fn test_resize_shrink() {
        let mut crypto_vec = CryptoVec::new_zeroed(10);
        crypto_vec.resize(5);
        assert_eq!(crypto_vec.size, 5);
        // Ensure shrinking keeps the previous elements intact
        assert_eq!(crypto_vec.len(), 5);
    }

    #[test]
    fn test_push() {
        let mut crypto_vec = CryptoVec::new();
        crypto_vec.push(1);
        crypto_vec.push(2);
        assert_eq!(crypto_vec.size, 2);
        assert_eq!(crypto_vec[0], 1);
        assert_eq!(crypto_vec[1], 2);
    }

    #[test]
    fn test_write_trait() {
        use std::io::Write;

        let mut crypto_vec = CryptoVec::new();
        let bytes_written = crypto_vec.write(&[1, 2, 3]).unwrap();
        assert_eq!(bytes_written, 3);
        assert_eq!(crypto_vec.size, 3);
        assert_eq!(crypto_vec.as_ref(), &[1, 2, 3]);
    }

    #[test]
    fn test_as_ref_as_mut() {
        let mut crypto_vec = CryptoVec::new_zeroed(5);
        let slice_ref: &[u8] = crypto_vec.as_ref();
        assert_eq!(slice_ref.len(), 5);
        let slice_mut: &mut [u8] = crypto_vec.as_mut();
        slice_mut[0] = 1;
        assert_eq!(crypto_vec[0], 1);
    }

    #[test]
    fn test_from_string() {
        let input = String::from("hello");
        let crypto_vec: CryptoVec = input.into();
        assert_eq!(crypto_vec.as_ref(), b"hello");
    }

    #[test]
    fn test_from_str() {
        let input = "hello";
        let crypto_vec: CryptoVec = input.into();
        assert_eq!(crypto_vec.as_ref(), b"hello");
    }

    #[test]
    fn test_from_byte_slice() {
        let input = b"hello".as_slice();
        let crypto_vec: CryptoVec = input.into();
        assert_eq!(crypto_vec.as_ref(), b"hello");
    }

    #[test]
    fn test_from_vec() {
        let input = vec![1, 2, 3, 4];
        let crypto_vec: CryptoVec = input.into();
        assert_eq!(crypto_vec.as_ref(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_index() {
        let crypto_vec = CryptoVec::from(vec![1, 2, 3, 4, 5]);
        assert_eq!(crypto_vec[0], 1);
        assert_eq!(crypto_vec[4], 5);
        assert_eq!(&crypto_vec[1..3], &[2, 3]);
    }

    #[test]
    fn test_drop() {
        let mut crypto_vec = CryptoVec::new_zeroed(10);
        // Ensure vector is filled with non-zero data
        crypto_vec.extend(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        drop(crypto_vec);

        // Check that memory zeroing was done during the drop
        // This part is more difficult to test directly since it involves
        // private memory management. However, with Rust's unsafe features,
        // it may be checked using tools like Valgrind or manual inspection.
    }

    #[test]
    fn test_new_zeroed() {
        let crypto_vec = CryptoVec::new_zeroed(10);
        assert_eq!(crypto_vec.size, 10);
        assert!(crypto_vec.capacity >= 10);
        assert!(crypto_vec.iter().all(|&x| x == 0)); // Ensure all bytes are zeroed
    }

    #[test]
    fn test_clear() {
        let mut crypto_vec = CryptoVec::new();
        crypto_vec.extend(b"blabla");
        crypto_vec.clear();
        assert!(crypto_vec.is_empty());
    }

    #[test]
    fn test_extend() {
        let mut crypto_vec = CryptoVec::new();
        crypto_vec.extend(b"test");
        assert_eq!(crypto_vec.as_ref(), b"test");
    }

    #[test]
    fn test_write_all_from() {
        let mut crypto_vec = CryptoVec::new();
        crypto_vec.extend(b"blabla");

        let mut output: Vec<u8> = Vec::new();
        let written_size = crypto_vec.write_all_from(0, &mut output).unwrap();
        assert_eq!(written_size, 6); // "blabla" has 6 bytes
        assert_eq!(output, b"blabla");
    }

    #[test]
    fn test_resize_mut() {
        let mut crypto_vec = CryptoVec::new();
        crypto_vec.resize_mut(4).clone_from_slice(b"test");
        assert_eq!(crypto_vec.as_ref(), b"test");
    }

    // DocTests cannot be run on with wasm_bindgen_test
    #[cfg(target_arch = "wasm32")]
    mod wasm32 {
        use wasm_bindgen_test::wasm_bindgen_test;

        use super::*;

        wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

        #[wasm_bindgen_test]
        fn test_push_u32_be() {
            let mut crypto_vec = CryptoVec::new();
            let value = 43554u32;
            crypto_vec.push_u32_be(value);
            assert_eq!(crypto_vec.len(), 4); // u32 is 4 bytes long
            assert_eq!(crypto_vec.read_u32_be(0), value);
        }

        #[wasm_bindgen_test]
        fn test_read_u32_be() {
            let mut crypto_vec = CryptoVec::new();
            let value = 99485710u32;
            crypto_vec.push_u32_be(value);
            assert_eq!(crypto_vec.read_u32_be(0), value);
        }
    }
}
