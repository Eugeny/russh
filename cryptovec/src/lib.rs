#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
use std::ops::{Deref, DerefMut, Index, IndexMut, Range, RangeFrom, RangeFull, RangeTo};

use libc::c_void;
#[cfg(not(windows))]
use libc::size_t;

/// A buffer which zeroes its memory on `.clear()`, `.resize()` and
/// reallocations, to avoid copying secrets around.
#[derive(Debug)]
pub struct CryptoVec {
    p: *mut u8,
    size: usize,
    capacity: usize,
}

impl Unpin for CryptoVec {}

unsafe impl Send for CryptoVec {}
unsafe impl Sync for CryptoVec {}

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

impl From<Vec<u8>> for CryptoVec {
    fn from(e: Vec<u8>) -> Self {
        let mut c = CryptoVec::new_zeroed(e.len());
        c.clone_from_slice(&e[..]);
        c
    }
}

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

impl std::io::Write for CryptoVec {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.extend(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl Default for CryptoVec {
    fn default() -> Self {
        CryptoVec {
            p: std::ptr::NonNull::dangling().as_ptr(),
            size: 0,
            capacity: 0,
        }
    }
}

#[cfg(not(windows))]
unsafe fn mlock(ptr: *const u8, len: usize) {
    libc::mlock(ptr as *const c_void, len as size_t);
}
#[cfg(not(windows))]
unsafe fn munlock(ptr: *const u8, len: usize) {
    libc::munlock(ptr as *const c_void, len as size_t);
}

#[cfg(windows)]
use winapi::shared::basetsd::SIZE_T;
#[cfg(windows)]
use winapi::shared::minwindef::LPVOID;
#[cfg(windows)]
use winapi::um::memoryapi::{VirtualLock, VirtualUnlock};
#[cfg(windows)]
unsafe fn mlock(ptr: *const u8, len: usize) {
    VirtualLock(ptr as LPVOID, len as SIZE_T);
}
#[cfg(windows)]
unsafe fn munlock(ptr: *const u8, len: usize) {
    VirtualUnlock(ptr as LPVOID, len as SIZE_T);
}

impl Clone for CryptoVec {
    fn clone(&self) -> Self {
        let mut v = Self::new();
        v.extend(self);
        v
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
            mlock(p, capacity);
            CryptoVec { p, capacity, size }
        }
    }

    /// Creates a new `CryptoVec` with capacity `capacity`.
    pub fn with_capacity(capacity: usize) -> CryptoVec {
        unsafe {
            let capacity = capacity.next_power_of_two();
            let layout = std::alloc::Layout::from_size_align_unchecked(capacity, 1);
            let p = std::alloc::alloc_zeroed(layout);
            mlock(p, capacity);
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
                libc::memset(self.p.add(size) as *mut c_void, 0, self.size - size);
            }
            self.size = size;
        } else {
            // realloc ! and erase the previous memory.
            unsafe {
                let next_capacity = size.next_power_of_two();
                let old_ptr = self.p;
                let next_layout = std::alloc::Layout::from_size_align_unchecked(next_capacity, 1);
                let new_ptr = std::alloc::alloc_zeroed(next_layout);
                if new_ptr.is_null() {
                    #[allow(clippy::panic)]
                    {
                        panic!("Realloc failed, pointer = {:?} {:?}", self, size)
                    }
                }

                self.p = new_ptr;
                mlock(self.p, next_capacity);

                if self.capacity > 0 {
                    std::ptr::copy_nonoverlapping(old_ptr, self.p, self.size);
                    for i in 0..self.size {
                        std::ptr::write_volatile(old_ptr.add(i), 0)
                    }
                    munlock(old_ptr, self.capacity);
                    let layout = std::alloc::Layout::from_size_align_unchecked(self.capacity, 1);
                    std::alloc::dealloc(old_ptr, layout);
                }

                self.capacity = next_capacity;
                self.size = size;
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

    /// Append a new u32, big endian-encoded, at the end of this CryptoVec.
    ///
    /// ```
    /// let mut v = russh_cryptovec::CryptoVec::new();
    /// let n = 43554;
    /// v.push_u32_be(n);
    /// assert_eq!(n, v.read_u32_be(0))
    /// ```
    pub fn push_u32_be(&mut self, s: u32) {
        let s = s.to_be();
        let x: [u8; 4] = s.to_ne_bytes();
        self.extend(&x)
    }

    /// Read a big endian-encoded u32 from this CryptoVec, with the
    /// first byte at position `i`.
    ///
    /// ```
    /// let mut v = russh_cryptovec::CryptoVec::new();
    /// let n = 99485710;
    /// v.push_u32_be(n);
    /// assert_eq!(n, v.read_u32_be(0))
    /// ```
    pub fn read_u32_be(&self, i: usize) -> u32 {
        assert!(i + 4 <= self.size);
        let mut x: u32 = 0;
        unsafe {
            libc::memcpy(
                (&mut x) as *mut u32 as *mut c_void,
                self.p.add(i) as *const c_void,
                4,
            );
        }
        u32::from_be(x)
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

impl Drop for CryptoVec {
    fn drop(&mut self) {
        if self.capacity > 0 {
            unsafe {
                for i in 0..self.size {
                    std::ptr::write_volatile(self.p.add(i), 0)
                }
                munlock(self.p, self.capacity);
                let layout = std::alloc::Layout::from_size_align_unchecked(self.capacity, 1);
                std::alloc::dealloc(self.p, layout);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // If `resize` is called with a size that is too large to be allocated, it
    // should panic, and not segfault or fail silently.
    #[test]
    fn large_resize_panics() {
        let result = std::panic::catch_unwind(|| {
            let mut vec = CryptoVec::new();
            // Write something into the vector, so that there is something to
            // copy when reallocating, to test all code paths.
            vec.push(42);

            vec.resize(1_000_000_000_000)
        });
        assert!(result.is_err());
    }
}
