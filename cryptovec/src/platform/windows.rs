//! Windows memory locking via VirtualLock/VirtualUnlock.
//!
//! Pins crypto buffer pages in physical RAM to prevent key material from
//! being written to the page file. Maintains per-page reference counts
//! since Windows does not support nested VirtualLock calls on the same page.
//!
//! When VirtualLock fails with ERROR_WORKING_SET_QUOTA (the default minimum
//! working set is too small), the process working set is grown incrementally
//! and the lock is retried.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::{Mutex, OnceLock};

use windows_sys::Win32::System::Memory::{
    GetProcessWorkingSetSizeEx, SetProcessWorkingSetSizeEx, VirtualLock, VirtualUnlock,
};
use windows_sys::Win32::System::SystemInformation::{GetNativeSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use super::MemoryLockError;

/// Page size cached at first use.
static PAGE_SIZE: OnceLock<usize> = OnceLock::new();

/// Per-page reference counts. Windows does not support nested VirtualLock
/// calls on the same page, so we track them ourselves and only call
/// VirtualLock/VirtualUnlock on the first lock / last unlock.
static LOCKED_PAGES: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());

/// Maximum number of pages this library will lock.
///
/// Crypto key material is small (typically 32-256 bytes per buffer). This
/// cap prevents unbounded working set growth from exhausting physical RAM.
/// 256 pages = 1 MiB on 4 KiB page systems.
const MAX_LOCKED_PAGES: usize = 256;

/// Win32 ERROR_WORKING_SET_QUOTA: the process minimum working set is too
/// small for VirtualLock to pin the requested page.
/// <https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1300-1699->
const ERROR_WORKING_SET_QUOTA: u32 = 0x5ad;

/// Known flag bits for SetProcessWorkingSetSizeEx. Masked before passing
/// to avoid forwarding undocumented bits from future Windows versions.
/// <https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-setprocessworkingsetsizeex>
const KNOWN_WS_FLAGS: u32 = 0x01 | 0x02 | 0x04 | 0x08;

/// Lock memory pages so they cannot be paged to disk.
pub fn mlock(ptr: *const u8, len: usize) -> Result<(), MemoryLockError> {
    let page_size = get_page_size();
    let page_range = get_page_range(ptr, len, page_size);
    let mut locked_pages = LOCKED_PAGES
        .lock()
        .map_err(|e| MemoryLockError::new(format!("failed to acquire page lock table: {e}")))?;

    let mut newly_locked: Vec<usize> = Vec::new();
    let mut refcount_bumped: Vec<usize> = Vec::new();

    for page_idx in page_range {
        let count = locked_pages.len();
        match locked_pages.entry(page_idx) {
            Entry::Occupied(mut entry) => {
                *entry.get_mut() += 1;
                refcount_bumped.push(page_idx);
            }
            Entry::Vacant(entry) => {
                if let Err(e) = lock_page(page_idx, count, page_size) {
                    // Roll back: undo refcount bumps on already-locked pages.
                    for &p in &refcount_bumped {
                        if let Entry::Occupied(mut e) = locked_pages.entry(p) {
                            *e.get_mut() -= 1;
                        }
                    }
                    // Roll back: unlock and remove newly locked pages.
                    for &p in &newly_locked {
                        locked_pages.remove(&p);
                        let _ = unlock_page(p, page_size);
                    }
                    return Err(e);
                }
                entry.insert(1);
                newly_locked.push(page_idx);
            }
        }
    }
    Ok(())
}

/// Unlock previously locked memory pages.
pub fn munlock(ptr: *const u8, len: usize) -> Result<(), MemoryLockError> {
    let page_size = get_page_size();
    let page_range = get_page_range(ptr, len, page_size);
    let mut locked_pages = LOCKED_PAGES
        .lock()
        .map_err(|e| MemoryLockError::new(format!("failed to acquire page lock table: {e}")))?;

    for page_idx in page_range {
        match locked_pages.entry(page_idx) {
            Entry::Occupied(mut entry) => {
                *entry.get_mut() -= 1;
                if *entry.get() == 0 {
                    entry.remove();
                    unlock_page(page_idx, page_size)?;
                }
            }
            Entry::Vacant(_) => {
                return Err(MemoryLockError::new(
                    "attempted to unlock a page that is not locked".into(),
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal: per-page VirtualLock / VirtualUnlock
// ---------------------------------------------------------------------------

/// Lock a single page into physical memory.
///
/// If VirtualLock fails with ERROR_WORKING_SET_QUOTA, grows the working
/// set by one page and retries once.
///
/// # Preconditions
///
/// Called with `LOCKED_PAGES` held. Must not re-acquire it.
fn lock_page(
    page_idx: usize,
    current_locked_count: usize,
    page_size: usize,
) -> Result<(), MemoryLockError> {
    if current_locked_count >= MAX_LOCKED_PAGES {
        return Err(MemoryLockError::new(format!(
            "VirtualLock: locked page limit reached ({MAX_LOCKED_PAGES} pages)"
        )));
    }

    let addr = page_idx
        .checked_mul(page_size)
        .ok_or_else(|| MemoryLockError::new("VirtualLock: page address overflow".into()))?
        as *mut std::ffi::c_void;

    // First attempt.
    if unsafe { VirtualLock(addr, page_size) } != 0 {
        return Ok(());
    }

    let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    if err != ERROR_WORKING_SET_QUOTA {
        return Err(MemoryLockError::new(format!(
            "VirtualLock failed: 0x{err:x}"
        )));
    }

    // Working set too small -- grow it and retry.
    log::debug!("VirtualLock failed with ERROR_WORKING_SET_QUOTA, growing working set");
    grow_working_set(page_size).map_err(|e| {
        MemoryLockError::new(format!(
            "VirtualLock failed: ERROR_WORKING_SET_QUOTA (0x{err:x}), working set growth also failed: {e}"
        ))
    })?;

    // Retry.
    if unsafe { VirtualLock(addr, page_size) } != 0 {
        return Ok(());
    }
    let retry_err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    Err(MemoryLockError::new(format!(
        "VirtualLock failed: 0x{retry_err:x} (after working set growth)"
    )))
}

/// Unlock a single page.
fn unlock_page(page_idx: usize, page_size: usize) -> Result<(), MemoryLockError> {
    let addr = page_idx
        .checked_mul(page_size)
        .ok_or_else(|| MemoryLockError::new("VirtualUnlock: page address overflow".into()))?
        as *mut std::ffi::c_void;
    if unsafe { VirtualUnlock(addr, page_size) } == 0 {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        return Err(MemoryLockError::new(format!(
            "VirtualUnlock failed: 0x{err:x}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal: working set management
// ---------------------------------------------------------------------------

/// Increase the process working set by one page.
///
/// Called on demand when VirtualLock fails with ERROR_WORKING_SET_QUOTA.
///
/// # Preconditions
///
/// Called with `LOCKED_PAGES` held. Must not re-acquire it.
fn grow_working_set(page_size: usize) -> Result<(), MemoryLockError> {
    let handle = unsafe { GetCurrentProcess() };

    let mut min_ws: usize = 0;
    let mut max_ws: usize = 0;
    let mut flags: u32 = 0;

    unsafe {
        if GetProcessWorkingSetSizeEx(handle, &mut min_ws, &mut max_ws, &mut flags) == 0 {
            let err = windows_sys::Win32::Foundation::GetLastError();
            return Err(MemoryLockError::new(format!(
                "GetProcessWorkingSetSizeEx failed: 0x{err:x}"
            )));
        }
    }

    let new_min = min_ws.saturating_add(page_size);
    let new_max = max_ws.max(new_min.saturating_add(page_size));
    let safe_flags = flags & KNOWN_WS_FLAGS;

    log::debug!(
        "growing process working set: min {min_ws} -> {new_min}, max {max_ws} -> {new_max}"
    );

    unsafe {
        if SetProcessWorkingSetSizeEx(handle, new_min, new_max, safe_flags) == 0 {
            let err = windows_sys::Win32::Foundation::GetLastError();
            return Err(MemoryLockError::new(format!(
                "SetProcessWorkingSetSizeEx failed: 0x{err:x}"
            )));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal: page arithmetic
// ---------------------------------------------------------------------------

fn get_page_size() -> usize {
    *PAGE_SIZE.get_or_init(|| {
        let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        unsafe { GetNativeSystemInfo(&mut info) };
        info.dwPageSize as usize
    })
}

/// Compute the range of page indices spanned by `[ptr, ptr+len)`.
fn get_page_range(ptr: *const u8, len: usize, page_size: usize) -> std::ops::Range<usize> {
    let start = ptr as usize / page_size;
    let end = if len == 0 {
        start
    } else {
        // Use the address of the last byte to find the last page, avoiding
        // overflow from `len + page_size - 1` when len is near usize::MAX.
        (ptr as usize + len - 1) / page_size + 1
    };
    start..end
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Page range arithmetic -----------------------------------------------

    #[test]
    fn page_range_zero_length() {
        let range = get_page_range(0x2000 as *const u8, 0, 4096);
        assert!(range.is_empty());
    }

    #[test]
    fn page_range_single_byte() {
        let range = get_page_range(0x2000 as *const u8, 1, 4096);
        assert_eq!(range, 2..3);
    }

    #[test]
    fn page_range_within_one_page() {
        let range = get_page_range(0x2010 as *const u8, 100, 4096);
        assert_eq!(range, 2..3);
    }

    #[test]
    fn page_range_spans_two_pages() {
        // Buffer starts near end of page 2, extends into page 3.
        let range = get_page_range(0x2FF0 as *const u8, 32, 4096);
        assert_eq!(range, 2..4);
    }

    #[test]
    fn page_range_exact_page_boundary() {
        let range = get_page_range(0x3000 as *const u8, 4096, 4096);
        assert_eq!(range, 3..4);
    }

    #[test]
    fn page_range_one_byte_past_boundary() {
        let range = get_page_range(0x3000 as *const u8, 4097, 4096);
        assert_eq!(range, 3..5);
    }

    // -- mlock / munlock integration -----------------------------------------

    #[test]
    fn mlock_munlock_roundtrip() {
        let buf = vec![0u8; 64];
        mlock(buf.as_ptr(), buf.len()).expect("mlock should succeed");
        munlock(buf.as_ptr(), buf.len()).expect("munlock should succeed");
    }

    #[test]
    fn mlock_refcount_overlap() {
        // Two overlapping mlock calls on the same page should refcount.
        let buf = vec![0u8; 128];
        mlock(buf.as_ptr(), 64).expect("first mlock");
        mlock(buf.as_ptr(), 128).expect("second mlock (overlapping)");
        munlock(buf.as_ptr(), 64).expect("first munlock");
        munlock(buf.as_ptr(), 128).expect("second munlock");
    }

    #[test]
    fn munlock_without_mlock_fails() {
        let buf = vec![0u8; 64];
        assert!(munlock(buf.as_ptr(), buf.len()).is_err());
    }

    #[test]
    fn mlock_zero_length_is_noop() {
        let buf = vec![0u8; 64];
        mlock(buf.as_ptr(), 0).expect("zero-length mlock should succeed");
    }

    #[test]
    fn mlock_multiple_distinct_buffers() {
        // Lock several distinct buffers to exercise working set growth.
        let buffers: Vec<Vec<u8>> = (0..8).map(|_| vec![0u8; 4096]).collect();
        for buf in &buffers {
            mlock(buf.as_ptr(), buf.len()).expect("mlock should succeed");
        }
        for buf in &buffers {
            munlock(buf.as_ptr(), buf.len()).expect("munlock should succeed");
        }
    }
}
