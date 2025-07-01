use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::sync::{Mutex, OnceLock};

use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::LPVOID;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::memoryapi::{VirtualLock, VirtualUnlock};
use winapi::um::sysinfoapi::{GetNativeSystemInfo, SYSTEM_INFO};

use super::MemoryLockError;

// To correctly lock/unlock memory, we need to know the pagesize:
static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
// Store refcounters for all locked pages, since Windows doesn't handle that for us:
static LOCKED_PAGES: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());

/// Unlock memory on drop for Windows.
pub fn munlock(ptr: *const u8, len: usize) -> Result<(), MemoryLockError> {
    let page_indices = get_page_indices(ptr, len);
    let mut locked_pages = LOCKED_PAGES
        .lock()
        .map_err(|e| MemoryLockError::new(format!("Accessing PageLocks failed: {e}")))?;
    for page_idx in page_indices {
        match locked_pages.entry(page_idx) {
            Entry::Occupied(mut lock_counter) => {
                let lock_counter_val = lock_counter.get_mut();
                *lock_counter_val -= 1;
                if *lock_counter_val == 0 {
                    lock_counter.remove();
                    unlock_page(page_idx)?;
                }
            }
            Entry::Vacant(_) => {
                return Err(MemoryLockError::new(
                    "Tried to unlock pointer from non-locked page!".into(),
                ));
            }
        }
    }
    Ok(())
}

fn unlock_page(page_idx: usize) -> Result<(), MemoryLockError> {
    unsafe {
        if VirtualUnlock((page_idx * get_page_size()) as LPVOID, 1 as SIZE_T) == 0 {
            // codes can be looked up at https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes
            let errorcode = GetLastError();
            return Err(MemoryLockError::new(format!(
                "VirtualUnlock: 0x{errorcode:x}"
            )));
        }
    }
    Ok(())
}

pub fn mlock(ptr: *const u8, len: usize) -> Result<(), MemoryLockError> {
    let page_indices = get_page_indices(ptr, len);
    let mut locked_pages = LOCKED_PAGES
        .lock()
        .map_err(|e| MemoryLockError::new(format!("Accessing PageLocks failed: {e}")))?;
    for page_idx in page_indices {
        match locked_pages.entry(page_idx) {
            Entry::Occupied(mut lock_counter) => {
                let lock_counter_val = lock_counter.get_mut();
                *lock_counter_val += 1;
            }
            Entry::Vacant(lock_counter) => {
                lock_page(page_idx)?;
                lock_counter.insert(1);
            }
        }
    }
    Ok(())
}

fn lock_page(page_idx: usize) -> Result<(), MemoryLockError> {
    unsafe {
        if VirtualLock((page_idx * get_page_size()) as LPVOID, 1 as SIZE_T) == 0 {
            let errorcode = GetLastError();
            return Err(MemoryLockError::new(format!(
                "VirtualLock: 0x{errorcode:x}"
            )));
        }
    }
    Ok(())
}

pub fn memset(ptr: *mut u8, value: i32, size: usize) {
    unsafe {
        libc::memset(ptr as *mut c_void, value, size);
    }
}

fn get_page_size() -> usize {
    *PAGE_SIZE.get_or_init(|| {
        let mut sys_info = SYSTEM_INFO::default();
        unsafe {
            GetNativeSystemInfo(&mut sys_info);
        }
        sys_info.dwPageSize as usize
    })
}

fn get_page_indices(ptr: *const u8, len: usize) -> std::ops::Range<usize> {
    let page_size = get_page_size();
    let first_page = ptr as usize / page_size;
    let page_count = (len + page_size - 1) / page_size;
    first_page..(first_page + page_count)
}
