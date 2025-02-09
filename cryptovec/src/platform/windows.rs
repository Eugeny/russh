use libc::c_void;
use winapi::shared::basetsd::SIZE_T;
use winapi::shared::minwindef::LPVOID;
use winapi::um::memoryapi::{VirtualLock, VirtualUnlock};

use super::MemoryLockError;

/// Unlock memory on drop for Windows.
pub fn munlock(ptr: *const u8, len: usize) -> Result<(), MemoryLockError> {
    unsafe {
        if VirtualUnlock(ptr as LPVOID, len as SIZE_T) == 0 {
            return Err(MemoryLockError::new("VirtualUnlock".into()));
        }
    }
    Ok(())
}

pub fn mlock(ptr: *const u8, len: usize) -> Result<(), MemoryLockError> {
    unsafe {
        if VirtualLock(ptr as LPVOID, len as SIZE_T) == 0 {
            return Err(MemoryLockError::new("VirtualLock".into()));
        }
    }
    Ok(())
}

pub fn memset(ptr: *mut u8, value: i32, size: usize) {
    unsafe {
        libc::memset(ptr as *mut c_void, value, size);
    }
}
