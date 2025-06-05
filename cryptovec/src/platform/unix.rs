use std::ffi::c_void;
use std::ptr::NonNull;

use nix::errno::Errno;

use super::MemoryLockError;

/// Unlock memory on drop for Unix-based systems.
pub fn munlock(ptr: *const u8, len: usize) -> Result<(), MemoryLockError> {
    unsafe {
        Errno::clear();
        let ptr = NonNull::new_unchecked(ptr as *mut c_void);
        nix::sys::mman::munlock(ptr, len).map_err(|e| {
            MemoryLockError::new(format!("munlock: {} (0x{:x})", e.desc(), e as i32))
        })?;
    }
    Ok(())
}

pub fn mlock(ptr: *const u8, len: usize) -> Result<(), MemoryLockError> {
    unsafe {
        Errno::clear();
        let ptr = NonNull::new_unchecked(ptr as *mut c_void);
        nix::sys::mman::mlock(ptr, len)
            .map_err(|e| MemoryLockError::new(format!("mlock: {} (0x{:x})", e.desc(), e as i32)))?;
    }
    Ok(())
}

pub fn memset(ptr: *mut u8, value: i32, size: usize) {
    unsafe {
        nix::libc::memset(ptr as *mut c_void, value, size);
    }
}
