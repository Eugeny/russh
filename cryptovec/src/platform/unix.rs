use std::ffi::c_void;
use std::ptr::NonNull;

use nix::errno::Errno;

use super::MemoryLockError;

/// Unlock memory on drop for Unix-based systems.
pub fn munlock(ptr: *const u8, len: usize) -> Result<(), MemoryLockError> {
    if len == 0 {
        return Ok(());
    }
    let Some(ptr) = NonNull::new(ptr as *mut c_void) else {
        return Err(MemoryLockError::new("munlock: null pointer".into()));
    };
    unsafe {
        Errno::clear();
        nix::sys::mman::munlock(ptr, len).map_err(|e| {
            MemoryLockError::new(format!("munlock: {} (0x{:x})", e.desc(), e as i32))
        })?;
    }
    Ok(())
}

pub fn mlock(ptr: *const u8, len: usize) -> Result<(), MemoryLockError> {
    if len == 0 {
        return Ok(());
    }
    let Some(ptr) = NonNull::new(ptr as *mut c_void) else {
        return Err(MemoryLockError::new("mlock: null pointer".into()));
    };
    unsafe {
        Errno::clear();
        nix::sys::mman::mlock(ptr, len)
            .map_err(|e| MemoryLockError::new(format!("mlock: {} (0x{:x})", e.desc(), e as i32)))?;
    }
    Ok(())
}
