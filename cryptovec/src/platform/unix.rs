use std::ffi::CStr;

use libc::c_void;

use super::MemoryLockError;

/// Unlock memory on drop for Unix-based systems.
pub fn munlock(ptr: *const u8, len: usize) -> Result<(), MemoryLockError> {
    unsafe {
        if libc::munlock(ptr as *const c_void, len) != 0 {
            return Err(MemoryLockError::new(get_libc_error("munlock")));
        }
    }
    Ok(())
}

pub fn mlock(ptr: *const u8, len: usize) -> Result<(), MemoryLockError> {
    unsafe {
        if libc::mlock(ptr as *const c_void, len) != 0 {
            return Err(MemoryLockError::new(get_libc_error("mlock")));
        }
    }
    Ok(())
}

pub fn memset(ptr: *mut u8, value: i32, size: usize) {
    unsafe {
        libc::memset(ptr as *mut c_void, value, size);
    }
}

unsafe fn get_libc_error(msg: &str) -> String {
    #[cfg(not(target_os = "macos"))]
    let errno = *libc::__errno_location();
    #[cfg(target_os = "macos")]
    let errno = *libc::__error();
    const ERRMAXLEN: usize = 255;
    const INVALID_ERR: &str = "Unknown";
    let mut errdesc = [0u8; ERRMAXLEN];
    let errdesc = if libc::strerror_r(errno, errdesc.as_mut_ptr() as _, ERRMAXLEN) == 0 {
        if let Some(nul_pos) = errdesc.iter().position(|b| *b == 0) {
            #[allow(clippy::indexing_slicing)]
            // safety: the position was just checked, so it is guaranteed to be in range
            CStr::from_bytes_with_nul(&errdesc[0..=nul_pos])
                .ok()
                .and_then(|msg| msg.to_str().ok())
                .unwrap_or(INVALID_ERR)
        } else {
            INVALID_ERR
        }
    } else {
        INVALID_ERR
    };
    // Note: if you get 'Cannot allocate memory (0xc)' here,
    // check if your RLIMIT_MEMLOCK (`ulimit -l`) is configured low!
    format!("{}: {} (0x{:x})", msg, errdesc, errno)
}
