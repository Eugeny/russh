use std::ffi::CStr;

use libc::c_void;

/// Unlock memory on drop for Unix-based systems.
pub fn munlock(ptr: *const u8, len: usize) {
    unsafe {
        if libc::munlock(ptr as *const c_void, len) != 0 {
            panic_libc_error("Failed to unlock memory");
        }
    }
}

pub fn mlock(ptr: *const u8, len: usize) {
    unsafe {
        if libc::mlock(ptr as *const c_void, len) != 0 {
            panic_libc_error("Failed to lock memory");
        }
    }
}

pub fn memset(ptr: *mut u8, value: i32, size: usize) {
    unsafe {
        libc::memset(ptr as *mut c_void, value, size);
    }
}

#[allow(clippy::panic)]
unsafe fn panic_libc_error(msg: &str) {
    let errno = *libc::__errno_location();
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
    panic!("{}: {} (0x{:x})", msg, errdesc, errno);
}
