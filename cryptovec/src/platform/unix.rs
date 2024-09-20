use libc::c_void;

/// Unlock memory on drop for Unix-based systems.
pub fn munlock(ptr: *const u8, len: usize) {
    unsafe {
        #[allow(clippy::panic)]
        if libc::munlock(ptr as *const c_void, len) != 0 {
            panic!("Failed to unlock memory");
        }
    }
}

pub fn mlock(ptr: *const u8, len: usize) {
    unsafe {
        #[allow(clippy::panic)]
        if libc::mlock(ptr as *const c_void, len) != 0 {
            panic!("Failed to lock memory");
        }
    }
}

pub fn memset(ptr: *mut u8, value: i32, size: usize) {
    unsafe {
        libc::memset(ptr as *mut c_void, value, size);
    }
}

pub fn memcpy(dest: *mut u32, src: *const u8, size: usize) {
    unsafe {
        libc::memcpy(dest as *mut c_void, src as *const c_void, size);
    }
}
