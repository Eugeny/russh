use winapi::shared::{basetsd::SIZE_T, minwindef::LPVOID};
use winapi::um::memoryapi::{VirtualLock, VirtualUnlock};

use libc::c_void;

/// Unlock memory on drop for Windows.
pub fn munlock(ptr: *const u8, len: usize) {
    unsafe {
        VirtualUnlock(ptr as LPVOID, len as SIZE_T);
    }
}

pub fn mlock(ptr: *const u8, len: usize) {
    unsafe {
        VirtualLock(ptr as LPVOID, len as SIZE_T);
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