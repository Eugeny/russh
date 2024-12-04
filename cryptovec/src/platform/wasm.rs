// WASM does not support synchronization primitives
pub fn munlock(_ptr: *const u8, _len: usize) {
    // No-op
}

pub fn mlock(_ptr: *const u8, _len: usize) -> i32 {
    0
}

pub fn memset(ptr: *mut u8, value: i32, size: usize) {
    let byte_value = value as u8; // Extract the least significant byte directly
    unsafe {
        std::ptr::write_bytes(ptr, byte_value, size);
    }
}