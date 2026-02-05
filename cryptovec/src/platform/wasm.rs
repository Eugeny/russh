use std::convert::Infallible;

// WASM does not support synchronization primitives
pub fn munlock(_ptr: *const u8, _len: usize) -> Result<(), Infallible> {
    // No-op
    Ok(())
}

pub fn mlock(_ptr: *const u8, _len: usize) -> Result<(), Infallible> {
    Ok(())
}
