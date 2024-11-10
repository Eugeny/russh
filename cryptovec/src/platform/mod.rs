#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
#[cfg(not(target_arch = "wasm32"))]
mod unix;

#[cfg(target_arch = "wasm32")]
mod wasm;

// Re-export functions based on the platform
#[cfg(not(windows))]
#[cfg(not(target_arch = "wasm32"))]
pub use unix::{memset, mlock, munlock};
#[cfg(target_arch = "wasm32")]
pub use wasm::{memset, mlock, munlock};
#[cfg(windows)]
pub use windows::{memset, mlock, munlock};

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    use super::*;

    #[wasm_bindgen_test]
    fn test_memset() {
        let mut buf = vec![0u8; 10];
        memset(buf.as_mut_ptr(), 0xff, buf.len());
        assert_eq!(buf, vec![0xff; 10]);
    }

    #[wasm_bindgen_test]
    fn test_memset_partial() {
        let mut buf = vec![0u8; 10];
        memset(buf.as_mut_ptr(), 0xff, 5);
        assert_eq!(buf, [0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0]);
    }
}
