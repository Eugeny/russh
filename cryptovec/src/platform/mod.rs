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

#[cfg(not(target_arch = "wasm32"))]
mod error {
    use std::error::Error;
    use std::fmt::Display;
    use std::sync::atomic::{AtomicBool, Ordering};

    use log::warn;

    #[derive(Debug)]
    pub struct MemoryLockError {
        message: String,
    }

    impl MemoryLockError {
        pub fn new(message: String) -> Self {
            let warning_previously_shown = MLOCK_WARNING_SHOWN.swap(true, Ordering::Relaxed);
            if !warning_previously_shown {
                warn!(
                    "Security warning: OS has failed to lock/unlock memory for a cryptographic buffer: {message}"
                );
                #[cfg(unix)]
                warn!("You might need to increase the RLIMIT_MEMLOCK limit.");
                warn!("This warning will only be shown once.");
            }
            Self { message }
        }
    }

    static MLOCK_WARNING_SHOWN: AtomicBool = AtomicBool::new(false);

    impl Display for MemoryLockError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "failed to lock/unlock memory: {}", self.message)
        }
    }

    impl Error for MemoryLockError {}
}

#[cfg(not(target_arch = "wasm32"))]
pub use error::MemoryLockError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memset() {
        let mut buf = vec![0u8; 10];
        memset(buf.as_mut_ptr(), 0xff, buf.len());
        assert_eq!(buf, vec![0xff; 10]);
    }

    #[test]
    fn test_memset_partial() {
        let mut buf = vec![0u8; 10];
        memset(buf.as_mut_ptr(), 0xff, 5);
        assert_eq!(buf, [0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0]);
    }
}
