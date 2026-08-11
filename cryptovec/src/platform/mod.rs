#[cfg(windows)]
mod windows;

#[cfg(not(windows))]
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_os = "motor"))]
mod unix;

// Motor OS has no memory-locking API; it uses the wasm no-op implementation.
#[cfg(any(target_arch = "wasm32", target_os = "motor"))]
mod wasm;

// Re-export functions based on the platform
#[cfg(not(windows))]
#[cfg(not(target_arch = "wasm32"))]
#[cfg(not(target_os = "motor"))]
pub use unix::{mlock, munlock};
#[cfg(any(target_arch = "wasm32", target_os = "motor"))]
pub use wasm::{mlock, munlock};
#[cfg(windows)]
pub use windows::{mlock, munlock};

#[cfg(not(any(target_arch = "wasm32", target_os = "motor")))]
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

#[cfg(not(any(target_arch = "wasm32", target_os = "motor")))]
pub use error::MemoryLockError;
