#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

// Re-export CryptoVec from the cryptovec module
mod cryptovec;
pub use cryptovec::CryptoVec;

// Platform-specific modules
mod platform;