#[cfg(not(target_arch = "wasm32"))]
pub use std::time::Instant;

// `web-time` uses `Performance.now()` on wasm32-unknown-unknown (where
// `std::time::Instant::now()` panics) and re-exports `std::time` on other
// wasm32 targets such as WASI. Unlike the previous `chrono::Utc::now()` based
// implementation, it is monotonic.
#[cfg(target_arch = "wasm32")]
pub use web_time::Instant;
