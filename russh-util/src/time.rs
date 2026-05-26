#[cfg(not(target_arch = "wasm32"))]
pub use std::time::Instant;

#[cfg(target_arch = "wasm32")]
pub use wasm::Instant;

#[cfg(target_arch = "wasm32")]
mod wasm {
    #[derive(Debug, Clone, Copy)]
    pub struct Instant {
        inner: chrono::DateTime<chrono::Utc>,
    }

    impl Instant {
        pub fn now() -> Self {
            Instant {
                inner: chrono::Utc::now(),
            }
        }

        pub fn duration_since(&self, earlier: Instant) -> std::time::Duration {
            (self.inner - earlier.inner)
                .to_std()
                .expect("Duration is negative")
        }
    }
}
