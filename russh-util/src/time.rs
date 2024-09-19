#[cfg(not(target_arch = "wasm32"))]
pub use std_time::Instant;

#[cfg(target_arch = "wasm32")]
pub use wasm::Instant;

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

mod std_time {

    #[derive(Debug, Clone, Copy)]
    pub struct Instant {
        inner: std::time::Instant,
    }

    impl Instant {
        pub fn now() -> Self {
            Instant {
                inner: std::time::Instant::now(),
            }
        }

        pub fn duration_since(&self, earlier: Instant) -> std::time::Duration {
            self.inner.duration_since(earlier.inner)
        }
    }
}
