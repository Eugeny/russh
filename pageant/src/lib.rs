//! # Pageant SSH agent transport protocol implementation
//!
//! This crate provides a [PageantStream] type that implements [AsyncRead] and [AsyncWrite] traits and can be used to talk to a running Pageant instance.
//!
//! This crate only implements the transport, not the actual SSH agent protocol.

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

#[cfg(all(windows, feature = "wmmessage", not(feature = "namedpipes")))]
mod pageant_impl;

#[cfg(all(windows, feature = "wmmessage", not(feature = "namedpipes")))]
pub use pageant_impl::*;

#[cfg(all(windows, feature = "namedpipes"))]
mod pageant_impl_namedpipes;

#[cfg(all(windows, feature = "namedpipes"))]
pub use pageant_impl_namedpipes::*;
