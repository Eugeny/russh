//! # Pageant SSH agent transport protocol implementation
//!
//! This crate provides a [PageantStream] type that implements [AsyncRead] and [AsyncWrite] traits and can be used to talk to a running Pageant instance.
//!
//! This crate only implements the transport, not the actual SSH agent protocol.

#[cfg(target_os = "windows")]
mod pageant_impl;

#[cfg(target_os = "windows")]
pub use pageant_impl::*;
