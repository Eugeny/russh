//! Test-only fault-injection gates for S0 malicious-client harness.
//!
//! Compiled only with `--features _test_hooks`. Attach a [`RekeyHoldGate`] to
//! `client::Config::rekey_hold` so each session has isolated state (safe under
//! parallel `cargo test`).
//!
//! When armed, the client holds rekey at the NEWKEYS step while bulk data and
//! window adjustments continue on the wire (KEX-only fault).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Per-session rekey hold gate. Share via `Arc` on `client::Config::rekey_hold`.
#[derive(Debug, Default)]
pub struct RekeyHoldGate {
    /// When armed, suppress outbound NEWKEYS and drop inbound NEWKEYS.
    armed: AtomicBool,
    /// Times we suppressed an outbound NEWKEYS that would have been written.
    held_outbound: AtomicU64,
    /// Times we dropped an inbound NEWKEYS that would have completed kex.
    dropped_inbound: AtomicU64,
    /// Set once the client reaches the post-DH "would send NEWKEYS" stage while armed.
    reached_stage: AtomicBool,
}

impl RekeyHoldGate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Arm the hold: subsequent rekeys on this session stall at NEWKEYS.
    pub fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    /// Disarm the hold (future NEWKEYS process normally). Does not retroactively
    /// complete an already-held exchange.
    pub fn disarm(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }

    pub fn is_armed(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
    }

    pub fn held_outbound_newkeys(&self) -> u64 {
        self.held_outbound.load(Ordering::SeqCst)
    }

    pub fn dropped_inbound_newkeys(&self) -> u64 {
        self.dropped_inbound.load(Ordering::SeqCst)
    }

    /// True once the client hit the NEWKEYS emission point under hold.
    pub fn rekey_reached_newkeys_stage(&self) -> bool {
        self.reached_stage.load(Ordering::SeqCst)
    }

    /// Rekey started and is incomplete under hold.
    pub fn rekey_held_incomplete(&self) -> bool {
        self.rekey_reached_newkeys_stage()
            && (self.held_outbound_newkeys() > 0 || self.dropped_inbound_newkeys() > 0)
    }

    // ── crate-internal ──────────────────────────────────────────────────────

    pub(crate) fn should_hold_outbound_newkeys(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
    }

    pub(crate) fn note_held_outbound_newkeys(&self) {
        self.held_outbound.fetch_add(1, Ordering::SeqCst);
        self.reached_stage.store(true, Ordering::SeqCst);
    }

    pub(crate) fn should_drop_inbound_newkeys(&self) -> bool {
        self.armed.load(Ordering::SeqCst)
    }

    pub(crate) fn note_dropped_inbound_newkeys(&self) {
        self.dropped_inbound.fetch_add(1, Ordering::SeqCst);
    }
}
