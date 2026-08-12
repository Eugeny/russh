//! ConnSupervisor (S1): write-progress watchdog + rekey/handshake deadlines
//! integrated into the existing single-task server session loop.
//!
//! Spec: rewrite plan §4.2. Full Reader/Session/Writer task split is S2/S3 —
//! this module only supplies the supervision state machine and timers that the
//! current `select!` loop polls.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use russh_util::time::Instant;

/// Why the supervisor tore down a connection. First cause wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DisconnectCause {
    /// Write path armed with wire-eligible bytes made no progress in time
    /// (activity layer or write_min_drain strategy layer).
    WriteStalled = 1,
    /// Rekey (InKex) did not complete before rekey_deadline.
    RekeyTimeout = 2,
    /// Banner / initial kex / auth did not finish before handshake_deadline.
    HandshakeTimeout = 3,
    /// Underlying peer/session error (not a supervisor deadline).
    PeerError = 4,
    /// Explicit local disconnect / clean shutdown.
    LocalShutdown = 5,
}

impl DisconnectCause {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::WriteStalled),
            2 => Some(Self::RekeyTimeout),
            3 => Some(Self::HandshakeTimeout),
            4 => Some(Self::PeerError),
            5 => Some(Self::LocalShutdown),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Test/harness slot: first cause is stored once (compare-and-swap style).
#[derive(Debug, Default)]
pub struct DisconnectCauseSlot {
    raw: AtomicU8,
}

impl DisconnectCauseSlot {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            raw: AtomicU8::new(0),
        })
    }

    /// Record first cause; later calls are ignored.
    pub fn record(&self, cause: DisconnectCause) {
        let _ = self
            .raw
            .compare_exchange(0, cause.as_u8(), Ordering::SeqCst, Ordering::SeqCst);
    }

    pub fn get(&self) -> Option<DisconnectCause> {
        DisconnectCause::from_u8(self.raw.load(Ordering::SeqCst))
    }

    pub fn clear(&self) {
        self.raw.store(0, Ordering::SeqCst);
    }
}

/// Single-structure write-progress snapshot (§4.2). Updated with one release store.
#[derive(Debug, Clone, Copy)]
pub struct WriteProgress {
    pub generation: u64,
    /// Monotonic millis since an arbitrary epoch (session start).
    pub last_write_ok_ms: u64,
    pub wire_eligible_bytes: u64,
    pub drained_bytes_epoch: u64,
}

impl WriteProgress {
    pub fn new() -> Self {
        Self {
            generation: 0,
            last_write_ok_ms: 0,
            wire_eligible_bytes: 0,
            drained_bytes_epoch: 0,
        }
    }
}

/// Two-layer write watchdog state (activity + optional min-drain policy).
#[derive(Debug)]
pub struct WriteWatchdog {
    /// When wire_eligible became > 0 (idle→eligible edge). None = disarmed.
    armed_at: Option<Instant>,
    last_progress_at: Option<Instant>,
    /// Strategy window: bytes drained since window_start while armed.
    drain_window_start: Option<Instant>,
    drained_in_window: u64,
    /// Session-relative clock base.
    base: Instant,
    /// Cached snapshot (single structure for external observers).
    snapshot: WriteProgress,
    snapshot_gen: u64,
}

impl WriteWatchdog {
    pub fn new() -> Self {
        Self {
            armed_at: None,
            last_progress_at: None,
            drain_window_start: None,
            drained_in_window: 0,
            base: Instant::now(),
            snapshot: WriteProgress::new(),
            snapshot_gen: 0,
        }
    }

    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    pub fn snapshot(&self) -> WriteProgress {
        self.snapshot
    }

    /// Map current sealed-but-unflushed bytes into wire_eligible and arm/disarm.
    ///
    /// S1 seam: `wire_eligible = packet_writer.pending_bytes()` (already-sealed
    /// ciphertext). Excludes peer-window=0 pending_data (never sealed) and
    /// kex-gated bulk still in app queues — so pure InKex with empty staging
    /// does **not** arm the write watchdog (case1 → RekeyTimeout only).
    pub fn observe_eligible(&mut self, wire_eligible_bytes: u64) {
        let now = Instant::now();
        self.snapshot.wire_eligible_bytes = wire_eligible_bytes;
        self.snapshot.generation = self.snapshot_gen;

        if wire_eligible_bytes == 0 {
            // Disarm: idle. Next eligible edge re-arms with fresh clock.
            self.armed_at = None;
            self.last_progress_at = None;
            self.drain_window_start = None;
            self.drained_in_window = 0;
            return;
        }

        if self.armed_at.is_none() {
            // idle → eligible edge
            self.armed_at = Some(now);
            self.last_progress_at = Some(now);
            self.drain_window_start = Some(now);
            self.drained_in_window = 0;
            self.snapshot.last_write_ok_ms = self.now_ms();
        }
    }

    /// Socket write returned `Ok(n>0)` (including partial).
    pub fn note_write_ok(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        let now = Instant::now();
        self.last_progress_at = Some(now);
        self.drained_in_window = self.drained_in_window.saturating_add(n as u64);
        self.snapshot.drained_bytes_epoch =
            self.snapshot.drained_bytes_epoch.saturating_add(n as u64);
        self.snapshot.last_write_ok_ms = self.now_ms();
        self.snapshot_gen = self.snapshot_gen.wrapping_add(1);
        self.snapshot.generation = self.snapshot_gen;
    }

    /// Returns `WriteStalled` if armed and either activity or strategy layer trips.
    pub fn poll_timeout(
        &mut self,
        write_progress_deadline: Duration,
        write_min_drain: Option<(usize, Duration)>,
    ) -> Option<DisconnectCause> {
        let armed_at = self.armed_at?;
        let now = Instant::now();
        let last = self.last_progress_at.unwrap_or(armed_at);

        // Activity layer: no Ok(n>0) for deadline while armed.
        if now.duration_since(last) >= write_progress_deadline {
            return Some(DisconnectCause::WriteStalled);
        }

        // Strategy layer (write_min_drain): low cumulative drain over window.
        if let Some((min_bytes, window)) = write_min_drain {
            let win_start = self.drain_window_start.unwrap_or(armed_at);
            if now.duration_since(win_start) >= window {
                if self.drained_in_window < min_bytes as u64 {
                    return Some(DisconnectCause::WriteStalled);
                }
                // Slide window after a healthy period.
                self.drain_window_start = Some(now);
                self.drained_in_window = 0;
            }
        }
        None
    }

    /// How long until the next possible activity-layer fire (for select! sleep).
    pub fn next_activity_deadline(
        &self,
        write_progress_deadline: Duration,
    ) -> Option<Duration> {
        let armed_at = self.armed_at?;
        let last = self.last_progress_at.unwrap_or(armed_at);
        let elapsed = Instant::now().duration_since(last);
        Some(write_progress_deadline.saturating_sub(elapsed).max(Duration::from_millis(1)))
    }

    /// How long until the next possible min-drain strategy fire (for select! sleep).
    /// `None` if disarmed or strategy disabled.
    pub fn next_min_drain_deadline(
        &self,
        write_min_drain: Option<(usize, Duration)>,
    ) -> Option<Duration> {
        let (_, window) = write_min_drain?;
        let armed_at = self.armed_at?;
        let win_start = self.drain_window_start.unwrap_or(armed_at);
        let elapsed = Instant::now().duration_since(win_start);
        Some(window.saturating_sub(elapsed).max(Duration::from_millis(1)))
    }
}

impl Default for WriteWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn min_drain_trips_while_activity_resets() {
        let mut wd = WriteWatchdog::new();
        wd.observe_eligible(4096);
        // Small writes keep activity layer happy (deadline 30s).
        wd.note_write_ok(1);
        thread::sleep(Duration::from_millis(30));
        wd.note_write_ok(1);
        thread::sleep(Duration::from_millis(100));
        // Strategy: need 4 KiB in 100ms — we only wrote 2 bytes over >100ms.
        let cause = wd.poll_timeout(
            Duration::from_secs(30),
            Some((4096, Duration::from_millis(100))),
        );
        assert_eq!(cause, Some(DisconnectCause::WriteStalled));
    }

    #[test]
    fn min_drain_off_does_not_trip_on_trickle() {
        let mut wd = WriteWatchdog::new();
        wd.observe_eligible(4096);
        wd.note_write_ok(1);
        thread::sleep(Duration::from_millis(50));
        wd.note_write_ok(1);
        let cause = wd.poll_timeout(Duration::from_secs(30), None);
        assert_eq!(cause, None);
    }

    #[test]
    fn zero_eligible_disarms() {
        let mut wd = WriteWatchdog::new();
        wd.observe_eligible(1024);
        wd.observe_eligible(0);
        thread::sleep(Duration::from_millis(20));
        let cause =
            wd.poll_timeout(Duration::from_millis(10), Some((1, Duration::from_millis(10))));
        assert_eq!(cause, None);
    }
}

/// Tracks rekey deadline registration (watch-style generation on the session).
#[derive(Debug, Default, Clone)]
pub struct RekeyDeadline {
    /// Generation currently in InKex with an armed deadline.
    pub generation: Option<u64>,
    pub deadline_at: Option<Instant>,
}

impl RekeyDeadline {
    pub fn register(&mut self, generation: u64, deadline: Duration) {
        self.generation = Some(generation);
        self.deadline_at = Some(Instant::now() + deadline);
    }

    pub fn clear_if_generation(&mut self, generation: u64) {
        if self.generation == Some(generation) {
            self.generation = None;
            self.deadline_at = None;
        }
    }

    pub fn clear(&mut self) {
        self.generation = None;
        self.deadline_at = None;
    }

    /// Fire only if still the same generation and past deadline.
    pub fn poll(&self, current_active_generation: Option<u64>) -> Option<u64> {
        let generation = self.generation?;
        let at = self.deadline_at?;
        if current_active_generation != Some(generation) {
            return None;
        }
        if Instant::now() >= at {
            Some(generation)
        } else {
            None
        }
    }

    pub fn remaining(&self) -> Option<Duration> {
        let at = self.deadline_at?;
        let now = Instant::now();
        if now >= at {
            Some(Duration::ZERO)
        } else {
            Some(at.duration_since(now))
        }
    }
}
