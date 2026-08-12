//! S0 malicious-client harness: reusable fault-injection client + flood server +
//! deadline / disconnect observation helpers.
//!
//! Test-side scaffolding for the malicious-client matrix. Production hooks used
//! by the KEX-only rekey hold live behind `feature = "_test_hooks"` in
//! `russh::client::test_hooks` (see impl-S0-report).
//!
//! Primary knobs are env-overridable (same style as `test_inbound_window_stall.rs`):
//! - `S0_OBSERVE_SECS` (default 10): how long to watch for disconnect / progress
//! - `S0_REKEY_WRITE_LIMIT` (default 256 KiB): server volume rekey trigger
//! - `S0_WINDOW` / `S0_PACKET` (defaults 64 KiB / 32 KiB)
//!
//! Run S0 with the test hook feature:
//! ```text
//! cargo test -p russh --features _test_hooks --test test_malicious_client_s0 -- --nocapture
//! ```

#![allow(dead_code)]

use std::net::{SocketAddr, TcpListener, TcpStream as StdTcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, client};
use ssh_key::PrivateKey;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::sleep;

// ── env knobs ───────────────────────────────────────────────────────────────

pub fn env_u32(k: &str, d: u32) -> u32 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

pub fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

pub fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

pub fn observe_secs() -> u64 {
    env_u64("S0_OBSERVE_SECS", 10)
}

pub fn rekey_write_limit() -> usize {
    env_usize("S0_REKEY_WRITE_LIMIT", 256 * 1024)
}

pub fn window_size() -> u32 {
    env_u32("S0_WINDOW", 64 * 1024)
}

pub fn packet_size() -> u32 {
    env_u32("S0_PACKET", 32 * 1024)
}

// ── address helper ──────────────────────────────────────────────────────────

pub fn free_addr() -> SocketAddr {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

pub async fn wait_listening(addr: SocketAddr) {
    while StdTcpStream::connect(addr).is_err() {
        sleep(Duration::from_millis(10)).await;
    }
}

// ── fault-inject stream (TCP-level freeze read / talk-no-read) ──────────────

/// Controls for a live [`FaultInjectStream`].
///
/// Freezing the read half parks the client's session-loop socket read while
/// writes still flow. Kernel receive buffers fill and the peer eventually sees
/// TCP zero-window — the production "peer stopped reading" condition.
#[derive(Clone, Debug)]
pub struct FaultControls {
    read_frozen: Arc<AtomicBool>,
    read_waker: Arc<Mutex<Option<Waker>>>,
    bytes_read: Arc<AtomicU64>,
    bytes_written: Arc<AtomicU64>,
    /// Trickle mode: at most `trickle_budget` bytes delivered per `trickle_interval`.
    /// Used by S1 trickle-read (strategy-layer min_drain) tests.
    trickle_budget: Arc<AtomicU64>,
    trickle_max: Arc<AtomicU64>,
    trickle_interval_ms: Arc<AtomicU64>,
    trickle_window_start_ms: Arc<AtomicU64>,
}

impl FaultControls {
    fn new() -> Self {
        Self {
            read_frozen: Arc::new(AtomicBool::new(false)),
            read_waker: Arc::new(Mutex::new(None)),
            bytes_read: Arc::new(AtomicU64::new(0)),
            bytes_written: Arc::new(AtomicU64::new(0)),
            trickle_budget: Arc::new(AtomicU64::new(u64::MAX)),
            trickle_max: Arc::new(AtomicU64::new(u64::MAX)),
            trickle_interval_ms: Arc::new(AtomicU64::new(0)),
            trickle_window_start_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Stop delivering bytes from the socket to the SSH client session loop.
    pub fn freeze_read(&self) {
        self.read_frozen.store(true, Ordering::SeqCst);
    }

    /// Resume delivering socket bytes.
    pub fn unfreeze_read(&self) {
        self.read_frozen.store(false, Ordering::SeqCst);
        if let Ok(mut g) = self.read_waker.lock() {
            if let Some(w) = g.take() {
                w.wake();
            }
        }
    }

    /// Deliver at most `bytes_per_window` from the socket every `interval`
    /// (TCP-level trickle-read for write_min_drain tests).
    pub fn set_trickle(&self, bytes_per_window: u64, interval: Duration) {
        self.trickle_max.store(bytes_per_window, Ordering::SeqCst);
        self.trickle_budget.store(bytes_per_window, Ordering::SeqCst);
        self.trickle_interval_ms
            .store(interval.as_millis() as u64, Ordering::SeqCst);
        self.trickle_window_start_ms.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            Ordering::SeqCst,
        );
        self.unfreeze_read();
    }

    pub fn is_read_frozen(&self) -> bool {
        self.read_frozen.load(Ordering::SeqCst)
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written.load(Ordering::Relaxed)
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Refresh trickle budget if the window has elapsed. Returns remaining budget.
    fn trickle_remaining(&self) -> u64 {
        let interval = self.trickle_interval_ms.load(Ordering::SeqCst);
        if interval == 0 {
            return u64::MAX;
        }
        let now = Self::now_ms();
        let start = self.trickle_window_start_ms.load(Ordering::SeqCst);
        if now.saturating_sub(start) >= interval {
            let max = self.trickle_max.load(Ordering::SeqCst);
            self.trickle_budget.store(max, Ordering::SeqCst);
            self.trickle_window_start_ms.store(now, Ordering::SeqCst);
            max
        } else {
            self.trickle_budget.load(Ordering::SeqCst)
        }
    }
}

/// `TcpStream` wrapper that can freeze the read half on demand.
pub struct FaultInjectStream {
    inner: TcpStream,
    ctrl: FaultControls,
}

impl FaultInjectStream {
    pub async fn connect(addr: SocketAddr) -> std::io::Result<(Self, FaultControls)> {
        let inner = TcpStream::connect(addr).await?;
        let _ = inner.set_nodelay(true);
        let ctrl = FaultControls::new();
        Ok((
            Self {
                inner,
                ctrl: ctrl.clone(),
            },
            ctrl,
        ))
    }

    pub fn controls(&self) -> FaultControls {
        self.ctrl.clone()
    }
}

impl AsyncRead for FaultInjectStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.ctrl.read_frozen.load(Ordering::SeqCst) {
            if let Ok(mut g) = self.ctrl.read_waker.lock() {
                *g = Some(cx.waker().clone());
            }
            return Poll::Pending;
        }
        // Trickle: cap how many bytes this poll may fill.
        let budget = self.ctrl.trickle_remaining();
        if budget == 0 {
            // Exhausted this window — wake later via timer-less Pending; the
            // runtime will re-poll; we also schedule a wake after the interval.
            let interval = self.ctrl.trickle_interval_ms.load(Ordering::SeqCst);
            let waker = cx.waker().clone();
            tokio::spawn(async move {
                sleep(Duration::from_millis(interval.max(1))).await;
                waker.wake();
            });
            return Poll::Pending;
        }
        // Temporarily limit the destination buffer via unfilled capacity clamp.
        let unfilled = buf.remaining();
        let allow = (budget as usize).min(unfilled).max(1);
        // Read into a stack/local scratch then copy — keeps ReadBuf API simple.
        let mut scratch = vec![0u8; allow];
        let mut scratch_buf = ReadBuf::new(&mut scratch);
        let polled = Pin::new(&mut self.inner).poll_read(cx, &mut scratch_buf);
        match polled {
            Poll::Ready(Ok(())) => {
                let n = scratch_buf.filled().len();
                if n > 0 {
                    buf.put_slice(scratch_buf.filled());
                    self.ctrl.bytes_read.fetch_add(n as u64, Ordering::Relaxed);
                    let _ = self.ctrl.trickle_budget.fetch_update(
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                        |b| Some(b.saturating_sub(n as u64)),
                    );
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for FaultInjectStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &polled {
            self.ctrl
                .bytes_written
                .fetch_add(*n as u64, Ordering::Relaxed);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ── observation helpers ─────────────────────────────────────────────────────

/// Shared progress counters for a flood producer (server → client).
#[derive(Clone, Default)]
pub struct Progress {
    pub bytes: Arc<AtomicU64>,
    /// Millis since an arbitrary base; updated on every successful write.
    pub last_progress_ms: Arc<AtomicU64>,
    pub base: Arc<Mutex<Option<Instant>>>,
    /// Set when the server session task ends (handler dropped / run returns).
    pub session_ended: Arc<AtomicBool>,
    /// Count of completed kex exchanges observed via client `kex_done`.
    pub kex_count: Arc<AtomicU64>,
}

impl Progress {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_base(&self) {
        *self.base.lock().unwrap() = Some(Instant::now());
        self.last_progress_ms.store(0, Ordering::Relaxed);
    }

    pub fn note_bytes(&self, n: u64) {
        self.bytes.fetch_add(n, Ordering::Relaxed);
        if let Some(base) = *self.base.lock().unwrap() {
            self.last_progress_ms
                .store(base.elapsed().as_millis() as u64, Ordering::Relaxed);
        }
    }

    pub fn total(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    pub fn idle_ms(&self) -> u64 {
        let Some(base) = *self.base.lock().unwrap() else {
            return 0;
        };
        let now = base.elapsed().as_millis() as u64;
        now.saturating_sub(self.last_progress_ms.load(Ordering::Relaxed))
    }

    pub fn session_alive(&self) -> bool {
        !self.session_ended.load(Ordering::Relaxed)
    }

    pub fn mark_session_ended(&self) {
        self.session_ended.store(true, Ordering::Relaxed);
    }
}

/// Derive a stall threshold safely inside the observe window.
///
/// Fail-fast if the env combo is unusable (`observe` too short).
pub fn stall_for_from_observe(observe: Duration) -> Duration {
    assert!(
        observe >= Duration::from_secs(4),
        "S0_OBSERVE_SECS too small ({:?}); need >= 4s so stall_for can fit",
        observe
    );
    // Leave ≥1s headroom; stall_for ∈ [3s, observe-1].
    let secs = observe.as_secs().saturating_sub(1).clamp(3, 30);
    Duration::from_secs(secs.min(observe.as_secs().saturating_sub(1)).max(3))
}

/// Sample progress for `observe` and report whether writes are **terminally** stalled.
///
/// A terminal stall means: at the end of the observe window the progress counter
/// has made no advance for at least `stall_for` continuously (not merely that a
/// long idle happened mid-window and then recovered).
pub async fn observe_write_stall(
    progress: &Progress,
    observe: Duration,
    stall_for: Duration,
) -> StallReport {
    assert!(
        observe > stall_for,
        "observe ({observe:?}) must be > stall_for ({stall_for:?})"
    );
    let start_total = progress.total();
    let t0 = Instant::now();
    let mut last_total = start_total;
    let mut last_change = Instant::now();
    let mut max_idle = Duration::ZERO;

    while t0.elapsed() < observe {
        sleep(Duration::from_millis(250)).await;
        let now_total = progress.total();
        if now_total > last_total {
            last_total = now_total;
            last_change = Instant::now();
        }
        let idle = last_change.elapsed();
        if idle > max_idle {
            max_idle = idle;
        }
        eprintln!(
            "s0-observe: total={} (+{}) terminal_idle_ms={} session_alive={}",
            now_total,
            now_total.saturating_sub(start_total),
            idle.as_millis(),
            progress.session_alive(),
        );
    }

    let end_total = progress.total();
    let terminal_idle = last_change.elapsed();
    // Terminal stall: still idle for stall_for at end, session up.
    let stalled = terminal_idle >= stall_for && progress.session_alive();
    StallReport {
        start_bytes: start_total,
        end_bytes: end_total,
        max_idle,
        terminal_idle,
        session_alive: progress.session_alive(),
        stalled,
    }
}

#[derive(Debug, Clone)]
pub struct StallReport {
    pub start_bytes: u64,
    pub end_bytes: u64,
    pub max_idle: Duration,
    /// Continuous idle at the end of the observe window.
    pub terminal_idle: Duration,
    pub session_alive: bool,
    /// True when terminal idle ≥ stall_for while the session stayed up.
    pub stalled: bool,
}

/// Wait until progress has been flat for `stable_for` (peer-window exhausted /
/// producer parked). Times out after `timeout`.
pub async fn wait_progress_stable(
    progress: &Progress,
    stable_for: Duration,
    timeout: Duration,
) -> Result<u64, anyhow::Error> {
    let deadline = Instant::now() + timeout;
    let mut last = progress.total();
    let mut flat_since = Instant::now();
    while Instant::now() < deadline {
        sleep(Duration::from_millis(50)).await;
        let now = progress.total();
        if now > last {
            last = now;
            flat_since = Instant::now();
        } else if flat_since.elapsed() >= stable_for {
            eprintln!(
                "s0: progress stable at {last} bytes for {:?}",
                flat_since.elapsed()
            );
            return Ok(last);
        }
    }
    anyhow::bail!(
        "progress never stabilized (last={last}, wanted flat for {stable_for:?} within {timeout:?})"
    )
}

/// Assert SSH **downlink credit is still positive** at stall, given a known
/// fault start where `accepted_at_fault == 0` (full initial peer window).
///
/// With the flood start-gate + freeze-before-release construction, every
/// accepted byte since fault start comes out of the initial window. If
/// `accepted + max_one_packet < initial_window`, the peer window cannot have
/// reached zero — §4.2 write watchdog *should* be armed.
pub fn assert_down_credit_positive(
    accepted_since_fault: u64,
    initial_down_window: u32,
    max_one_packet: u32,
    label: &str,
) {
    let ceiling = (initial_down_window as u64).saturating_sub(max_one_packet as u64);
    assert!(
        accepted_since_fault < ceiling,
        "{label}: accepted_since_fault={accepted_since_fault} not < \
         initial_window-max_packet ({initial_down_window}-{max_one_packet}={ceiling}). \
         Stall may be legal peer-window=0; watchdog must NOT be assumed armed."
    );
}

/// Legacy helper retained for case1 (KEX-only; no start-gate). Prefer
/// [`assert_down_credit_positive`] for freeze-before-release constructions.
pub fn assert_ssh_credit_remaining(
    post_fault_growth: u64,
    initial_peer_window: u32,
    label: &str,
) {
    let ceiling = (initial_peer_window as u64) / 4;
    assert!(
        post_fault_growth < ceiling,
        "{label}: post-fault growth={post_fault_growth} ≥ window/4={ceiling} \
         (window={initial_peer_window})."
    );
}

/// Flood start-gate: producers wait until [`FloodStartGate::release`] so the
/// test can freeze TCP **before** any downlink bytes are accepted (known full
/// initial window credit at fault start).
#[derive(Debug, Default)]
pub struct FloodStartGate {
    released: AtomicBool,
    notify: tokio::sync::Notify,
}

impl FloodStartGate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            released: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        })
    }

    /// Allow flood producers to begin writing.
    pub fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    pub fn is_released(&self) -> bool {
        self.released.load(Ordering::SeqCst)
    }

    /// Wait until released (cancel-safe for test tasks).
    pub async fn wait(&self) {
        loop {
            if self.released.load(Ordering::SeqCst) {
                return;
            }
            // Double-check after registering to avoid lost-wake.
            let notified = self.notify.notified();
            if self.released.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

// ── flood server ────────────────────────────────────────────────────────────

const FILL: u8 = 0xC3;

/// What the flood server does on each accepted session channel.
#[derive(Clone, Copy, Debug)]
pub enum ServerMode {
    /// Flood forever (until write fails / channel closes).
    FloodForever,
    /// Flood a fixed number of bytes then EOF.
    FloodBytes(u64),
    /// Accept the channel and leave it idle (no producer).
    Idle,
    /// Accept and drain inbound forever (for talk-no-read uplink feeding).
    DrainInbound,
}

/// Shared config for the S0/S1 test server.
#[derive(Clone)]
pub struct FloodServerConfig {
    pub window_size: u32,
    pub maximum_packet_size: u32,
    pub channel_buffer_size: usize,
    pub rekey_write_limit: usize,
    pub rekey_time_limit: Duration,
    pub inactivity_timeout: Option<Duration>,
    pub keepalive_interval: Option<Duration>,
    pub keepalive_max: usize,
    /// Mode applied to the first channel; subsequent channels use `secondary_mode`.
    pub first_channel_mode: ServerMode,
    pub secondary_mode: ServerMode,
    /// When set, `FloodForever` / `FloodBytes` await release before the first
    /// write (channel is accepted, but downlink accepted stays 0 until release).
    /// `None` = start writing immediately (case1 / G2 / negative control).
    pub flood_start: Option<Arc<FloodStartGate>>,
    /// S1 ConnSupervisor: short deadlines for tests (defaults match production 30s).
    pub write_progress_deadline: Duration,
    pub write_min_drain: Option<(usize, Duration)>,
    pub handshake_deadline: Duration,
    pub rekey_deadline: Duration,
    pub teardown_grace: Duration,
    /// First-cause slot for supervisor assertions (`_test_hooks`).
    #[cfg(feature = "_test_hooks")]
    pub disconnect_cause_slot: Option<Arc<russh::server::DisconnectCauseSlot>>,
}

impl Default for FloodServerConfig {
    fn default() -> Self {
        Self {
            window_size: window_size(),
            maximum_packet_size: packet_size(),
            channel_buffer_size: 4,
            rekey_write_limit: rekey_write_limit(),
            rekey_time_limit: Duration::from_secs(3600),
            // Keep defaults high enough that timers don't steal the show unless a
            // test shortens them deliberately (talk-no-read).
            inactivity_timeout: Some(Duration::from_secs(600)),
            keepalive_interval: None,
            keepalive_max: 3,
            first_channel_mode: ServerMode::FloodForever,
            secondary_mode: ServerMode::Idle,
            flood_start: None,
            write_progress_deadline: Duration::from_secs(30),
            write_min_drain: None, // match library default (opt-in strategy layer)
            handshake_deadline: Duration::from_secs(30),
            rekey_deadline: Duration::from_secs(30),
            teardown_grace: Duration::from_secs(5),
            #[cfg(feature = "_test_hooks")]
            disconnect_cause_slot: None,
        }
    }
}

#[derive(Clone)]
pub struct FloodServer {
    progress: Progress,
    cfg: FloodServerConfig,
    /// Per-connection channel open ordinal.
    chan_seq: Arc<AtomicU64>,
}

impl FloodServer {
    pub fn new(progress: Progress, cfg: FloodServerConfig) -> Self {
        Self {
            progress,
            cfg,
            chan_seq: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn spawn(mut self, addr: SocketAddr) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let config = Arc::new(server::Config {
                keys: vec![
                    PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap(),
                ],
                window_size: self.cfg.window_size,
                maximum_packet_size: self.cfg.maximum_packet_size,
                channel_buffer_size: self.cfg.channel_buffer_size,
                limits: russh::Limits {
                    rekey_write_limit: self.cfg.rekey_write_limit,
                    rekey_time_limit: self.cfg.rekey_time_limit,
                    ..Default::default()
                },
                inactivity_timeout: self.cfg.inactivity_timeout,
                keepalive_interval: self.cfg.keepalive_interval,
                keepalive_max: self.cfg.keepalive_max,
                write_progress_deadline: self.cfg.write_progress_deadline,
                write_min_drain: self.cfg.write_min_drain,
                handshake_deadline: self.cfg.handshake_deadline,
                rekey_deadline: self.cfg.rekey_deadline,
                teardown_grace: self.cfg.teardown_grace,
                #[cfg(feature = "_test_hooks")]
                disconnect_cause_slot: self.cfg.disconnect_cause_slot.clone(),
                ..Default::default()
            });
            if let Err(e) = self.run_on_address(config, addr).await {
                eprintln!("s0 flood server exited: {e:?}");
            }
        })
    }
}

impl server::Server for FloodServer {
    type Handler = FloodHandler;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        FloodHandler {
            progress: self.progress.clone(),
            cfg: self.cfg.clone(),
            chan_seq: self.chan_seq.clone(),
            authenticated: false,
        }
    }
}

pub struct FloodHandler {
    progress: Progress,
    cfg: FloodServerConfig,
    chan_seq: Arc<AtomicU64>,
    /// Only handlers that got past auth count as a "real" session for liveness.
    /// (`wait_listening` probes TCP with a connect/drop that would otherwise
    /// false-trigger session_ended via Drop.)
    authenticated: bool,
}

impl Drop for FloodHandler {
    fn drop(&mut self) {
        if self.authenticated {
            // Handler drop after auth ≈ session teardown on current architecture.
            self.progress.mark_session_ended();
            eprintln!(
                "s0: FloodHandler dropped (session ended), bytes={}",
                self.progress.total()
            );
        }
    }
}

impl server::Handler for FloodHandler {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.authenticated = true;
        // A new authenticated session supersedes any stale ended flag (e.g. if a
        // previous connection on this shared Progress ended).
        self.progress.session_ended.store(false, Ordering::Relaxed);
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let idx = self.chan_seq.fetch_add(1, Ordering::Relaxed);
        let mode = if idx == 0 {
            self.cfg.first_channel_mode
        } else {
            self.cfg.secondary_mode
        };
        let progress = self.progress.clone();
        let flood_start = self.cfg.flood_start.clone();
        eprintln!("s0: server accepted channel #{idx} mode={mode:?}");
        tokio::spawn(async move {
            run_channel_mode(channel, mode, progress, flood_start).await;
        });
        Ok(())
    }
}

async fn run_channel_mode(
    mut channel: Channel<Msg>,
    mode: ServerMode,
    progress: Progress,
    flood_start: Option<Arc<FloodStartGate>>,
) {
    match mode {
        ServerMode::Idle => {
            // Hold the channel open; do nothing.
            let mut reader = channel.make_reader();
            let mut buf = [0u8; 256];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
        ServerMode::DrainInbound => {
            let mut reader = channel.make_reader();
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
        ServerMode::FloodForever => {
            if let Some(gate) = flood_start.as_ref() {
                eprintln!("s0: flood producer waiting for start-gate");
                gate.wait().await;
                eprintln!("s0: flood producer released");
            }
            let mut writer = channel.make_writer();
            let chunk = vec![FILL; 16 * 1024];
            loop {
                match writer.write_all(&chunk).await {
                    Ok(()) => progress.note_bytes(chunk.len() as u64),
                    Err(_) => break,
                }
            }
        }
        ServerMode::FloodBytes(total) => {
            if let Some(gate) = flood_start.as_ref() {
                eprintln!("s0: flood producer waiting for start-gate");
                gate.wait().await;
                eprintln!("s0: flood producer released");
            }
            let mut writer = channel.make_writer();
            let chunk = vec![FILL; 16 * 1024];
            let mut left = total;
            while left > 0 {
                let n = left.min(chunk.len() as u64) as usize;
                if writer.write_all(&chunk[..n]).await.is_err() {
                    break;
                }
                progress.note_bytes(n as u64);
                left -= n as u64;
            }
            let _ = writer.shutdown().await;
        }
    }
}

// ── client helpers ──────────────────────────────────────────────────────────

/// Minimal client handler that counts kex completions.
pub struct CountingClient {
    pub progress: Progress,
}

impl client::Handler for CountingClient {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        _names: &russh::Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        self.progress.kex_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

pub struct PlainClient;

impl client::Handler for PlainClient {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Authenticated client over a fault-injectable stream.
pub async fn connect_faulty(
    addr: SocketAddr,
    client_cfg: client::Config,
    progress: Progress,
) -> Result<(client::Handle<CountingClient>, FaultControls), anyhow::Error> {
    let (stream, ctrl) = FaultInjectStream::connect(addr).await?;
    let config = Arc::new(client_cfg);
    let mut session = client::connect_stream(
        config,
        stream,
        CountingClient {
            progress: progress.clone(),
        },
    )
    .await?;
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let authed = session
        .authenticate_publickey(
            "user",
            PrivateKeyWithHashAlg::new(
                key,
                session.best_supported_rsa_hash().await.unwrap().flatten(),
            ),
        )
        .await?
        .success();
    anyhow::ensure!(authed, "auth failed");
    Ok((session, ctrl))
}

/// Wait until a per-session rekey hold gate has taken effect.
#[cfg(feature = "_test_hooks")]
pub async fn wait_rekey_held(
    gate: &russh::client::test_hooks::RekeyHoldGate,
    timeout: Duration,
) -> Result<(), anyhow::Error> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if gate.rekey_held_incomplete() {
            eprintln!(
                "s0: rekey hold active (held_out={} dropped_in={})",
                gate.held_outbound_newkeys(),
                gate.dropped_inbound_newkeys()
            );
            return Ok(());
        }
        sleep(Duration::from_millis(20)).await;
    }
    anyhow::bail!(
        "rekey hold did not engage within {timeout:?} \
         (reached_stage={} held_out={} dropped_in={} armed={})",
        gate.rekey_reached_newkeys_stage(),
        gate.held_outbound_newkeys(),
        gate.dropped_inbound_newkeys(),
        gate.is_armed()
    )
}

/// Authenticated client over a plain TCP stream (no fault injection).
pub async fn connect_plain(
    addr: SocketAddr,
    client_cfg: client::Config,
) -> Result<client::Handle<PlainClient>, anyhow::Error> {
    let config = Arc::new(client_cfg);
    let mut session = client::connect(config, addr, PlainClient).await?;
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let authed = session
        .authenticate_publickey(
            "user",
            PrivateKeyWithHashAlg::new(
                key,
                session.best_supported_rsa_hash().await.unwrap().flatten(),
            ),
        )
        .await?
        .success();
    anyhow::ensure!(authed, "auth failed");
    Ok(session)
}

/// Default client config matching the S0 window/packet knobs.
pub fn default_client_config() -> client::Config {
    client::Config {
        window_size: window_size(),
        maximum_packet_size: packet_size(),
        channel_buffer_size: 4,
        // Don't let the client side tear the session down on its own timers
        // while we are measuring server-side behaviour.
        inactivity_timeout: None,
        ..Default::default()
    }
}

/// Keep a channel's app-level consumer frozen (no reads) for the duration.
///
/// Exhausts peer window from the server's point of view without freezing TCP.
pub fn freeze_channel_consumer(mut channel: Channel<client::Msg>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Park forever holding the channel (and its receiver) so window is never returned.
        // Dropping the reader half without reading still leaves undelivered data in the
        // channel buffer; not reading is enough once the initial window drains.
        let _reader = channel.make_reader();
        sleep(Duration::from_secs(3600)).await;
    })
}

/// Continuously push uplink data on a channel (talk-no-read feeder).
pub fn spawn_uplink_feeder(channel: Channel<client::Msg>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut writer = channel.make_writer();
        let buf = vec![0x5Au8; 1024];
        loop {
            if writer.write_all(&buf).await.is_err() {
                break;
            }
            // Pace a little so we don't spin a pure-CPU tight loop on loopback.
            sleep(Duration::from_millis(50)).await;
        }
    })
}

/// Continuously drain a channel (healthy consumer).
pub fn spawn_channel_drainer(mut channel: Channel<client::Msg>) -> tokio::task::JoinHandle<u64> {
    tokio::spawn(async move {
        let mut reader = channel.make_reader();
        let mut buf = vec![0u8; 16 * 1024];
        let mut total = 0u64;
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => total += n as u64,
                Err(_) => break,
            }
        }
        total
    })
}
