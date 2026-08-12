//! S0/S1 malicious-client suite.
//!
//! S1: ConnSupervisor tears down known-bad stalls with the correct first cause.
//! Requires `--features _test_hooks`.
//!
//! Run:
//! ```text
//! cargo test -p russh --features _test_hooks --test test_malicious_client_s0 -- --nocapture
//! ```
//!
//! ## S1 first-cause contract
//! - case1 rekey-stall → `RekeyTimeout`
//! - case2 talk-no-read / case4 write-stall-during-rekey → `WriteStalled`
//! - case3 zero-window-legit → never torn down
//! - trickle-read → `WriteStalled` with min_drain on; no tear-down with min_drain off

mod harness;

use std::sync::atomic::Ordering;
use std::time::Duration;

use harness::*;
use russh::server::DisconnectCause;
use tokio::time::sleep;

/// Short test deadlines: write watchdog / rekey / observe headroom.
const WD: Duration = Duration::from_secs(2);
const REKEY_DL: Duration = Duration::from_secs(3);
const GRACE: Duration = Duration::from_secs(1);
/// Observe until past the longest short deadline + grace + ε.
const OBSERVE: Duration = Duration::from_secs(8);

fn assert_cause(
    slot: &russh::server::DisconnectCauseSlot,
    expected: DisconnectCause,
    label: &str,
) {
    let got = slot.get();
    assert_eq!(
        got,
        Some(expected),
        "{label}: expected supervisor first cause {expected:?}, got {got:?}"
    );
}

/// Wait until the supervisor records a first cause (authoritative) or the
/// handler drops. Prefer cause over `session_alive` — teardown grace delays Drop.
async fn wait_supervisor(
    progress: &Progress,
    cause: &russh::server::DisconnectCauseSlot,
    timeout: Duration,
) {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if cause.get().is_some() || !progress.session_alive() {
            // Brief settle for Drop after cause is recorded.
            sleep(Duration::from_millis(200)).await;
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. rekey-stall → RekeyTimeout
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s0_incident_repro_rekey_stall_client_initiated() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();

    let down_window = 8 * 1024 * 1024u32;
    let pkt = 32 * 1024u32;
    let cause = russh::server::DisconnectCauseSlot::new();
    eprintln!("s1 rekey-stall: rekey_dl={REKEY_DL:?} wd={WD:?}");

    let progress = Progress::new();
    let addr = free_addr();
    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: down_window,
            maximum_packet_size: pkt,
            rekey_write_limit: usize::MAX / 4,
            first_channel_mode: ServerMode::FloodForever,
            inactivity_timeout: Some(Duration::from_secs(600)),
            keepalive_interval: None,
            // Write watchdog must NOT win: keep it longer than rekey deadline.
            write_progress_deadline: Duration::from_secs(30),
            write_min_drain: None,
            rekey_deadline: REKEY_DL,
            teardown_grace: GRACE,
            disconnect_cause_slot: Some(cause.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let hold = russh::client::test_hooks::RekeyHoldGate::new();
    let mut client_cfg = default_client_config();
    client_cfg.window_size = down_window;
    client_cfg.maximum_packet_size = pkt;
    client_cfg.rekey_hold = Some(hold.clone());
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);

    progress.mark_base();
    sleep(Duration::from_millis(300)).await;
    assert!(progress.total() > 0);

    hold.arm();
    session.rekey_soon().await?;
    wait_rekey_held(&hold, Duration::from_secs(5)).await?;
    eprintln!("s1 rekey-stall: hold engaged; waiting for RekeyTimeout");

    wait_supervisor(&progress, &cause, OBSERVE).await;
    eprintln!(
        "s1 rekey-stall: session_alive={} cause={:?}",
        progress.session_alive(),
        cause.get()
    );
    assert_cause(&cause, DisconnectCause::RekeyTimeout, "rekey-stall");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 1b. negative: no rekey → no tear-down / bulk flows
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s0_incident_repro_rekey_stall_negative_no_rekey() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();

    let observe = Duration::from_secs(4);
    let stall_for = stall_for_from_observe(observe);
    let down_window = 8 * 1024 * 1024u32;
    let pkt = 32 * 1024u32;

    let progress = Progress::new();
    let addr = free_addr();
    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: down_window,
            maximum_packet_size: pkt,
            rekey_write_limit: usize::MAX / 4,
            first_channel_mode: ServerMode::FloodForever,
            inactivity_timeout: Some(Duration::from_secs(600)),
            write_progress_deadline: Duration::from_secs(30),
            write_min_drain: None,
            rekey_deadline: Duration::from_secs(30),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let hold = russh::client::test_hooks::RekeyHoldGate::new();
    let mut client_cfg = default_client_config();
    client_cfg.window_size = down_window;
    client_cfg.maximum_packet_size = pkt;
    client_cfg.rekey_hold = Some(hold.clone());
    let (session, _ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);

    progress.mark_base();
    sleep(Duration::from_millis(200)).await;
    let report = observe_write_stall(&progress, observe, stall_for).await;
    eprintln!("s1 rekey-stall NEGATIVE: {report:?}");

    assert!(report.session_alive, "negative: session stays up");
    assert!(
        !report.stalled && report.end_bytes > report.start_bytes,
        "negative: bulk must keep flowing without rekey: {report:?}"
    );
    assert!(!hold.rekey_reached_newkeys_stage());
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. talk-no-read → WriteStalled
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s0_talk_no_read() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();

    let down_window = 16 * 1024 * 1024u32;
    let up_window = 2 * 1024 * 1024u32;
    let pkt = 32 * 1024u32;
    let cause = russh::server::DisconnectCauseSlot::new();
    let flood_gate = FloodStartGate::new();

    let progress = Progress::new();
    let addr = free_addr();
    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: up_window,
            maximum_packet_size: pkt,
            first_channel_mode: ServerMode::FloodForever,
            secondary_mode: ServerMode::DrainInbound,
            inactivity_timeout: Some(Duration::from_secs(600)),
            keepalive_interval: Some(Duration::from_secs(1)),
            keepalive_max: 100,
            rekey_write_limit: usize::MAX / 4,
            flood_start: Some(flood_gate.clone()),
            write_progress_deadline: WD,
            write_min_drain: None, // activity layer alone
            rekey_deadline: Duration::from_secs(30),
            teardown_grace: GRACE,
            disconnect_cause_slot: Some(cause.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = down_window;
    client_cfg.maximum_packet_size = pkt;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;

    let down = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(down);
    let up = session.channel_open_session().await?;
    let _feeder = spawn_uplink_feeder(up);

    sleep(Duration::from_millis(100)).await;
    assert_eq!(progress.total(), 0);

    ctrl.freeze_read();
    flood_gate.release();
    eprintln!("s1 talk-no-read: TCP frozen + flood released; wait WriteStalled");

    wait_supervisor(&progress, &cause, OBSERVE).await;
    eprintln!(
        "s1 talk-no-read: alive={} bytes={} cause={:?}",
        progress.session_alive(),
        progress.total(),
        cause.get()
    );

    assert!(progress.total() > 0, "some bulk must have been accepted");
    assert_down_credit_positive(progress.total(), down_window, pkt, "talk-no-read");
    assert_cause(&cause, DisconnectCause::WriteStalled, "talk-no-read");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. zero-window-legit → never torn down (G2)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s0_zero_window_legit() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();

    let observe = OBSERVE;
    let win = 8 * 1024u32;
    let pkt = 4 * 1024u32;
    let cause = russh::server::DisconnectCauseSlot::new();

    let progress = Progress::new();
    let addr = free_addr();
    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: win,
            maximum_packet_size: pkt,
            first_channel_mode: ServerMode::FloodForever,
            secondary_mode: ServerMode::Idle,
            inactivity_timeout: Some(Duration::from_secs(600)),
            rekey_write_limit: usize::MAX / 4,
            // Short watchdog — must NOT fire on pure peer-window=0.
            write_progress_deadline: WD,
            write_min_drain: Some((4 * 1024, WD)),
            rekey_deadline: Duration::from_secs(30),
            teardown_grace: GRACE,
            disconnect_cause_slot: Some(cause.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = win;
    client_cfg.maximum_packet_size = pkt;
    let session = connect_plain(addr, client_cfg).await?;

    let ch0 = session.channel_open_session().await?;
    let _frozen = freeze_channel_consumer(ch0);
    let _ch1 = session.channel_open_session().await?;

    progress.mark_base();
    let filled = wait_progress_stable(
        &progress,
        Duration::from_millis(400),
        Duration::from_secs(10),
    )
    .await?;
    eprintln!("s1 zero-window-legit: stable at {filled}");
    assert!(filled > 0);

    let t0 = std::time::Instant::now();
    let baseline = progress.total();
    while t0.elapsed() < observe {
        sleep(Duration::from_millis(500)).await;
        assert_eq!(progress.total(), baseline, "G2: must stay at zero progress");
        assert!(
            progress.session_alive() && !session.is_closed(),
            "G2: must not tear down peer-window=0"
        );
    }
    assert!(cause.get().is_none(), "G2: no supervisor cause: {:?}", cause.get());
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. write-stall-during-rekey → WriteStalled (before RekeyTimeout)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s0_write_stall_during_rekey() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();

    let down_window = 16 * 1024 * 1024u32;
    let pkt = 32 * 1024u32;
    let cause = russh::server::DisconnectCauseSlot::new();
    let flood_gate = FloodStartGate::new();

    let progress = Progress::new();
    let addr = free_addr();
    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: down_window,
            maximum_packet_size: pkt,
            rekey_write_limit: usize::MAX / 4,
            first_channel_mode: ServerMode::FloodForever,
            inactivity_timeout: Some(Duration::from_secs(600)),
            flood_start: Some(flood_gate.clone()),
            // Write watchdog fires first; rekey deadline is longer.
            write_progress_deadline: WD,
            write_min_drain: None,
            rekey_deadline: Duration::from_secs(30),
            teardown_grace: GRACE,
            disconnect_cause_slot: Some(cause.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = down_window;
    client_cfg.maximum_packet_size = pkt;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    let channel = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(channel);

    sleep(Duration::from_millis(80)).await;
    assert_eq!(progress.total(), 0);

    ctrl.freeze_read();
    flood_gate.release();
    let stalled_level = wait_progress_stable(
        &progress,
        Duration::from_millis(300),
        Duration::from_secs(5),
    )
    .await?;
    eprintln!("s1 write-stall-during-rekey: parked at {stalled_level}");
    assert!(stalled_level > 0);
    assert_down_credit_positive(stalled_level, down_window, pkt, "pre-rekey");

    let kex_before = progress.kex_count.load(Ordering::Relaxed);
    session.rekey_soon().await?;
    sleep(Duration::from_millis(50)).await;

    wait_supervisor(&progress, &cause, OBSERVE).await;
    eprintln!(
        "s1 write-stall-during-rekey: alive={} cause={:?} kex={}->{}",
        progress.session_alive(),
        cause.get(),
        kex_before,
        progress.kex_count.load(Ordering::Relaxed)
    );

    assert_cause(&cause, DisconnectCause::WriteStalled, "write-stall-during-rekey");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. trickle-read: min_drain on → WriteStalled; off → survives
// ─────────────────────────────────────────────────────────────────────────────

/// True trickle-read: same TCP trickle load + same long activity deadline;
/// only `write_min_drain` differs. ON must tear down near the strategy window
/// with WriteStalled; OFF must survive the same observe period.
#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s1_trickle_read_min_drain_on() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let cause = russh::server::DisconnectCauseSlot::new();
    let down_window = 16 * 1024 * 1024u32;
    let pkt = 32 * 1024u32;
    // Strategy: need ≥4 KiB / 2s. Trickle delivers ≤512 B/s → never meets threshold.
    let min_drain_window = Duration::from_secs(2);
    let activity_dl = Duration::from_secs(30); // same as OFF; long enough strategy fires first

    let progress = Progress::new();
    let addr = free_addr();
    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: down_window,
            maximum_packet_size: pkt,
            first_channel_mode: ServerMode::FloodForever,
            rekey_write_limit: usize::MAX / 4,
            inactivity_timeout: Some(Duration::from_secs(600)),
            write_progress_deadline: activity_dl,
            write_min_drain: Some((4 * 1024, min_drain_window)),
            teardown_grace: GRACE,
            disconnect_cause_slot: Some(cause.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = down_window;
    client_cfg.maximum_packet_size = pkt;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    // Real trickle: ≤512 bytes every 1s (≪ 4 KiB / 2s), keeps activity resetting.
    ctrl.set_trickle(512, Duration::from_secs(1));
    let ch = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(ch);

    // Strategy window 2s; allow a couple of slides after initial burst, assert near window.
    wait_supervisor(&progress, &cause, Duration::from_secs(12)).await;
    eprintln!(
        "s1 trickle ON: alive={} bytes={} cause={:?}",
        progress.session_alive(),
        progress.total(),
        cause.get()
    );
    assert_cause(&cause, DisconnectCause::WriteStalled, "trickle min_drain ON");
    Ok(())
}

/// Same trickle load + same activity deadline as ON; strategy OFF → must survive.
#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s1_trickle_read_min_drain_off() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let cause = russh::server::DisconnectCauseSlot::new();
    let down_window = 16 * 1024 * 1024u32;
    let pkt = 32 * 1024u32;
    let activity_dl = Duration::from_secs(30); // identical to ON

    let progress = Progress::new();
    let addr = free_addr();
    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            window_size: down_window,
            maximum_packet_size: pkt,
            first_channel_mode: ServerMode::FloodForever,
            rekey_write_limit: usize::MAX / 4,
            inactivity_timeout: Some(Duration::from_secs(600)),
            write_progress_deadline: activity_dl,
            write_min_drain: None, // only difference vs ON
            teardown_grace: GRACE,
            disconnect_cause_slot: Some(cause.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    let mut client_cfg = default_client_config();
    client_cfg.window_size = down_window;
    client_cfg.maximum_packet_size = pkt;
    let (session, ctrl) = connect_faulty(addr, client_cfg, progress.clone()).await?;
    ctrl.set_trickle(512, Duration::from_secs(1)); // same load as ON
    let ch = session.channel_open_session().await?;
    let _drainer = spawn_channel_drainer(ch);

    // Longer than ON's strategy window (2s); shorter than activity 30s.
    sleep(Duration::from_secs(6)).await;
    eprintln!(
        "s1 trickle OFF: alive={} cause={:?}",
        progress.session_alive(),
        cause.get()
    );
    assert!(
        progress.session_alive() && cause.get().is_none(),
        "trickle OFF must NOT tear down under same load; cause={:?}",
        cause.get()
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. 他连零影响: rekey-stall tear-down of conn A must not kill conn B
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s1_rekey_stall_other_connection_unaffected() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();

    let down_window = 8 * 1024 * 1024u32;
    let pkt = 32 * 1024u32;

    // Victim connection (will rekey-stall).
    let cause_a = russh::server::DisconnectCauseSlot::new();
    let progress_a = Progress::new();
    let addr_a = free_addr();
    let server_a = FloodServer::new(
        progress_a.clone(),
        FloodServerConfig {
            window_size: down_window,
            maximum_packet_size: pkt,
            rekey_write_limit: usize::MAX / 4,
            first_channel_mode: ServerMode::FloodForever,
            write_progress_deadline: Duration::from_secs(30),
            write_min_drain: None,
            rekey_deadline: REKEY_DL,
            teardown_grace: GRACE,
            disconnect_cause_slot: Some(cause_a.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _sa = server_a.spawn(addr_a);
    wait_listening(addr_a).await;

    // Healthy connection on a separate server instance / port.
    let progress_b = Progress::new();
    let addr_b = free_addr();
    let server_b = FloodServer::new(
        progress_b.clone(),
        FloodServerConfig {
            window_size: down_window,
            maximum_packet_size: pkt,
            rekey_write_limit: usize::MAX / 4,
            first_channel_mode: ServerMode::FloodForever,
            write_progress_deadline: Duration::from_secs(30),
            write_min_drain: None,
            rekey_deadline: Duration::from_secs(30),
            ..FloodServerConfig::default()
        },
    );
    let _sb = server_b.spawn(addr_b);
    wait_listening(addr_b).await;

    // Connect A (victim).
    let hold = russh::client::test_hooks::RekeyHoldGate::new();
    let mut cfg_a = default_client_config();
    cfg_a.window_size = down_window;
    cfg_a.maximum_packet_size = pkt;
    cfg_a.rekey_hold = Some(hold.clone());
    let (session_a, _) = connect_faulty(addr_a, cfg_a, progress_a.clone()).await?;
    let ch_a = session_a.channel_open_session().await?;
    let _da = spawn_channel_drainer(ch_a);

    // Connect B (healthy).
    let mut cfg_b = default_client_config();
    cfg_b.window_size = down_window;
    cfg_b.maximum_packet_size = pkt;
    let (session_b, _) = connect_faulty(addr_b, cfg_b, progress_b.clone()).await?;
    let ch_b = session_b.channel_open_session().await?;
    let _db = spawn_channel_drainer(ch_b);

    sleep(Duration::from_millis(300)).await;
    assert!(progress_a.total() > 0 && progress_b.total() > 0);

    hold.arm();
    session_a.rekey_soon().await?;
    wait_rekey_held(&hold, Duration::from_secs(5)).await?;

    wait_supervisor(&progress_a, &cause_a, OBSERVE).await;
    assert_cause(&cause_a, DisconnectCause::RekeyTimeout, "isolation victim");

    // B continues to make progress after A dies.
    let b0 = progress_b.total();
    sleep(Duration::from_millis(500)).await;
    let b1 = progress_b.total();
    eprintln!("s1 isolation: A dead, B bytes {b0} → {b1}");
    assert!(
        progress_b.session_alive() && b1 > b0,
        "healthy connection B must keep flowing after A is torn down"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Auth success + idle (InitCompression): must NOT HandshakeTimeout
// ─────────────────────────────────────────────────────────────────────────────
//
// After publickey accept the server enters EncryptedState::InitCompression and
// only moves to Authenticated on the next post-auth packet. Legitimate clients
// may sit idle after auth without opening a channel — handshake_deadline must
// treat InitCompression as complete (S1 r2 NO-GO fix).

#[cfg(feature = "_test_hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s1_auth_success_idle_survives_handshake_deadline() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();
    let cause = russh::server::DisconnectCauseSlot::new();
    // Short absolute handshake budget: if InitCompression were still "in handshake",
    // idling 3s after auth would be mis-killed as HandshakeTimeout.
    let handshake_dl = Duration::from_secs(2);
    let idle_after_auth = Duration::from_secs(3);

    let progress = Progress::new();
    let addr = free_addr();
    let server = FloodServer::new(
        progress.clone(),
        FloodServerConfig {
            // No flood needed — we never open a channel.
            first_channel_mode: ServerMode::Idle,
            inactivity_timeout: Some(Duration::from_secs(600)),
            handshake_deadline: handshake_dl,
            write_progress_deadline: Duration::from_secs(30),
            write_min_drain: None,
            rekey_deadline: Duration::from_secs(30),
            teardown_grace: GRACE,
            disconnect_cause_slot: Some(cause.clone()),
            ..FloodServerConfig::default()
        },
    );
    let _srv = server.spawn(addr);
    wait_listening(addr).await;

    // Publickey auth succeeds; intentionally do NOT open any channel / global request.
    let session = connect_plain(addr, default_client_config()).await?;
    eprintln!(
        "s1 auth-idle: authenticated; idling {idle_after_auth:?} \
         (handshake_deadline={handshake_dl:?})"
    );

    sleep(idle_after_auth).await;

    eprintln!(
        "s1 auth-idle: alive={} closed={} cause={:?}",
        progress.session_alive(),
        session.is_closed(),
        cause.get()
    );
    assert!(
        progress.session_alive() && !session.is_closed(),
        "post-auth idle (InitCompression) must not be torn down by handshake_deadline"
    );
    assert!(
        cause.get().is_none(),
        "first-cause must stay None after post-auth idle; got {:?}",
        cause.get()
    );
    Ok(())
}
