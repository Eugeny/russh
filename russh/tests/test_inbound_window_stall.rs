//! Accelerated reproducer for the SSH **inbound-proxy downstream stall**.
//!
//! Symptom in production (zfc): a long-lived, downstream-heavy `direct-tcpip` channel
//! (server -> client) permanently stalls and never recovers; the client eventually reports
//! "socket closed unexpectedly". The suspected mechanism lives in `channels/io/tx.rs`
//! (`ChannelTx::poll_writable`): the producer parks at `A == 0` (producer-side window) and a
//! `WINDOW_ADJUST`'s `notify_one()` is lost in the recreate-`WatchNotification` gap (and/or the
//! absolute `update()` SET races an in-flight decrement = A/B drift), so the producer is
//! stranded while the wire window `B` actually has room.
//!
//! Why this reproduces fast where production does not: the strand requires an `A == 0` park
//! coinciding with a `WINDOW_ADJUST`. Park frequency is `~ 1 / window_size`. Production windows
//! are ~2 MiB and the client reads fast, so parks are rare. Here we shrink the client's
//! advertised window/packet to a few KiB, flood from the server, and have the client read in
//! slow random bursts across many channels — driving the window to oscillate around zero
//! thousands of times per second per channel, so the race surfaces in seconds.
//!
//! Run:
//!   RUST_LOG=russh=debug cargo test -p russh --test test_inbound_window_stall -- --nocapture
//!
//! A reproduced stall shows, in the logs, a `HOLDIAG WINDOW park chan=ChannelId(N) A==0` with
//! NO matching `HOLDIAG WINDOW unpark chan=ChannelId(N)` while bytes for that channel stop
//! advancing — and the test fails with `STALL detected on channel ...`.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rand::RngExt;
use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{client, Channel};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

// --- Tunables (env-overridable for fast iteration). Keep windows tiny so the producer parks
// constantly: when window == max_packet the producer parks at `A == 0` on EVERY packet, so each
// packet is a park/WINDOW_ADJUST handshake — the maximal stress on the suspected race. ---------
fn env_u32(k: &str, d: u32) -> u32 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}
fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}
fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inbound_window_stall_repro() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();

    let window = env_u32("REPRO_WINDOW", 2048);
    let packet = env_u32("REPRO_PACKET", 2048);
    let num_channels = env_usize("REPRO_CHANNELS", 64);
    let duration = Duration::from_secs(env_u64("REPRO_SECS", 45));
    let stall_threshold = Duration::from_secs(env_u64("REPRO_STALL_SECS", 8));
    eprintln!(
        "repro cfg: window={window} packet={packet} channels={num_channels} \
         duration={}s stall_threshold={}s",
        duration.as_secs(),
        stall_threshold.as_secs()
    );

    let server_addr = free_addr();
    tokio::spawn(Server::run(server_addr));
    while TcpStream::connect(server_addr).is_err() {
        sleep(Duration::from_millis(10)).await;
    }

    // Optionally interpose a rate-throttled proxy so the server->client socket actually
    // backpressures (loopback otherwise never blocks `flush_into().await`). This is the missing
    // production ingredient: a slow remote client. REPRO_THROTTLE_KBPS=0 => direct connect.
    let throttle_kbps = env_u64("REPRO_THROTTLE_KBPS", 0);
    let addr = if throttle_kbps > 0 {
        let proxy_addr = free_addr();
        eprintln!("interposing throttled proxy @ {throttle_kbps} KB/s (downstream)");
        tokio::spawn(throttled_proxy(proxy_addr, server_addr, throttle_kbps * 1024));
        while TcpStream::connect(proxy_addr).is_err() {
            sleep(Duration::from_millis(10)).await;
        }
        proxy_addr
    } else {
        server_addr
    };

    let config = Arc::new(client::Config {
        window_size: window,
        maximum_packet_size: packet,
        ..Default::default()
    });
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());

    let mut session = russh::client::connect(config, addr, Client).await?;
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
    assert!(authed, "auth failed");

    let base = Instant::now();
    // Per-channel last-progress timestamp (millis since `base`); updated on every client read.
    let progress: Arc<Vec<AtomicU64>> =
        Arc::new((0..num_channels).map(|_| AtomicU64::new(0)).collect());
    let total_bytes = Arc::new(AtomicU64::new(0));
    // Split accounting so the regression gate is precise: channel 0 is the sole VICTIM (only it
    // floods upstream, so only its server-side inbound buffer fills when the upstream freezes);
    // channels 1..N are downstream-only HEALTHY channels that must keep flowing regardless. A
    // healthy channel stalling is the unambiguous proof that one stuck channel wedged the shared
    // session loop (cross-channel HoL) — it cannot be explained by that channel's own state.
    let victim_bytes = Arc::new(AtomicU64::new(0));
    let healthy_bytes = Arc::new(AtomicU64::new(0));
    let stalled = Arc::new(AtomicBool::new(false));

    let bidir = env_u32("REPRO_BIDIR", 0) != 0;
    let mut readers = Vec::new();
    for idx in 0..num_channels {
        eprintln!("CLI opening #{idx}");
        let mut channel = session.channel_open_session().await?;
        eprintln!("CLI opened  #{idx}");
        let progress = progress.clone();
        let total_bytes = total_bytes.clone();
        // Bidirectional: ONLY the victim (channel 0) floods UPSTREAM (client->server), mimicking
        // zfc's copy_bidirectional. When the server-side upstream drain for the victim freezes,
        // the victim's inbound buffer fills and the session loop blocks in reply()->chan.send()
        // .await — the same loop that must process EVERY channel's downstream WINDOW_ADJUST.
        // Channels 1..N send no upstream, so they can only stall via that shared-loop HoL.
        let is_victim = idx == 0;
        if bidir && is_victim {
            let mut writer = channel.make_writer();
            tokio::spawn(async move {
                let buf = vec![0x5Au8; 4096];
                loop {
                    if writer.write_all(&buf).await.is_err() {
                        break;
                    }
                }
            });
        }
        let victim_bytes = victim_bytes.clone();
        let healthy_bytes = healthy_bytes.clone();
        readers.push(tokio::spawn(async move {
            let mut reader = channel.make_reader();
            let mut buf = vec![0u8; 4096];
            loop {
                // Slow, bursty reader: read a small chunk, then sleep a random short while.
                // Each drained chunk frees window => triggers a WINDOW_ADJUST, the exact event
                // that must race the producer's park.
                let n = match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                progress[idx].store(base.elapsed().as_millis() as u64, Ordering::Relaxed);
                total_bytes.fetch_add(n as u64, Ordering::Relaxed);
                if is_victim {
                    victim_bytes.fetch_add(n as u64, Ordering::Relaxed);
                } else {
                    healthy_bytes.fetch_add(n as u64, Ordering::Relaxed);
                }
                // Mostly fast bursts, but ~1% of reads FREEZE the consumer for a long stretch
                // (simulate an SSE client idling between events). A frozen consumer lets wire
                // window B exhaust and `pending_data` fill — the production-only path. When it
                // thaws it emits a WINDOW_ADJUST; if that grant's wakeup/accounting is lost,
                // the channel never resumes = the strand we are hunting.
                let nap_ms = {
                    let mut rng = rand::rng();
                    if rng.random_range(0..100) == 0 {
                        rng.random_range(800..=2500)
                    } else {
                        rng.random_range(1..=15)
                    }
                };
                sleep(Duration::from_millis(nap_ms)).await;
            }
        }));
    }
    // give channels a moment to open + start flowing before arming the stall monitor
    sleep(Duration::from_millis(500)).await;
    let now = base.elapsed().as_millis() as u64;
    for p in progress.iter() {
        p.store(now, Ordering::Relaxed);
    }

    // Monitor loop. The gate is precise: a STALL is only declared when a HEALTHY (downstream-only,
    // idx>=1) channel makes no progress for `stall_threshold`. Such a channel sends no upstream and
    // has no per-channel reason to stall — so its starvation can ONLY be the shared session loop
    // being wedged by the victim's full inbound buffer (cross-channel HoL). We also report victim
    // vs healthy throughput separately so "the whole session died" is backed by numbers, not just
    // a single-channel idle reading.
    let deadline = Instant::now() + duration;
    let (mut last_v, mut last_h) = (0u64, 0u64);
    while Instant::now() < deadline {
        sleep(Duration::from_secs(1)).await;
        let nowm = base.elapsed().as_millis() as u64;
        let v = victim_bytes.load(Ordering::Relaxed);
        let h = healthy_bytes.load(Ordering::Relaxed);
        let v_mbps = (v - last_v) as f64 / 1_000_000.0;
        let h_mbps = (h - last_h) as f64 / 1_000_000.0;
        last_v = v;
        last_h = h;
        // worst idle among HEALTHY channels only (idx 0 is the victim, excluded from the gate)
        let mut worst = (usize::MAX, 0u64);
        for (i, p) in progress.iter().enumerate() {
            if i == 0 {
                continue;
            }
            let idle = nowm.saturating_sub(p.load(Ordering::Relaxed));
            if idle > worst.1 {
                worst = (i, idle);
            }
        }
        eprintln!(
            "repro: healthy={h_mbps:.2} MB/s victim={v_mbps:.2} MB/s, worst HEALTHY idle: chan#{} {} ms",
            worst.0, worst.1
        );
        if worst.1 > stall_threshold.as_millis() as u64 {
            stalled.store(true, Ordering::Relaxed);
            eprintln!(
                "STALL: healthy downstream-only channel #{} made no progress for {} ms \
                 (healthy aggregate {h_mbps:.2} MB/s). A channel that sends NO upstream can only \
                 stall via the shared session loop being wedged by the victim's full inbound \
                 buffer => cross-channel head-of-line blocking (RC2).",
                worst.0, worst.1
            );
            break;
        }
    }

    for r in readers {
        r.abort();
    }

    assert!(
        !stalled.load(Ordering::Relaxed),
        "RC2 cross-channel HoL reproduced: a healthy downstream-only channel was starved by the \
         victim channel's frozen upstream wedging the shared session loop"
    );
    Ok(())
}

fn free_addr() -> SocketAddr {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

/// TCP proxy: client -> [proxy] -> server. The **downstream** (server->client) direction is
/// rate-limited via a token bucket, with a deliberately small forwarding buffer, so the server's
/// socket write backs up under TCP backpressure — forcing the session loop's `flush_into().await`
/// to actually block (the RC2 head-of-line path that loopback can't otherwise exercise). The
/// upstream (client->server) direction is unthrottled.
async fn throttled_proxy(listen: SocketAddr, server: SocketAddr, bytes_per_sec: u64) {
    use tokio::net::{TcpListener as TokioListener, TcpStream as TokioStream};
    let l = TokioListener::bind(listen).await.unwrap();
    loop {
        let (client, _) = match l.accept().await {
            Ok(x) => x,
            Err(_) => break,
        };
        tokio::spawn(async move {
            let upstream = match TokioStream::connect(server).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let (mut cr, mut cw) = client.into_split();
            let (mut sr, mut sw) = upstream.into_split();
            // upstream: client -> server (unthrottled)
            let up = tokio::spawn(async move {
                let _ = tokio::io::copy(&mut cr, &mut sw).await;
            });
            // downstream: server -> client, token-bucketed at bytes_per_sec with a small buffer
            let down = tokio::spawn(async move {
                let mut buf = vec![0u8; 8 * 1024];
                let refill_per_100ms = (bytes_per_sec / 10).max(1) as i64;
                let mut tokens: i64 = refill_per_100ms;
                loop {
                    if tokens <= 0 {
                        sleep(Duration::from_millis(100)).await;
                        tokens += refill_per_100ms;
                        continue;
                    }
                    let want = tokens.min(buf.len() as i64) as usize;
                    let n = match sr.read(&mut buf[..want]).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    if cw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    tokens -= n as i64;
                }
            });
            let _ = up.await;
            let _ = down.await;
        });
    }
}

#[derive(Clone)]
struct Server;

impl Server {
    async fn run(addr: SocketAddr) {
        let config = Arc::new(server::Config {
            keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
            window_size: env_u32("REPRO_WINDOW", 2048),
            maximum_packet_size: env_u32("REPRO_PACKET", 2048),
            channel_buffer_size: env_usize("REPRO_CHAN_BUF", 4),
            // DIAG: session Msg queue capacity (default 10). Raising this to a huge value
            // discriminates the queue-full self-deadlock theory (hang disappears) from the
            // flush_into TCP-deadlock theory (hang unaffected or worse).
            event_buffer_size: env_usize("REPRO_EVENT_BUF", 10),
            ..Default::default()
        });
        Server.run_on_address(config, addr).await.unwrap();
    }
}

impl russh::server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

impl russh::server::Handler for Server {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        mut channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Confirm the open before any producer starts writing: since channel confirmations
        // became async upstream, data must not be queued ahead of CHANNEL_OPEN_CONFIRMATION.
        static OPEN_SEQ: AtomicU64 = AtomicU64::new(0);
        let oi = OPEN_SEQ.fetch_add(1, Ordering::Relaxed);
        eprintln!("SRV open #{oi}: accept enter");
        reply.accept().await;
        eprintln!("SRV open #{oi}: accept done");
        // Producer side: flood the channel via the AsyncWrite (`ChannelTx`) path — the exact
        // code zfc's relay copy drives. When the client window is exhausted this parks at
        // `A == 0`; a lost wakeup here is the stall.
        let bidir = env_u32("REPRO_BIDIR", 0) != 0;
        let writer = channel.make_writer();
        tokio::spawn(async move {
            let mut writer = writer;
            let buf = vec![0xABu8; env_usize("REPRO_SERVER_CHUNK", 8 * 1024)];
            loop {
                if writer.write_all(&buf).await.is_err() {
                    break;
                }
            }
        });
        // Slow upstream drain: read the channel's inbound (client->server) at a throttled rate so
        // the inbound buffer fills and the session loop blocks at reply()->chan.send().await.
        let slow = env_u64("REPRO_UPSTREAM_SLOW_KBPS", 32) * 1024;
        // Simulate the upstream relay FULLY hanging after N seconds (e.g. the TOT->landing path
        // stalls). The client keeps writing upstream, the inbound buffer fills, and the session
        // loop wedges at reply()->chan.send().await — if downstream then permanently strands,
        // the production "never recovers + socket closed" symptom is this cross-direction HoL.
        let freeze_at = env_u64("REPRO_UPSTREAM_FREEZE_AT_SECS", 0);
        // -1 (default) => every channel's upstream hangs; >=0 => only that channel index hangs
        // (the rest stay healthy). Used to prove ONE hung upstream wedges the WHOLE session.
        let freeze_only: i64 = std::env::var("REPRO_FREEZE_ONLY_CHAN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(-1);
        static SERVER_START: OnceLock<Instant> = OnceLock::new();
        static CHAN_SEQ: AtomicU64 = AtomicU64::new(0);
        let start = *SERVER_START.get_or_init(Instant::now);
        let my_idx = CHAN_SEQ.fetch_add(1, Ordering::Relaxed) as i64;
        let i_freeze = freeze_only < 0 || my_idx == freeze_only;
        tokio::spawn(async move {
            let mut reader = channel.make_reader();
            let mut buf = vec![0u8; 4096];
            let refill = (slow / 10).max(1) as i64;
            let mut tokens: i64 = refill;
            loop {
                if i_freeze && freeze_at > 0 && start.elapsed().as_secs() >= freeze_at {
                    // upstream hung: stop draining entirely
                    sleep(Duration::from_secs(3600)).await;
                    continue;
                }
                if !bidir {
                    // not bidir: still drain so the client's upstream writer (if any) doesn't
                    // wedge; but there is no upstream writer, so just read normally.
                    match reader.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                if tokens <= 0 {
                    sleep(Duration::from_millis(100)).await;
                    tokens += refill;
                    continue;
                }
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => tokens -= n as i64,
                    Err(_) => break,
                }
            }
        });
        Ok(())
    }
}

struct Client;

impl russh::client::Handler for Client {
    type Error = anyhow::Error;
    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
