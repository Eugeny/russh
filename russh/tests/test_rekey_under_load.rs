//! Regression gate for the **rekey-under-load wedge**.
//!
//! History: with blocking inbound delivery, a key re-exchange starting mid-bulk-transfer could
//! wedge a session permanently — the loop sat parked in a per-channel `chan.send().await` while
//! the receiver arm was gated for the whole exchange, so the kex packets that would have
//! released everything were never read (reproduced in production at the default 1 GiB
//! `rekey_write_limit`, second back-to-back speedtest). The fork's stopgap was to disable
//! volume/time rekey entirely. Both session loops now deliver inbound data without blocking
//! (Scheme C, `pending_inbound.rs`) and volume/time rekey is re-enabled; this test holds that
//! line.
//!
//! Scenario: the server floods N channels (server → client) with a tiny `rekey_write_limit`, so
//! server-initiated rekeys fire continuously mid-transfer; the client additionally forces its
//! own rekeys via `rekey_soon()`, and the client consumers deliberately FREEZE for long
//! stretches (so channels are backpressured with full app buffers while re-exchanges run —
//! exactly the historical wedge window). The transfer must still complete, byte-perfect, within
//! the deadline, and multiple re-exchanges must actually have happened.
//!
//! Run:
//!   cargo test -p russh --test test_rekey_under_load -- --nocapture

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use russh::keys::PrivateKeyWithHashAlg;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, client};
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

const NUM_CHANNELS: usize = 4;
const BYTES_PER_CHANNEL: u64 = 8 * 1024 * 1024;
const FILL: u8 = 0xC3;
/// Small enough that a transfer of `BYTES_PER_CHANNEL * NUM_CHANNELS` crosses it many times.
const REKEY_WRITE_LIMIT: usize = 1024 * 1024;

static KEX_COUNT: AtomicUsize = AtomicUsize::new(0);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rekey_under_saturated_transfer_completes() -> Result<(), anyhow::Error> {
    let _ = env_logger::builder().is_test(false).try_init();

    let server_addr = free_addr();
    tokio::spawn(Server::run(server_addr));
    while TcpStream::connect(server_addr).is_err() {
        sleep(Duration::from_millis(10)).await;
    }

    let config = Arc::new(client::Config {
        // Small windows + tiny app buffer keep the channels backpressured, so re-exchanges
        // overlap with full per-channel buffers — the historical wedge window.
        window_size: 64 * 1024,
        maximum_packet_size: 32 * 1024,
        channel_buffer_size: 4,
        ..Default::default()
    });
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());

    let mut session = russh::client::connect(config, server_addr, Client).await?;
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

    let received = Arc::new(AtomicU64::new(0));
    let mut readers = Vec::new();
    for idx in 0..NUM_CHANNELS {
        let mut channel = session.channel_open_session().await?;
        let received = received.clone();
        readers.push(tokio::spawn(async move {
            let mut reader = channel.make_reader();
            let mut buf = vec![0u8; 16 * 1024];
            let mut got: u64 = 0;
            let mut next_freeze = BYTES_PER_CHANNEL / 3;
            loop {
                let n = match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => panic!("channel {idx} read error after {got} bytes: {e}"),
                };
                assert!(
                    buf[..n].iter().all(|&b| b == FILL),
                    "channel {idx} data corrupted around offset {got}"
                );
                got += n as u64;
                received.fetch_add(n as u64, Ordering::Relaxed);
                // Freeze the consumer twice per channel for a long stretch: the channel
                // backpressures (full app buffer, inbound queue engaged, window withheld)
                // while the server keeps crossing its rekey limit on the other channels.
                if got >= next_freeze && next_freeze <= 2 * BYTES_PER_CHANNEL / 3 {
                    next_freeze += BYTES_PER_CHANNEL / 3;
                    sleep(Duration::from_millis(1200)).await;
                }
            }
            got
        }));
    }

    // Force client-initiated re-exchanges mid-transfer as well (the exact scenario flagged as
    // the remaining wedge risk: a client-forced rekey under a saturated download). The readers
    // are already running as independent tasks, so the transfer is saturated while these fire.
    for _ in 0..3 {
        sleep(Duration::from_millis(700)).await;
        session.rekey_soon().await?;
    }

    let expected_total = BYTES_PER_CHANNEL * NUM_CHANNELS as u64;
    let all = async {
        for (idx, r) in readers.into_iter().enumerate() {
            let got = r.await.expect("reader task panicked");
            assert_eq!(
                got, BYTES_PER_CHANNEL,
                "channel {idx} ended early: {got}/{BYTES_PER_CHANNEL} bytes"
            );
        }
    };
    // Generous deadline: the transfer takes a few seconds when healthy; a rekey wedge hangs it
    // forever. Progress is also reported so a failure log shows where it died.
    let progress = {
        let received = received.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(2)).await;
                eprintln!(
                    "rekey-under-load: {} / {expected_total} bytes, {} kex completions",
                    received.load(Ordering::Relaxed),
                    KEX_COUNT.load(Ordering::Relaxed),
                );
            }
        })
    };
    tokio::time::timeout(Duration::from_secs(120), all)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "rekey-under-load WEDGE: transfer stalled at {} / {expected_total} bytes with {} \
                 kex completions — a re-exchange failed to complete under load",
                received.load(Ordering::Relaxed),
                KEX_COUNT.load(Ordering::Relaxed),
            )
        });
    progress.abort();

    // The initial kex counts once; anything beyond it is a completed re-exchange. The tiny
    // rekey_write_limit alone crosses dozens of times during the transfer.
    let kexes = KEX_COUNT.load(Ordering::Relaxed);
    eprintln!(
        "rekey-under-load: transfer complete ({expected_total} bytes), {kexes} kex completions"
    );
    assert!(
        kexes >= 3,
        "expected several re-exchanges during the transfer, saw only {kexes} kex completions — \
         the volume-based rekey trigger is not firing"
    );
    Ok(())
}

fn free_addr() -> SocketAddr {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

#[derive(Clone)]
struct Server;

impl Server {
    async fn run(addr: SocketAddr) {
        let config = Arc::new(server::Config {
            keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
            window_size: 64 * 1024,
            maximum_packet_size: 32 * 1024,
            channel_buffer_size: 4,
            limits: russh::Limits {
                rekey_write_limit: REKEY_WRITE_LIMIT,
                ..Default::default()
            },
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
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        // Flood exactly BYTES_PER_CHANNEL down the channel through the window-reserving
        // writer path (what zfc's relay drives), then EOF+close via drop.
        tokio::spawn(async move {
            let mut writer = channel.make_writer();
            let chunk = vec![FILL; 32 * 1024];
            let mut left = BYTES_PER_CHANNEL as usize;
            while left > 0 {
                let n = left.min(chunk.len());
                #[allow(clippy::indexing_slicing)]
                if writer.write_all(&chunk[..n]).await.is_err() {
                    return;
                }
                left -= n;
            }
            let _ = writer.shutdown().await;
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
    async fn kex_done(
        &mut self,
        _shared_secret: Option<&[u8]>,
        _names: &russh::Names,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        KEX_COUNT.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
