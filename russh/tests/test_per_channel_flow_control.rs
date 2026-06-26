//! Regression test for per-channel head-of-line blocking.
//!
//! Before the fix, the session loop forwarded `CHANNEL_DATA` to the
//! `Channel<Msg>` mpsc with `.send().await` and replenished the SSH receive
//! window on receipt. A consumer that stopped draining one channel would park
//! the entire connection — every other channel and keepalives included.
//!
//! After the fix, the loop uses `try_send` and withholds `WINDOW_ADJUST` for a
//! backed-up channel: the peer's window for that channel drains to zero, the
//! peer stops sending on it, and the loop stays live for other channels.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelMsg};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

const CHANNEL_BUFFER_SIZE: usize = 2;
const CHUNK: usize = 8 * 1024;
/// Exactly the bytes written to channel A while its consumer is parked, so
/// the server's local receive window for A reaches zero and the post-drain
/// write below depends on `WINDOW_ADJUST` being sent from the drain path.
const WINDOW_SIZE: u32 = (A_STALLED_WRITES * CHUNK) as u32;
const A_STALLED_WRITES: usize = CHANNEL_BUFFER_SIZE + 6;

#[tokio::test]
async fn slow_channel_does_not_block_sibling() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init();

    let addr = common::addr();
    let (channel_tx, mut channel_rx) = mpsc::unbounded_channel::<Channel<Msg>>();

    tokio::spawn(Server::run(addr, channel_tx));
    common::wait_for_server(addr).await;

    let session = common::connect(addr).await?;

    // Two channels on the same connection. Channel A's server-side consumer
    // is parked; channel B's consumer drains promptly.
    let chan_a = session.channel_open_session().await?;
    let server_a = channel_rx.recv().await.expect("server channel a");
    let chan_b = session.channel_open_session().await?;
    let mut server_b = channel_rx.recv().await.expect("server channel b");

    let b_count = Arc::new(AtomicUsize::new(0));
    let (b_first_tx, b_first_rx) = oneshot::channel::<()>();
    let b_consumer = tokio::spawn({
        let b_count = b_count.clone();
        async move {
            let mut first = Some(b_first_tx);
            while let Some(msg) = server_b.wait().await {
                if let ChannelMsg::Data { data } = msg {
                    b_count.fetch_add(data.len(), Ordering::Relaxed);
                    if let Some(tx) = first.take() {
                        let _ = tx.send(());
                    }
                }
            }
        }
    });

    // Flood channel A well past its mpsc capacity. With CHANNEL_BUFFER_SIZE=2
    // the server-side mpsc fills after two packets; the rest land in the
    // session's per-channel overflow and the server stops re-opening A's
    // window. The session loop must NOT park.
    let mut writer_a = chan_a.make_writer();
    let chunk_a = vec![0xAAu8; CHUNK];
    for _ in 0..A_STALLED_WRITES {
        timeout(Duration::from_secs(5), writer_a.write_all(&chunk_a))
            .await
            .expect("write to channel A should not time out while window is open")?;
    }

    // Channel B must still be served promptly even though A is backed up.
    let mut writer_b = chan_b.make_writer();
    let chunk_b = vec![0xBBu8; CHUNK];
    timeout(Duration::from_secs(5), writer_b.write_all(&chunk_b))
        .await
        .expect("write to channel B should not be blocked by channel A")?;
    timeout(Duration::from_secs(5), b_first_rx)
        .await
        .expect("channel B data should reach the server while channel A is stalled")?;
    assert_eq!(b_count.load(Ordering::Relaxed), CHUNK);

    // Now unblock channel A's consumer and confirm its backlog drains and the
    // session re-opens A's window so further writes proceed.
    let (a_done_tx, a_done_rx) = oneshot::channel::<usize>();
    let server_a_consumer = tokio::spawn(async move {
        let mut server_a = server_a;
        let mut total = 0;
        while let Some(msg) = server_a.wait().await {
            match msg {
                ChannelMsg::Data { data } => total += data.len(),
                ChannelMsg::Eof => break,
                _ => {}
            }
        }
        let _ = a_done_tx.send(total);
    });

    // A's window is at zero; this write only completes if the server's drain
    // path emitted WINDOW_ADJUST after the consumer caught up.
    timeout(Duration::from_secs(5), writer_a.write_all(&chunk_a))
        .await
        .expect("channel A write should resume once consumer drains")?;
    chan_a.eof().await?;
    let a_total = timeout(Duration::from_secs(5), a_done_rx)
        .await
        .expect("channel A backlog should drain once consumer resumes")?;
    assert_eq!(a_total, CHUNK * (A_STALLED_WRITES + 1));

    drop(b_consumer);
    drop(server_a_consumer);
    Ok(())
}

#[derive(Clone)]
struct Server {
    channels: mpsc::UnboundedSender<Channel<Msg>>,
}

impl Server {
    async fn run(addr: SocketAddr, channels: mpsc::UnboundedSender<Channel<Msg>>) {
        let config = common::server_config(WINDOW_SIZE, CHANNEL_BUFFER_SIZE);
        let mut sh = Server { channels };
        sh.run_on_address(config, addr).await.unwrap();
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
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        // Hand the channel out to the test body so it controls consumption.
        let _ = self.channels.send(channel);
        Ok(())
    }
}
