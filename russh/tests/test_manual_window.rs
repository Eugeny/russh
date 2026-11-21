//! `server::Config::manual_window`: a channel's receive window grows only
//! through `server::Handle::grant_window`. A russh client and server talk in
//! process over a duplex pipe. The second test is the control (without the
//! flag, russh refills the window itself), which shows that the first test
//! would see a refill.
//!
//! Ordering, not time: the server answers each full window with an `ack`
//! data message, and russh writes any window adjust it makes for a packet
//! before the handler runs for that packet, so a refill always reaches the
//! client before the `ack`.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use russh::keys::PrivateKey;
use russh::keys::ssh_key::private::Ed25519Keypair;
use russh::server::{Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, Limits, MethodKind, MethodSet};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};

/// The initial window, two packets.
const WINDOW: u32 = 64 * 1024;
const PACKET: u32 = 32 * 1024;
/// A liveness bound only: every wait here ends in milliseconds when healthy.
const LIVENESS: Duration = Duration::from_secs(30);

struct Server {
    opened: mpsc::UnboundedSender<ChannelId>,
    grant_on_open: u32,
    /// If set, the first `data` call waits for it, so the server reads
    /// nothing more until then.
    gate: Option<Arc<Notify>>,
    received: u64,
    next_ack: u64,
}

impl russh::server::Handler for Server {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let _ = self.opened.send(channel.id());
        reply.accept().await;
        if self.grant_on_open > 0 {
            session
                .handle()
                .grant_window(channel.id(), self.grant_on_open)
                .expect("the session is running");
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(gate) = self.gate.take() {
            gate.notified().await;
        }
        self.received += data.len() as u64;
        while self.received >= self.next_ack {
            session.data(channel, &b"ack"[..])?;
            self.next_ack += u64::from(WINDOW);
        }
        Ok(())
    }
}

struct Client;

impl russh::client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct Pair {
    server: russh::server::Handle,
    server_channel: ChannelId,
    channel: Channel<russh::client::Msg>,
    _client: russh::client::Handle<Client>,
    /// Bytes the client has written into the pipe so far.
    written: Arc<AtomicUsize>,
    /// Opens `Options::gate_first_data`.
    gate: Arc<Notify>,
}

/// The client's end of the pipe, counting what the client writes.
struct Counted<S> {
    inner: S,
    written: Arc<AtomicUsize>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = poll {
            self.written.fetch_add(n, Ordering::SeqCst);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Default)]
struct Options {
    manual_window: bool,
    /// Granted as soon as the channel is accepted.
    grant_on_open: u32,
    limits: Option<Limits>,
    gate_first_data: bool,
}

async fn connect(manual_window: bool) -> Pair {
    connect_with(Options {
        manual_window,
        ..Default::default()
    })
    .await
}

async fn connect_with(options: Options) -> Pair {
    tokio::time::timeout(LIVENESS, setup(options))
        .await
        .expect("setup finished in time")
}

async fn setup(options: Options) -> Pair {
    let key = PrivateKey::from(Ed25519Keypair::from_seed(&[7; 32]));
    let config = russh::server::Config {
        methods: MethodSet::from(&[MethodKind::None][..]),
        auth_rejection_time: Duration::ZERO,
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![key],
        window_size: WINDOW,
        maximum_packet_size: PACKET,
        manual_window: options.manual_window,
        limits: options.limits.unwrap_or_default(),
        ..Default::default()
    };
    let (client_io, server_io) = tokio::io::duplex(8 << 20);
    let written = Arc::new(AtomicUsize::new(0));
    let client_io = Counted {
        inner: client_io,
        written: written.clone(),
    };
    let gate = Arc::new(Notify::new());
    let (opened, mut open) = mpsc::unbounded_channel();
    let handler = Server {
        opened,
        grant_on_open: options.grant_on_open,
        gate: options.gate_first_data.then(|| gate.clone()),
        received: 0,
        next_ack: u64::from(WINDOW),
    };
    let running = russh::server::run_stream(Arc::new(config), server_io, handler);
    let connecting = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_io,
        Client,
    );
    let (running, client) = tokio::join!(running, connecting);
    let running = running.expect("server handshake");
    let server = running.handle();
    tokio::spawn(running);
    let mut client = client.expect("client handshake");
    let auth = client.authenticate_none("anyone").await.unwrap();
    assert!(auth.success(), "{auth:?}");
    let channel = client.channel_open_session().await.unwrap();
    let server_channel = open.recv().await.unwrap();
    Pair {
        server,
        server_channel,
        channel,
        _client: client,
        written,
        gate,
    }
}

/// What the client sees next: a window adjust (`Some(new_size)`) or the
/// server's `ack` (`None`).
async fn next(channel: &mut Channel<russh::client::Msg>) -> Option<u32> {
    loop {
        match tokio::time::timeout(LIVENESS, channel.wait()).await {
            Ok(Some(ChannelMsg::WindowAdjusted { new_size })) => return Some(new_size),
            Ok(Some(ChannelMsg::Data { data })) => {
                assert_eq!(&data[..], b"ack");
                return None;
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("the channel closed"),
            Err(_) => panic!("nothing within {LIVENESS:?}"),
        }
    }
}

async fn send_window(channel: &Channel<russh::client::Msg>, bytes: u32) {
    let data = vec![b'x'; bytes as usize];
    tokio::time::timeout(LIVENESS, channel.data(&data[..]))
        .await
        .expect("the client's send stalled")
        .unwrap();
}

#[tokio::test]
async fn with_manual_window_the_window_grows_only_by_grants() {
    let mut pair = connect(true).await;
    send_window(&pair.channel, WINDOW).await;
    assert_eq!(
        next(&mut pair.channel).await,
        None,
        "a full window was refilled without a grant"
    );
    let grant = 2 * WINDOW;
    pair.server
        .grant_window(pair.server_channel, grant)
        .expect("the session is running");
    assert_eq!(
        next(&mut pair.channel).await,
        Some(grant),
        "the grant is the whole window"
    );
    // The granted bytes are usable, and still nothing refills on receipt.
    send_window(&pair.channel, WINDOW).await;
    assert_eq!(next(&mut pair.channel).await, None);
    send_window(&pair.channel, WINDOW).await;
    assert_eq!(next(&mut pair.channel).await, None);
    pair.server
        .grant_window(pair.server_channel, PACKET)
        .unwrap();
    assert_eq!(next(&mut pair.channel).await, Some(PACKET));
}

#[tokio::test]
async fn without_manual_window_russh_refills_the_window_on_receipt() {
    let mut pair = connect(false).await;
    send_window(&pair.channel, WINDOW).await;
    let mut refills = 0;
    while let Some(size) = next(&mut pair.channel).await {
        assert!(size <= WINDOW, "{size}");
        refills += 1;
    }
    assert!(refills > 0, "russh's own refill came before the ack");
}

#[tokio::test]
async fn with_manual_window_received_data_uses_up_the_window() {
    let mut pair = connect(true).await;
    send_window(&pair.channel, WINDOW).await;
    assert_eq!(next(&mut pair.channel).await, None);
    // The server's window is now empty, so the largest possible grant fits.
    // Had the data not been counted, this grant would pass `u32::MAX` and be
    // dropped.
    pair.server
        .grant_window(pair.server_channel, u32::MAX)
        .unwrap();
    assert_eq!(next(&mut pair.channel).await, Some(u32::MAX));
}

/// A server-initiated key exchange starts while the client still has data in
/// flight inside a grant much larger than `window_size`. That data is
/// legitimate and must not end the session.
///
/// The server stops reading at the first data packet until the client has
/// written the whole upload into the pipe. Then it reads again and starts a
/// key exchange after 256 KiB, with the rest of the upload already in flight.
#[tokio::test]
async fn with_manual_window_a_server_rekey_accepts_granted_data_in_flight() {
    // At most one `ack` per window, fewer than the client's channel buffer
    // holds, since nothing reads them until the upload is done.
    const UPLOAD: u32 = 4 << 20;
    let mut pair = connect_with(Options {
        manual_window: true,
        grant_on_open: UPLOAD - WINDOW,
        limits: Some(Limits::new(1 << 30, 256 << 10, Duration::from_secs(3600))),
        gate_first_data: true,
    })
    .await;
    assert_eq!(next(&mut pair.channel).await, Some(UPLOAD));
    let before = pair.written.load(Ordering::SeqCst);
    send_window(&pair.channel, UPLOAD).await;
    tokio::time::timeout(LIVENESS, async {
        while pair.written.load(Ordering::SeqCst) < before + UPLOAD as usize {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the client wrote the upload into the pipe");
    pair.gate.notify_one();
    for _ in 0..UPLOAD / WINDOW {
        assert_eq!(next(&mut pair.channel).await, None, "no refill on receipt");
    }
}
