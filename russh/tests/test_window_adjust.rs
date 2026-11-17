use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::server::{self, Auth, Msg, Server as _, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelMsg, Disconnect, client};
use ssh_key::PrivateKey;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpSocket;
use tokio::time::timeout;

const ROUNDS: usize = 4;

const ADJUSTS: usize = 4;

const SOCKET_BUFFER: u32 = 64 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closing_a_channel_with_its_window_used_up_does_not_stall_the_session()
-> Result<(), anyhow::Error> {
    let _ = env_logger::try_init();

    let addr = start_server(WhenIdle::Close).await?;

    for round in 0..ROUNDS {
        let session = connect(addr).await?;
        let channel = session.channel_open_session().await?;
        let (mut read_half, write_half) = channel.split();

        let mut writer = write_half.make_writer();
        let uploading = tokio::spawn(async move {
            let chunk = vec![0u8; 256 * 1024];
            while writer.write_all(&chunk).await.is_ok() {}
        });

        timeout(Duration::from_secs(30), async {
            while let Some(msg) = read_half.wait().await {
                if let ChannelMsg::Close = msg {
                    break;
                }
            }
        })
        .await
        .expect("the server closes the channel");
        timeout(Duration::from_secs(5), uploading)
            .await
            .unwrap_or_else(|_| {
                panic!("round {round}: the upload still waits for window on a closed channel")
            })?;

        timeout(Duration::from_secs(5), session.send_ping())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "round {round}: the session sent nothing after the server closed a channel \
                     whose window was used up"
                )
            })?;

        session
            .disconnect(Disconnect::ByApplication, "", "")
            .await?;
    }

    Ok(())
}

/// A write waiting for window fails when the connection ends, rather than waiting for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_waiting_for_window_fails_when_the_connection_ends() -> Result<(), anyhow::Error> {
    let _ = env_logger::try_init();

    let addr = start_server(WhenIdle::Disconnect).await?;
    let session = connect(addr).await?;
    let channel = session.channel_open_session().await?;

    let mut writer = channel.make_writer();
    let uploading = tokio::spawn(async move {
        let chunk = vec![0u8; 256 * 1024];
        while writer.write_all(&chunk).await.is_ok() {}
    });

    timeout(Duration::from_secs(30), uploading)
        .await
        .expect("the upload still waits for window after the connection ended")?;
    drop(channel);

    Ok(())
}

/// What the server does once a channel's upload stops coming.
#[derive(Clone, Copy, Default)]
enum WhenIdle {
    /// Close the channel.
    #[default]
    Close,
    /// End the connection.
    Disconnect,
}

async fn start_server(when_idle: WhenIdle) -> Result<SocketAddr, anyhow::Error> {
    let config = Arc::new(server::Config {
        keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
        ..Default::default()
    });
    let socket = TcpSocket::new_v4()?;
    socket.set_recv_buffer_size(SOCKET_BUFFER)?;
    socket.bind(([127, 0, 0, 1], 0).into())?;
    let socket = socket.listen(16)?;
    let addr = socket.local_addr()?;
    tokio::spawn(async move {
        Server {
            when_idle,
            adjusts: 0,
        }
        .run_on_socket(config, &socket)
        .await
    });
    Ok(addr)
}

async fn connect(addr: SocketAddr) -> Result<client::Handle<Client>, anyhow::Error> {
    let socket = TcpSocket::new_v4()?;
    socket.set_send_buffer_size(SOCKET_BUFFER)?;
    let stream = socket.connect(addr).await?;
    let config = Arc::new(client::Config::default());
    let mut session = client::connect_stream(config, stream, Client).await?;
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let auth = session
        .authenticate_publickey("user", PrivateKeyWithHashAlg::new(key, None))
        .await?;
    assert!(auth.success(), "authentication failed");
    Ok(session)
}

struct Server {
    when_idle: WhenIdle,
    adjusts: usize,
}

impl server::Server for Server {
    type Handler = Self;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        Self {
            when_idle: self.when_idle,
            adjusts: 0,
        }
    }
}

impl server::Handler for Server {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    fn adjust_window(&mut self, _: ChannelId, current: u32) -> u32 {
        self.adjusts += 1;
        if self.adjusts < ADJUSTS { current } else { 1 }
    }

    async fn channel_open_session(
        &mut self,
        mut channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let (when_idle, handle) = (self.when_idle, session.handle());
        tokio::spawn(async move {
            loop {
                match timeout(Duration::from_millis(200), channel.wait()).await {
                    Ok(Some(_)) => {}
                    Ok(None) => return,
                    Err(_) => break,
                }
            }
            match when_idle {
                WhenIdle::Close => {
                    let _ = channel.close().await;
                }
                WhenIdle::Disconnect => {
                    let _ = handle
                        .disconnect(Disconnect::ByApplication, String::new(), String::new())
                        .await;
                }
            }
        });
        Ok(())
    }
}

struct Client;

impl client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
