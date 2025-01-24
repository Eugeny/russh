use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use futures::FutureExt;
use rand::RngCore;
use rand_core::OsRng;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{client, Channel, ChannelMsg};
use ssh_key::PrivateKey;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use tokio::time::sleep;

pub const WINDOW_SIZE: usize = 8 * 2048;
pub const CHANNEL_BUFFER_SIZE: usize = 10;

#[tokio::test]
async fn test_backpressure() -> Result<(), anyhow::Error> {
    env_logger::init();

    let addr = addr();
    let data = data();
    let (tx, rx) = watch::channel(());

    tokio::spawn(Server::run(addr, rx));

    // Wait until the server is started
    while TcpStream::connect(addr).is_err() {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    stream(addr, &data, tx).await?;

    Ok(())
}

async fn stream(addr: SocketAddr, data: &[u8], tx: watch::Sender<()>) -> Result<(), anyhow::Error> {
    let config = Arc::new(client::Config::default());
    let key = Arc::new(PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap());

    let mut session = russh::client::connect(config, addr, Client).await?;
    let channel = match session
        .authenticate_publickey("user", key)
        .await
        .map(|x| x.success())
    {
        Ok(true) => session.channel_open_session().await?,
        Ok(false) => panic!("Authentication failed"),
        Err(err) => return Err(err.into()),
    };

    let mut writer = channel.make_writer();

    // TCP listener will buffer one extra message
    for _ in 0..=CHANNEL_BUFFER_SIZE {
        assert!(writer.write(data).await.is_ok());
    }
    let pending_write = async { writer.write(data).await.unwrap() };
    sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(pending_write.now_or_never(), None);
    // Make space on the buffer
    tx.send(()).unwrap();
    assert!(writer.write(data).await.is_ok());

    Ok(())
}

fn data() -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let mut data = vec![0u8; WINDOW_SIZE]; // Check whether the window_size resizing works
    rng.fill_bytes(&mut data);

    data
}

/// Find a unused local address to bind our server to
fn addr() -> SocketAddr {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

#[derive(Clone)]
struct Server {
    rx: Option<watch::Receiver<()>>,
}

impl Server {
    async fn run(addr: SocketAddr, rx: watch::Receiver<()>) {
        let config = Arc::new(server::Config {
            keys: vec![PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap()],
            window_size: WINDOW_SIZE as u32,
            channel_buffer_size: CHANNEL_BUFFER_SIZE,
            ..Default::default()
        });
        let mut sh = Server { rx: Some(rx) };

        sh.run_on_address(config, addr).await.unwrap();
    }
}

impl russh::server::Server for Server {
    type Handler = Self;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        self.clone()
    }
}

#[async_trait::async_trait]
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
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let mut rx = self.rx.take().unwrap();
        tokio::spawn(async move {
            while let Ok(_) = rx.changed().await {
                match channel.wait().await {
                    Some(ChannelMsg::Data { .. }) => (),
                    other => panic!("unexpected message {:?}", other),
                }
            }
        });

        Ok(true)
    }
}

struct Client;

#[async_trait::async_trait]
impl russh::client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
