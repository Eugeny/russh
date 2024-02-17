use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use rand::RngCore;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{client, Channel};
use russh_keys::key;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const WINDOW_SIZE: u32 = 8 * 2048;

#[tokio::test]
async fn test_reader_and_writer() -> Result<(), anyhow::Error> {
    env_logger::init();

    let addr = addr();
    let data = data();

    tokio::spawn(Server::run(addr));

    // Wait until the server is started
    while TcpStream::connect(addr).is_err() {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    stream(addr, &data).await?;

    Ok(())
}

async fn stream(addr: SocketAddr, data: &[u8]) -> Result<(), anyhow::Error> {
    let config = Arc::new(client::Config::default());
    let key = Arc::new(russh_keys::key::KeyPair::generate_ed25519().unwrap());

    let mut session = russh::client::connect(config, addr, Client).await?;
    let mut channel = match session.authenticate_publickey("user", key).await {
        Ok(true) => session.channel_open_session().await?,
        Ok(false) => panic!("Authentication failed"),
        Err(err) => return Err(err.into()),
    };

    let mut buf = Vec::<u8>::new();
    let (mut writer, mut reader) = (channel.make_writer_ext(Some(1)), channel.make_reader());

    let (r0, r1) = tokio::join!(
        async {
            writer.write_all(data).await?;
            writer.shutdown().await?;

            Ok::<_, anyhow::Error>(())
        },
        reader.read_to_end(&mut buf)
    );

    r0?;
    let count = r1?;

    assert_eq!(data.len(), count);
    assert_eq!(data, buf);

    Ok(())
}

fn data() -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let mut data = vec![0u8; WINDOW_SIZE as usize * 2 + 7]; // Check whether the window_size resizing works
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
struct Server;

impl Server {
    async fn run(addr: SocketAddr) {
        let config = Arc::new(server::Config {
            keys: vec![russh_keys::key::KeyPair::generate_ed25519().unwrap()],
            window_size: WINDOW_SIZE,
            ..Default::default()
        });
        let mut sh = Server {};

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

    async fn auth_publickey(&mut self, _: &str, _: &key::PublicKey) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        mut channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        tokio::spawn(async move {
            let (mut writer, mut reader) =
                (channel.make_writer(), channel.make_reader_ext(Some(1)));

            tokio::io::copy(&mut reader, &mut writer)
                .await
                .expect("Data transfer failed");

            writer.shutdown().await.expect("Shutdown failed");
        });

        Ok(true)
    }
}

struct Client;

#[async_trait::async_trait]
impl russh::client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _: &key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
