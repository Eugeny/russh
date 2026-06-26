mod common;

use std::net::SocketAddr;

use futures::FutureExt;
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelMsg};
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use tokio::time::sleep;

pub const WINDOW_SIZE: usize = 8 * 2048;
pub const CHANNEL_BUFFER_SIZE: usize = 10;

#[tokio::test]
async fn test_backpressure() -> Result<(), anyhow::Error> {
    env_logger::init();

    let addr = common::addr();
    let data = data();
    let (tx, rx) = watch::channel(());

    tokio::spawn(Server::run(addr, rx));
    common::wait_for_server(addr).await;

    let session = common::connect(addr).await?;
    let channel = session.channel_open_session().await?;
    let mut writer = channel.make_writer();

    // TCP listener will buffer one extra message
    for _ in 0..=CHANNEL_BUFFER_SIZE {
        assert!(writer.write(&data).await.is_ok());
    }
    let pending_write = async { writer.write(&data).await.unwrap() };
    sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(pending_write.now_or_never(), None);
    // Make space on the buffer
    tx.send(()).unwrap();
    assert!(writer.write(&data).await.is_ok());

    Ok(())
}

fn data() -> Vec<u8> {
    let mut data = vec![0u8; WINDOW_SIZE]; // Check whether the window_size resizing works
    use rand::RngExt;
    rand::rng().fill(&mut data[..]);
    data
}

#[derive(Clone)]
struct Server {
    rx: Option<watch::Receiver<()>>,
}

impl Server {
    async fn run(addr: SocketAddr, rx: watch::Receiver<()>) {
        let config = common::server_config(WINDOW_SIZE as u32, CHANNEL_BUFFER_SIZE);
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
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut rx = self.rx.take().unwrap();
        reply.accept().await;
        tokio::spawn(async move {
            while let Ok(_) = rx.changed().await {
                match channel.wait().await {
                    Some(ChannelMsg::Data { .. }) => (),
                    Some(ChannelMsg::Close) | None => break,
                    other => panic!("unexpected message {other:?}"),
                }
            }
        });

        Ok(())
    }
}
