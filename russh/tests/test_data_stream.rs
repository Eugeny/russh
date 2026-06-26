mod common;

use std::net::SocketAddr;

use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelMsg, client};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const WINDOW_SIZE: u32 = 8 * 2048;

trait ChannelDataCopy {
    async fn copy_data_through_channel(
        &mut self,
        channel: Channel<client::Msg>,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>>;
}

struct ReaderAndWriter;

impl ChannelDataCopy for ReaderAndWriter {
    async fn copy_data_through_channel(
        &mut self,
        mut channel: Channel<client::Msg>,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::<u8>::new();
        let mut writer = channel.make_writer_ext(Some(1));
        let mut reader = channel.make_reader();

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

        Ok(buf)
    }
}

struct ChannelHalves;

impl ChannelDataCopy for ChannelHalves {
    async fn copy_data_through_channel(
        &mut self,
        channel: Channel<client::Msg>,
        data: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let (mut read, write) = channel.split();
        let (r0, r1) = tokio::join!(
            async {
                write.extended_data(1, data).await?;
                write.eof().await?;

                Ok::<_, anyhow::Error>(())
            },
            async {
                let mut buf = Vec::<u8>::new();
                while let Some(msg) = read.wait().await {
                    match msg {
                        ChannelMsg::WindowAdjusted { .. } => {}
                        ChannelMsg::Data { data } => buf.extend(&*data),
                        ChannelMsg::Eof | ChannelMsg::Close => break,
                        msg => panic!("Got unexpected message: {msg:?}"),
                    }
                }
                Ok(buf)
            }
        );

        r0?;
        r1
    }
}

#[tokio::test]
async fn test_reader_and_writer() -> Result<(), anyhow::Error> {
    run_test(ReaderAndWriter).await
}

#[tokio::test]
async fn test_channel_halves() -> Result<(), anyhow::Error> {
    run_test(ChannelHalves).await
}

async fn run_test(mut test: impl ChannelDataCopy) -> Result<(), anyhow::Error> {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(env_logger::init);

    let addr = common::addr();
    let data = data();

    tokio::spawn(Server::run(addr));
    common::wait_for_server(addr).await;

    let session = common::connect(addr).await?;
    let channel = session.channel_open_session().await?;

    let buf = test
        .copy_data_through_channel(channel, data.as_slice())
        .await?;
    assert_eq!(data, buf);

    Ok(())
}

fn data() -> Vec<u8> {
    let mut data = vec![0u8; WINDOW_SIZE as usize * 2 + 7]; // Check whether the window_size resizing works
    use rand::RngExt;
    rand::rng().fill(&mut data[..]);
    data
}

#[derive(Clone)]
struct Server;

impl Server {
    async fn run(addr: SocketAddr) {
        let config =
            common::server_config(WINDOW_SIZE, server::Config::default().channel_buffer_size);
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
        reply.accept().await;
        tokio::spawn(async move {
            let (mut writer, mut reader) =
                (channel.make_writer(), channel.make_reader_ext(Some(1)));

            tokio::io::copy(&mut reader, &mut writer)
                .await
                .expect("Data transfer failed");

            writer.shutdown().await.expect("Shutdown failed");
        });

        Ok(())
    }
}
