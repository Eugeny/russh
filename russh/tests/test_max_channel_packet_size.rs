#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;
use std::sync::Arc;

use russh::keys::PrivateKeyWithHashAlg;
use russh::keys::ssh_key::rand_core::OsRng;
use russh::*;
use ssh_key::PrivateKey;
use tokio::io::{AsyncWrite, AsyncWriteExt};

const MAX_CHANNEL_PACKET_SIZE: u32 = 256 * 1024;
const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const STDERR_EXTENDED_DATA_TYPE: u32 = 1;

#[tokio::test]
async fn test_aes256_gcm_allows_full_256k_channel_packet() {
    let _ = env_logger::try_init();

    let client_key = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();

    let mut server_config = server::Config::default();
    server_config.inactivity_timeout = None;
    server_config.auth_rejection_time = std::time::Duration::from_secs(3);
    server_config.maximum_packet_size = MAX_CHANNEL_PACKET_SIZE;
    server_config.window_size = MAX_CHANNEL_PACKET_SIZE * 4;
    server_config
        .keys
        .push(PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap());
    server_config.preferred = {
        let mut preferred = Preferred::default();
        preferred.cipher = Cow::Borrowed(&[cipher::AES_256_GCM]);
        preferred
    };

    let server_config = Arc::new(server_config);
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let (socket, _) = socket.accept().await.unwrap();
        server::run_stream(server_config, socket, EchoServer {})
            .await
            .unwrap();
    });

    let mut client_config = client::Config::default();
    client_config.maximum_packet_size = MAX_CHANNEL_PACKET_SIZE;
    client_config.window_size = MAX_CHANNEL_PACKET_SIZE * 4;
    client_config.preferred = {
        let mut preferred = Preferred::default();
        preferred.cipher = Cow::Borrowed(&[cipher::AES_256_GCM]);
        preferred
    };

    let mut session = client::connect(Arc::new(client_config), addr, TestClient {})
        .await
        .unwrap();

    let authenticated = session
        .authenticate_publickey(
            std::env::var("USER").unwrap_or("user".to_owned()),
            PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
        )
        .await
        .unwrap()
        .success();
    assert!(authenticated);

    let payload = vec![0x5a; MAX_CHANNEL_PACKET_SIZE as usize];
    let mut channel = session.channel_open_session().await.unwrap();
    write_and_expect_echo(
        channel.make_writer(),
        &mut channel,
        &payload,
        |msg| match msg {
            ChannelMsg::Data { data } => Some(data),
            other => panic!("Unexpected message while waiting for echoed payload: {other:?}"),
        },
    )
    .await;

    write_and_expect_echo(
        channel.make_writer_ext(Some(STDERR_EXTENDED_DATA_TYPE)),
        &mut channel,
        &payload,
        |msg| match msg {
            ChannelMsg::ExtendedData { data, ext } if ext == STDERR_EXTENDED_DATA_TYPE => {
                Some(data)
            }
            other => {
                panic!("Unexpected message while waiting for echoed extended payload: {other:?}")
            }
        },
    )
    .await;

    channel.eof().await.unwrap();
    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}

async fn write_and_expect_echo<W, F>(
    mut writer: W,
    channel: &mut Channel<client::Msg>,
    payload: &[u8],
    mut extract_data: F,
) where
    W: AsyncWrite + Unpin,
    F: FnMut(ChannelMsg) -> Option<bytes::Bytes>,
{
    writer.write_all(payload).await.unwrap();
    writer.flush().await.unwrap();

    let echoed = tokio::time::timeout(TEST_TIMEOUT, async {
        let mut echoed = Vec::with_capacity(payload.len());
        while echoed.len() < payload.len() {
            match channel.wait().await {
                Some(ChannelMsg::WindowAdjusted { .. }) => {}
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) => {
                    panic!("channel closed before echoing a full 256 KiB packet")
                }
                Some(msg) => {
                    if let Some(data) = extract_data(msg) {
                        echoed.extend_from_slice(&data);
                    }
                }
                None => panic!("channel closed before echoing a full 256 KiB packet"),
            }
        }
        echoed
    })
    .await
    .expect("timed out waiting for echoed payload");

    assert_eq!(echoed, payload);
}

#[derive(Clone)]
struct EchoServer {}

impl server::Handler for EchoServer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _public_key: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<server::Msg>,
        _session: &mut server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.data(channel, bytes::Bytes::copy_from_slice(data))?;
        Ok(())
    }

    async fn extended_data(
        &mut self,
        channel: ChannelId,
        ext: u32,
        data: &[u8],
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        session.extended_data(channel, ext, bytes::Bytes::copy_from_slice(data))?;
        Ok(())
    }
}

struct TestClient {}

impl client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}
