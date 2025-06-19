use std::future::Future;

use crate::keys::PrivateKeyWithHashAlg;
use crate::server::Session;
use rand_core::OsRng;
use ssh_key::PrivateKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{Channel, ChannelId, ChannelMsg, CryptoVec};

async fn test_session<RC, RS, CH, SH, F1, F2>(
    client_handler: CH,
    server_handler: SH,
    run_client: RC,
    run_server: RS,
) where
    RC: FnOnce(crate::client::Handle<CH>) -> F1 + Send + Sync + 'static,
    RS: FnOnce(crate::server::Handle) -> F2 + Send + Sync + 'static,
    F1: Future<Output = crate::client::Handle<CH>> + Send + Sync + 'static,
    F2: Future<Output = crate::server::Handle> + Send + Sync + 'static,
    CH: crate::client::Handler + Send + Sync + 'static,
    SH: crate::server::Handler + Send + Sync + 'static,
{
    use std::sync::Arc;

    use crate::*;

    let _ = env_logger::try_init();

    let client_key = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let mut config = server::Config::default();
    config.inactivity_timeout = None;
    config.auth_rejection_time = std::time::Duration::from_secs(3);
    config
        .keys
        .push(PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap());
    let config = Arc::new(config);
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    let server_join = tokio::spawn(async move {
        let (socket, _) = socket.accept().await.unwrap();

        server::run_stream(config, socket, server_handler)
            .await
            .map_err(|_| ())
            .unwrap()
    });

    let client_join = tokio::spawn(async move {
        let config = Arc::new(client::Config::default());
        let mut session = client::connect(config, addr, client_handler)
            .await
            .map_err(|_| ())
            .unwrap();
        let authenticated = session
            .authenticate_publickey(
                std::env::var("USER").unwrap_or("user".to_owned()),
                PrivateKeyWithHashAlg::new(Arc::new(client_key), None),
            )
            .await
            .unwrap();
        assert!(authenticated.success());
        session
    });

    let (server_session, client_session) = tokio::join!(server_join, client_join);
    let client_handle = tokio::spawn(run_client(client_session.unwrap()));
    let server_handle = tokio::spawn(run_server(server_session.unwrap().handle()));

    let (server_session, client_session) = tokio::join!(server_handle, client_handle);
    assert!(server_session.is_ok());
    assert!(client_session.is_ok());
    drop(client_session);
    drop(server_session);
}

#[tokio::test]
async fn test_server_channels() {
    #[derive(Debug)]
    struct Client {}

    impl crate::client::Handler for Client {
        type Error = crate::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &crate::keys::ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }

        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut crate::client::Session,
        ) -> Result<(), Self::Error> {
            assert_eq!(data, &b"hello world!"[..]);
            session.data(channel, CryptoVec::from_slice(&b"hey there!"[..]))?;
            Ok(())
        }
    }

    struct ServerHandle {
        did_auth: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl ServerHandle {
        fn get_auth_waiter(&mut self) -> tokio::sync::oneshot::Receiver<()> {
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.did_auth = Some(tx);
            rx
        }
    }

    impl crate::server::Handler for ServerHandle {
        type Error = crate::Error;

        async fn auth_publickey(
            &mut self,
            _: &str,
            _: &crate::keys::ssh_key::PublicKey,
        ) -> Result<crate::server::Auth, Self::Error> {
            Ok(crate::server::Auth::Accept)
        }
        async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
            if let Some(a) = self.did_auth.take() {
                a.send(()).unwrap();
            }
            Ok(())
        }
    }

    let mut sh = ServerHandle { did_auth: None };
    let a = sh.get_auth_waiter();
    test_session(
        Client {},
        sh,
        |c| async move { c },
        |s| async move {
            a.await.unwrap();
            let mut ch = s.channel_open_session().await.unwrap();
            ch.data(&b"hello world!"[..]).await.unwrap();

            let msg = ch.wait().await.unwrap();
            if let ChannelMsg::Data { data } = msg {
                assert_eq!(data.as_ref(), &b"hey there!"[..]);
            } else {
                panic!("Unexpected message {:?}", msg);
            }
            s
        },
    )
    .await;
}

#[tokio::test]
async fn test_channel_streams() {
    #[derive(Debug)]
    struct Client {}

    impl crate::client::Handler for Client {
        type Error = crate::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &crate::keys::ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    struct ServerHandle {
        channel: Option<tokio::sync::oneshot::Sender<Channel<crate::server::Msg>>>,
    }

    impl ServerHandle {
        fn get_channel_waiter(
            &mut self,
        ) -> tokio::sync::oneshot::Receiver<Channel<crate::server::Msg>> {
            let (tx, rx) = tokio::sync::oneshot::channel::<Channel<crate::server::Msg>>();
            self.channel = Some(tx);
            rx
        }
    }

    impl crate::server::Handler for ServerHandle {
        type Error = crate::Error;

        async fn auth_publickey(
            &mut self,
            _: &str,
            _: &crate::keys::ssh_key::PublicKey,
        ) -> Result<crate::server::Auth, Self::Error> {
            Ok(crate::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            channel: Channel<crate::server::Msg>,
            _session: &mut crate::server::Session,
        ) -> Result<bool, Self::Error> {
            if let Some(a) = self.channel.take() {
                println!("channel open session {:?}", a);
                a.send(channel).unwrap();
            }
            Ok(true)
        }
    }

    let mut sh = ServerHandle { channel: None };
    let scw = sh.get_channel_waiter();

    test_session(
        Client {},
        sh,
        |client| async move {
            let ch = client.channel_open_session().await.unwrap();
            let mut stream = ch.into_stream();
            stream.write_all(&b"request"[..]).await.unwrap();

            let mut buf = Vec::new();
            stream.read_buf(&mut buf).await.unwrap();
            assert_eq!(&buf, &b"response"[..]);

            stream.write_all(&b"reply"[..]).await.unwrap();

            client
        },
        |server| async move {
            let channel = scw.await.unwrap();
            let mut stream = channel.into_stream();

            let mut buf = Vec::new();
            stream.read_buf(&mut buf).await.unwrap();
            assert_eq!(&buf, &b"request"[..]);

            stream.write_all(&b"response"[..]).await.unwrap();

            buf.clear();

            stream.read_buf(&mut buf).await.unwrap();
            assert_eq!(&buf, &b"reply"[..]);

            server
        },
    )
    .await;
}

#[tokio::test]
async fn test_channel_objects() {
    #[derive(Debug)]
    struct Client {}

    impl crate::client::Handler for Client {
        type Error = crate::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &crate::keys::ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    struct ServerHandle {}

    impl ServerHandle {}

    impl crate::server::Handler for ServerHandle {
        type Error = crate::Error;

        async fn auth_publickey(
            &mut self,
            _: &str,
            _: &crate::keys::ssh_key::PublicKey,
        ) -> Result<crate::server::Auth, Self::Error> {
            Ok(crate::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            mut channel: Channel<crate::server::Msg>,
            _session: &mut Session,
        ) -> Result<bool, Self::Error> {
            tokio::spawn(async move {
                while let Some(msg) = channel.wait().await {
                    match msg {
                        ChannelMsg::Data { data } => {
                            channel.data(&data[..]).await.unwrap();
                            channel.close().await.unwrap();
                            break;
                        }
                        _ => {}
                    }
                }
            });
            Ok(true)
        }
    }

    let sh = ServerHandle {};
    test_session(
        Client {},
        sh,
        |c| async move {
            let mut ch = c.channel_open_session().await.unwrap();
            ch.data(&b"hello world!"[..]).await.unwrap();

            let msg = ch.wait().await.unwrap();
            if let ChannelMsg::Data { data } = msg {
                assert_eq!(data.as_ref(), &b"hello world!"[..]);
            } else {
                panic!("Unexpected message {:?}", msg);
            }

            assert!(ch.wait().await.is_none());
            c
        },
        |s| async move { s },
    )
    .await;
}

#[tokio::test]
async fn test_channel_window_size() {
    #[derive(Debug)]
    struct Client {}

    impl crate::client::Handler for Client {
        type Error = crate::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &crate::keys::ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    struct ServerHandle {
        channel: Option<tokio::sync::oneshot::Sender<Channel<crate::server::Msg>>>,
    }

    impl ServerHandle {
        fn get_channel_waiter(
            &mut self,
        ) -> tokio::sync::oneshot::Receiver<Channel<crate::server::Msg>> {
            let (tx, rx) = tokio::sync::oneshot::channel::<Channel<crate::server::Msg>>();
            self.channel = Some(tx);
            rx
        }
    }

    impl crate::server::Handler for ServerHandle {
        type Error = crate::Error;

        async fn auth_publickey(
            &mut self,
            _: &str,
            _: &crate::keys::ssh_key::PublicKey,
        ) -> Result<crate::server::Auth, Self::Error> {
            Ok(crate::server::Auth::Accept)
        }

        async fn channel_open_session(
            &mut self,
            channel: Channel<crate::server::Msg>,
            _session: &mut crate::server::Session,
        ) -> Result<bool, Self::Error> {
            if let Some(a) = self.channel.take() {
                println!("channel open session {:?}", a);
                a.send(channel).unwrap();
            }
            Ok(true)
        }
    }

    let mut sh = ServerHandle { channel: None };
    let scw = sh.get_channel_waiter();

    test_session(
        Client {},
        sh,
        |client| async move {
            let ch = client.channel_open_session().await.unwrap();

            let mut writer_1 = ch.make_writer();
            let jh_1 = tokio::spawn(async move {
                let buf = [1u8; 1024 * 64];
                assert!(writer_1.write_all(&buf).await.is_ok());
            });
            let mut writer_2 = ch.make_writer();
            let jh_2 = tokio::spawn(async move {
                let buf = [2u8; 1024 * 64];
                assert!(writer_2.write_all(&buf).await.is_ok());
            });

            assert!(tokio::try_join!(jh_1, jh_2).is_ok());

            client
        },
        |server| async move {
            let mut channel = scw.await.unwrap();

            let mut total_data = 2 * 1024 * 64;
            while let Some(msg) = channel.wait().await {
                match msg {
                    ChannelMsg::Data { data } => {
                        total_data -= data.len();
                        if total_data == 0 {
                            break;
                        }
                    }
                    _ => panic!("Unexpected message {:?}", msg),
                }
            }

            server
        },
    )
    .await;
}
