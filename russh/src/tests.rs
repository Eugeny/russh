#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Allow unwraps, expects and panics in the test suite

use futures::Future;

use super::*;

mod compress {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use log::debug;

    use super::server::{Server as _, Session};
    use super::*;
    use crate::server::Msg;

    #[tokio::test]
    async fn compress_local_test() {
        let _ = env_logger::try_init();

        let client_key = russh_keys::key::KeyPair::generate_ed25519().unwrap();
        let mut config = server::Config::default();
        config.preferred = Preferred::COMPRESSED;
        config.inactivity_timeout = None; // Some(std::time::Duration::from_secs(3));
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config
            .keys
            .push(russh_keys::key::KeyPair::generate_ed25519().unwrap());
        let config = Arc::new(config);
        let mut sh = Server {
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
        };

        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let (socket, _) = socket.accept().await.unwrap();
            let server = sh.new_client(socket.peer_addr().ok());
            server::run_stream(config, socket, server).await.unwrap();
        });

        let mut config = client::Config::default();
        config.preferred = Preferred::COMPRESSED;
        let config = Arc::new(config);

        dbg!(&addr);
        let mut session = client::connect(config, addr, Client {}).await.unwrap();
        let authenticated = session
            .authenticate_publickey(
                std::env::var("USER").unwrap_or("user".to_owned()),
                Arc::new(client_key),
            )
            .await
            .unwrap();
        assert!(authenticated);
        let mut channel = session.channel_open_session().await.unwrap();

        let data = &b"Hello, world!"[..];
        channel.data(data).await.unwrap();
        let msg = channel.wait().await.unwrap();
        match msg {
            ChannelMsg::Data { data: msg_data } => {
                assert_eq!(*data, *msg_data)
            }
            msg => panic!("Unexpected message {:?}", msg),
        }
    }

    #[derive(Clone)]
    struct Server {
        clients: Arc<Mutex<HashMap<(usize, ChannelId), super::server::Handle>>>,
        id: usize,
    }

    impl server::Server for Server {
        type Handler = Self;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            let s = self.clone();
            self.id += 1;
            s
        }
    }

    #[async_trait]
    impl server::Handler for Server {
        type Error = super::Error;

        async fn channel_open_session(
            &mut self,
            channel: Channel<Msg>,
            session: &mut Session,
        ) -> Result<bool, Self::Error> {
            {
                let mut clients = self.clients.lock().unwrap();
                clients.insert((self.id, channel.id()), session.handle());
            }
            Ok(true)
        }
        async fn auth_publickey(
            &mut self,
            _: &str,
            _: &russh_keys::key::PublicKey,
        ) -> Result<server::Auth, Self::Error> {
            debug!("auth_publickey");
            Ok(server::Auth::Accept)
        }
        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            debug!("server data = {:?}", std::str::from_utf8(data));
            session.data(channel, CryptoVec::from_slice(data));
            Ok(())
        }
    }

    struct Client {}

    #[async_trait]
    impl client::Handler for Client {
        type Error = super::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &russh_keys::key::PublicKey,
        ) -> Result<bool, Self::Error> {
            // println!("check_server_key: {:?}", server_public_key);
            Ok(true)
        }
    }
}

mod channels {
    use async_trait::async_trait;
    use russh_cryptovec::CryptoVec;
    use server::Session;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

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

        let client_key = russh_keys::key::KeyPair::generate_ed25519().unwrap();
        let mut config = server::Config::default();
        config.inactivity_timeout = None;
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config
            .keys
            .push(russh_keys::key::KeyPair::generate_ed25519().unwrap());
        let config = Arc::new(config);
        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        #[derive(Clone)]
        struct Server {}

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
                    Arc::new(client_key),
                )
                .await
                .unwrap();
            assert!(authenticated);
            session
        });

        let (server_session, client_session) = tokio::join!(server_join, client_join);
        let client_handle = tokio::spawn(run_client(client_session.unwrap()));
        let server_handle = tokio::spawn(run_server(server_session.unwrap().handle()));

        let (server_session, client_session) = tokio::join!(server_handle, client_handle);
        drop(client_session);
        drop(server_session);
    }

    #[tokio::test]
    async fn test_server_channels() {
        #[derive(Debug)]
        struct Client {}

        #[async_trait]
        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &russh_keys::key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }

            async fn data(
                &mut self,
                channel: ChannelId,
                data: &[u8],
                session: &mut client::Session,
            ) -> Result<(), Self::Error> {
                assert_eq!(data, &b"hello world!"[..]);
                session.data(channel, CryptoVec::from_slice(&b"hey there!"[..]));
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

        #[async_trait]
        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &russh_keys::key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
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

        #[async_trait]
        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &russh_keys::key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {
            channel: Option<tokio::sync::oneshot::Sender<Channel<server::Msg>>>,
        }

        impl ServerHandle {
            fn get_channel_waiter(
                &mut self,
            ) -> tokio::sync::oneshot::Receiver<Channel<server::Msg>> {
                let (tx, rx) = tokio::sync::oneshot::channel::<Channel<server::Msg>>();
                self.channel = Some(tx);
                rx
            }
        }

        #[async_trait]
        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &russh_keys::key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn channel_open_session(
                &mut self,
                channel: Channel<server::Msg>,
                _session: &mut server::Session,
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

        #[async_trait]
        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &russh_keys::key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {}

        impl ServerHandle {}

        #[async_trait]
        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &russh_keys::key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn channel_open_session(
                &mut self,
                mut channel: Channel<server::Msg>,
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
                    assert_eq!(data.as_ref(), &b"hey there!"[..]);
                } else {
                    panic!("Unexpected message {:?}", msg);
                }

                let msg = ch.wait().await.unwrap();
                let ChannelMsg::Close = msg else {
                    panic!("Unexpected message {:?}", msg);
                };

                ch.close().await.unwrap();
                c
            },
            |s| async move { s },
        )
        .await;
    }
}
