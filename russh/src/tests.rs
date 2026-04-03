#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Allow unwraps, expects and panics in the test suite

use futures::Future;

use super::*;

mod compress {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use keys::PrivateKeyWithHashAlg;
    use log::debug;
    use ssh_key::PrivateKey;

    use super::server::{Server as _, Session};
    use super::*;
    use crate::server::Msg;

    #[tokio::test]
    async fn compress_local_test() {
        let _ = env_logger::try_init();

        let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let mut config = server::Config::default();
        config.preferred = Preferred::COMPRESSED;
        config.inactivity_timeout = None; // Some(std::time::Duration::from_secs(3));
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config
            .keys
            .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
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

        let mut session = client::connect(config, addr, Client {}).await.unwrap();
        let authenticated = session
            .authenticate_publickey(
                std::env::var("USER").unwrap_or("user".to_owned()),
                PrivateKeyWithHashAlg::new(
                    Arc::new(client_key),
                    session.best_supported_rsa_hash().await.unwrap().flatten(),
                ),
            )
            .await
            .unwrap()
            .success();
        assert!(authenticated);
        let mut channel = session.channel_open_session().await.unwrap();

        let data = &b"Hello, world!"[..];
        channel.data(data).await.unwrap();
        let msg = channel.wait().await.unwrap();
        match msg {
            ChannelMsg::Data { data: msg_data } => {
                assert_eq!(*data, *msg_data)
            }
            msg => panic!("Unexpected message {msg:?}"),
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
            _: &crate::keys::ssh_key::PublicKey,
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
            session.data(channel, data.to_vec())?;
            Ok(())
        }
    }

    struct Client {}

    impl client::Handler for Client {
        type Error = super::Error;

        async fn check_server_key(
            &mut self,
            _server_public_key: &crate::keys::ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            // println!("check_server_key: {:?}", server_public_key);
            Ok(true)
        }
    }
}

mod channels {
    use keys::PrivateKeyWithHashAlg;
    use server::Session;
    use ssh_key::PrivateKey;
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

        let client_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let mut config = server::Config::default();
        config.inactivity_timeout = None;
        config.auth_rejection_time = std::time::Duration::from_secs(3);
        config
            .keys
            .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
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

        impl client::Handler for Client {
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
                session: &mut client::Session,
            ) -> Result<(), Self::Error> {
                assert_eq!(data, &b"hello world!"[..]);
                session.data(channel, b"hey there!".to_vec())?;
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

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &crate::keys::ssh_key::PublicKey,
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
                    assert_eq!(&data[..], &b"hey there!"[..]);
                } else {
                    panic!("Unexpected message {msg:?}");
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

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &crate::keys::ssh_key::PublicKey,
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

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &crate::keys::ssh_key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn channel_open_session(
                &mut self,
                channel: Channel<server::Msg>,
                _session: &mut server::Session,
            ) -> Result<bool, Self::Error> {
                if let Some(a) = self.channel.take() {
                    println!("channel open session {a:?}");
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

        impl client::Handler for Client {
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

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &crate::keys::ssh_key::PublicKey,
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
                    assert_eq!(&data[..], &b"hello world!"[..]);
                } else {
                    panic!("Unexpected message {msg:?}");
                }

                // After the server closes the channel, we should receive an
                // explicit Close message before the channel stream ends.
                let msg = ch.wait().await.unwrap();
                assert!(
                    matches!(msg, ChannelMsg::Close),
                    "expected Close, got {msg:?}"
                );
                assert!(ch.wait().await.is_none());
                c
            },
            |s| async move { s },
        )
        .await;
    }

    /// Verify that the server-side CHANNEL_CLOSE handler delivers
    /// `ChannelMsg::Close` before the channel stream ends.
    #[tokio::test]
    async fn test_server_receives_close_on_client_close() {
        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &crate::keys::ssh_key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        struct ServerHandle {
            channel: Option<tokio::sync::oneshot::Sender<Channel<server::Msg>>>,
        }

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &crate::keys::ssh_key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn channel_open_session(
                &mut self,
                channel: Channel<server::Msg>,
                _session: &mut server::Session,
            ) -> Result<bool, Self::Error> {
                if let Some(tx) = self.channel.take() {
                    tx.send(channel).unwrap();
                }
                Ok(true)
            }
        }

        let (tx, rx) = tokio::sync::oneshot::channel::<Channel<server::Msg>>();
        let sh = ServerHandle { channel: Some(tx) };

        test_session(
            Client {},
            sh,
            |c| async move {
                let ch = c.channel_open_session().await.unwrap();
                ch.close().await.unwrap();
                c
            },
            |s| async move {
                let mut ch = rx.await.unwrap();
                // The server should receive an explicit Close message
                // when the client closes the channel.
                let msg = ch.wait().await.unwrap();
                assert!(
                    matches!(msg, ChannelMsg::Close),
                    "expected Close, got {msg:?}"
                );
                assert!(ch.wait().await.is_none());
                s
            },
        )
        .await;
    }

    #[tokio::test]
    async fn test_channel_window_size() {
        #[derive(Debug)]
        struct Client {}

        impl client::Handler for Client {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &crate::keys::ssh_key::PublicKey,
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

        impl server::Handler for ServerHandle {
            type Error = crate::Error;

            async fn auth_publickey(
                &mut self,
                _: &str,
                _: &crate::keys::ssh_key::PublicKey,
            ) -> Result<server::Auth, Self::Error> {
                Ok(server::Auth::Accept)
            }

            async fn channel_open_session(
                &mut self,
                channel: Channel<server::Msg>,
                _session: &mut server::Session,
            ) -> Result<bool, Self::Error> {
                if let Some(a) = self.channel.take() {
                    println!("channel open session {a:?}");
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
                        _ => panic!("Unexpected message {msg:?}"),
                    }
                }

                server
            },
        )
        .await;
    }
}

mod gex {
    use super::*;

    #[test]
    fn peer_request_accepts_rfc4419_minimum_when_server_can_choose_stronger_group() {
        let params = client::GexParams::from_peer_request(1024, 4097, 8192).unwrap();

        assert_eq!(params.min_group_size(), 1024);
        assert_eq!(params.preferred_group_size(), 4097);
        assert_eq!(params.max_group_size(), 8192);
    }

    #[test]
    fn local_client_config_still_rejects_minimum_below_2048() {
        let error = client::GexParams::for_client_config(1024, 4097, 8192).unwrap_err();

        assert!(matches!(error, Error::InvalidConfig(_)));
    }
}

mod server_kex_junk {
    use std::sync::Arc;

    use tokio::io::AsyncWriteExt;

    use super::server::Server as _;
    use super::*;

    #[tokio::test]
    async fn server_kex_junk_test() {
        let _ = env_logger::try_init();

        let config = server::Config::default();
        let config = Arc::new(config);
        let mut sh = Server {};

        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut client_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            client_stream
                .write_all(b"SSH-2.0-Client_1.0\r\n")
                .await
                .unwrap();
            // Unexpected message pre-kex
            client_stream.write_all(&[0, 0, 0, 2, 0, 99]).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        });

        let (socket, _) = socket.accept().await.unwrap();
        let server = sh.new_client(socket.peer_addr().ok());
        let rs = server::run_stream(config, socket, server).await.unwrap();

        // May not panic
        assert!(rs.await.is_err());
    }

    #[derive(Clone)]
    struct Server {}

    impl server::Server for Server {
        type Handler = Self;
        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            self.clone()
        }
    }

    impl server::Handler for Server {
        type Error = super::Error;
    }
}

/// Integration test for FutureCertificate authentication flow
#[cfg(unix)]
mod future_certificate {
    use std::io::Write;
    use std::process::Stdio;
    use std::sync::Arc;

    use ssh_key::{certificate, PrivateKey};

    use crate::keys::agent::client::AgentClient;
    use crate::{client, server};
    use crate::server::Session;

    /// Helper to spawn an ssh-agent
    async fn spawn_agent() -> (
        tokio::process::Child,
        std::path::PathBuf,
        tempfile::TempDir,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let agent_path = dir.path().join("agent");
        let agent = tokio::process::Command::new("ssh-agent")
            .arg("-a")
            .arg(&agent_path)
            .arg("-D")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        // Wait for the socket to be created
        while agent_path.canonicalize().is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        (agent, agent_path, dir)
    }

    /// Helper to create a test certificate
    fn create_test_cert(ca_key: &PrivateKey, user_key: &PrivateKey) -> ssh_key::Certificate {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let valid_after = now - 3600;
        let valid_before = now + 86400 * 365;

        let mut builder = certificate::Builder::new_with_random_nonce(
            &mut rand::rng(),
            user_key.public_key(),
            valid_after,
            valid_before,
        )
        .unwrap();

        builder.serial(1).unwrap();
        builder.key_id("test-user-cert").unwrap();
        builder.cert_type(certificate::CertType::User).unwrap();
        builder.valid_principal("testuser").unwrap();
        builder.sign(ca_key).unwrap()
    }

    #[tokio::test]
    async fn test_future_certificate_auth_full_flow() {
        let _ = env_logger::try_init();

        // 1. Spawn ssh-agent
        let (mut agent, agent_path, dir) = spawn_agent().await;

        // 2. Create CA key and user key
        let ca_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let user_key = PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();

        // 3. Create a certificate
        let cert = create_test_cert(&ca_key, &user_key);

        // 4. Write keys and certificate to temp files and add to agent
        let user_key_path = dir.path().join("user_key");
        let cert_path = dir.path().join("user_key-cert.pub");

        let mut f = std::fs::File::create(&user_key_path).unwrap();
        f.write_all(
            user_key
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(
            &user_key_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();

        let mut f = std::fs::File::create(&cert_path).unwrap();
        f.write_all(cert.to_openssh().unwrap().as_bytes()).unwrap();

        let status = tokio::process::Command::new("ssh-add")
            .arg(&user_key_path)
            .env("SSH_AUTH_SOCK", &agent_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .unwrap();
        assert!(status.success(), "ssh-add failed");

        // 5. Set up test server that accepts certificate auth
        let mut server_config = server::Config::default();
        server_config.inactivity_timeout = None;
        server_config.auth_rejection_time = std::time::Duration::from_secs(3);
        server_config
            .keys
            .push(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
        let server_config = Arc::new(server_config);

        let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        // Server that accepts certificate auth
        let server_join = tokio::spawn(async move {
            let (socket, _) = socket.accept().await.unwrap();

            struct CertHandler;

            impl server::Handler for CertHandler {
                type Error = crate::Error;

                async fn auth_publickey_offered(
                    &mut self,
                    _user: &str,
                    _public_key: &ssh_key::PublicKey,
                ) -> Result<server::Auth, Self::Error> {
                    // Accept the key/certificate for the probe
                    Ok(server::Auth::Accept)
                }

                async fn auth_openssh_certificate(
                    &mut self,
                    _user: &str,
                    cert: &ssh_key::Certificate,
                ) -> Result<server::Auth, Self::Error> {
                    // Validate the certificate is signed by our CA
                    // In a real server, you'd properly verify the CA signature
                    // For this test, just check the key_id matches
                    if cert.key_id() == "test-user-cert" {
                        Ok(server::Auth::Accept)
                    } else {
                        Ok(server::Auth::Reject { proceed_with_methods: None, partial_success: false })
                    }
                }

                async fn channel_open_session(
                    &mut self,
                    channel: crate::Channel<server::Msg>,
                    _session: &mut Session,
                ) -> Result<bool, Self::Error> {
                    drop(channel);
                    Ok(true)
                }
            }

            let handler = CertHandler;
            server::run_stream(server_config, socket, handler)
                .await
                .unwrap()
        });

        // 6. Connect as client using FutureCertificate auth with the agent
        let client_config = Arc::new(client::Config::default());

        struct TestClient;
        impl client::Handler for TestClient {
            type Error = crate::Error;

            async fn check_server_key(
                &mut self,
                _server_public_key: &ssh_key::PublicKey,
            ) -> Result<bool, Self::Error> {
                Ok(true)
            }
        }

        let mut session = client::connect(client_config, addr, TestClient)
            .await
            .unwrap();

        // Connect to the agent
        let stream = tokio::net::UnixStream::connect(&agent_path).await.unwrap();
        let mut agent_client = AgentClient::connect(stream);

        // Authenticate using FutureCertificate (None for hash_alg since Ed25519 doesn't need it)
        let auth_result = session
            .authenticate_certificate_with("testuser", cert.clone(), None, &mut agent_client)
            .await
            .unwrap();

        // 7. Verify authentication succeeded
        assert!(auth_result.success(), "Certificate authentication should succeed");

        // Clean up
        session.disconnect(crate::Disconnect::ByApplication, "", "").await.unwrap();
        drop(session);
        server_join.abort();
        agent.kill().await.unwrap();
        agent.wait().await.unwrap();
    }
}
