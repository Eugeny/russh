#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::sync::{Arc, Mutex};

    use log::debug;
    use rand_core::OsRng;
    use ssh_key::PrivateKey;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::TcpListener;

    // Import client types directly since we're in the client module
    use crate::client::{connect, Config, Handler};
    use crate::keys::PrivateKeyWithHashAlg;
    use crate::server::{self, Auth, Handler as ServerHandler, Server, Session};
    use crate::ChannelId; // Import directly from crate root
    use crate::{CryptoVec, Error};

    #[derive(Clone)]
    struct TestServer {
        clients: Arc<Mutex<HashMap<(usize, ChannelId), server::Handle>>>,
        id: usize,
    }

    impl server::Server for TestServer {
        type Handler = Self;

        fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
            let s = self.clone();
            self.id += 1;
            s
        }
    }

    impl ServerHandler for TestServer {
        type Error = Error;

        async fn channel_open_session(
            &mut self,
            channel: crate::channels::Channel<server::Msg>,
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
            _: &ssh_key::PublicKey,
        ) -> Result<Auth, Self::Error> {
            debug!("auth_publickey");
            Ok(Auth::Accept)
        }

        async fn data(
            &mut self,
            channel: ChannelId,
            data: &[u8],
            session: &mut Session,
        ) -> Result<(), Self::Error> {
            debug!("server received data: {:?}", std::str::from_utf8(data));
            session.data(channel, CryptoVec::from_slice(data))?;
            Ok(())
        }
    }

    struct Client {}

    impl Handler for Client {
        type Error = Error;

        async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    // Custom stream wrapper that pretends to be a server with protocol version 1.99
    struct Protocol199Stream<T> {
        inner: T,
        initial_exchange_done: bool,
    }

    impl<T> Protocol199Stream<T> {
        fn new(inner: T) -> Self {
            Self {
                inner,
                initial_exchange_done: false,
            }
        }
    }

    impl<T: AsyncRead + Unpin> AsyncRead for Protocol199Stream<T> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<T: AsyncWrite + Unpin> AsyncWrite for Protocol199Stream<T> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, io::Error>> {
            if !self.initial_exchange_done && buf.starts_with(b"SSH-2.0") {
                self.initial_exchange_done = true;
                return std::pin::Pin::new(&mut self.inner)
                    .poll_write(cx, b"SSH-1.99-CustomServer_1.0\r\n");
            }
            std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), io::Error>> {
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), io::Error>> {
            std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn test_client_connects_to_protocol_1_99() {
        let _ = env_logger::try_init();

        // Create a client key
        let client_key = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();

        // Configure the server
        let mut config = server::Config::default();
        config.auth_rejection_time = std::time::Duration::from_secs(1);
        config.inactivity_timeout = None;
        config
            .keys
            .push(PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap());
        let config = Arc::new(config);

        // Create server struct
        let mut server = TestServer {
            clients: Arc::new(Mutex::new(HashMap::new())),
            id: 0,
        };

        // Start the TCP listener for our mock server
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        // Spawn a separate task that will handle the server connection
        tokio::spawn(async move {
            // Accept a connection
            let (socket, _) = socket.accept().await.unwrap();

            // Wrap socket with our Protocol199Stream to modify the version string
            let wrapped_socket = Protocol199Stream::new(socket);

            // Handle the connection with the server
            let server_handler = server.new_client(None);
            server::run_stream(config, wrapped_socket, server_handler)
                .await
                .unwrap();
        });

        println!("Server listening on {}", addr);

        // Configure the client
        let client_config = Arc::new(Config::default());

        // Connect to the server
        let mut session = connect(client_config, addr, Client {}).await.unwrap();

        // Unfortunately, we can't directly verify the protocol version from the client API
        // The Protocol199Stream wrapper ensures the server sends SSH-1.99-CustomServer_1.0
        // The test passing means the client accepted this protocol version

        // Try to authenticate
        let auth_result = session
            .authenticate_publickey(
                std::env::var("USER").unwrap_or("user".to_string()),
                PrivateKeyWithHashAlg::new(
                    Arc::new(client_key),
                    session.best_supported_rsa_hash().await.unwrap().flatten(),
                ),
            )
            .await
            .unwrap();

        assert!(auth_result.success());

        // Try opening a session channel
        let mut channel = session.channel_open_session().await.unwrap();

        // Send some data
        let test_data = b"Hello, 1.99 protocol server!";
        channel.data(&test_data[..]).await.unwrap();

        // Wait for response
        let msg = channel.wait().await.unwrap();
        match msg {
            crate::channels::ChannelMsg::Data { data: msg_data } => {
                assert_eq!(test_data.as_slice(), &msg_data[..]);
            }
            msg => panic!("Unexpected message {:?}", msg),
        }
    }
}
