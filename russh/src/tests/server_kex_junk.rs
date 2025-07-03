use std::sync::Arc;

use tokio::io::AsyncWriteExt;

use crate::server;
use crate::server::Server as _;
use crate::tests::test_init;

#[tokio::test]
async fn server_kex_junk_test() {
    test_init();

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
    type Error = crate::Error;
}
