//! Shared scaffolding for integration tests: ephemeral port allocation and a
//! trivial accept-all client handler.

#![allow(dead_code)]

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use russh::keys::PrivateKeyWithHashAlg;
use russh::{client, server};
use ssh_key::PrivateKey;

/// Find an unused local address to bind a server to.
pub fn addr() -> SocketAddr {
    TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Spin until a TCP connection to `addr` succeeds.
pub async fn wait_for_server(addr: SocketAddr) {
    while TcpStream::connect(addr).is_err() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A client handler that accepts any server key.
pub struct Client;

impl client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// `server::Config` with a fresh ed25519 host key and the given overrides.
pub fn server_config(window_size: u32, channel_buffer_size: usize) -> Arc<server::Config> {
    Arc::new(server::Config {
        keys: vec![PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap()],
        window_size,
        channel_buffer_size,
        ..Default::default()
    })
}

/// Connect to `addr` and authenticate with a fresh ed25519 key.
pub async fn connect(addr: SocketAddr) -> Result<client::Handle<Client>, anyhow::Error> {
    let config = Arc::new(client::Config::default());
    let key = Arc::new(PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap());
    let mut session = client::connect(config, addr, Client).await?;
    let auth = session
        .authenticate_publickey(
            "user",
            PrivateKeyWithHashAlg::new(
                key,
                session.best_supported_rsa_hash().await.unwrap().flatten(),
            ),
        )
        .await?;
    assert!(auth.success(), "authentication rejected");
    Ok(session)
}
