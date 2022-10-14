use std::collections::HashMap;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use futures::FutureExt;
use russh::server::{Auth, Session};
use russh::*;
use russh_keys::*;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let mut config = russh::server::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(3600));
    config.auth_rejection_time = std::time::Duration::from_secs(3);

    // Depending on whether you use OpenSSL or not, you can generate different keys:
    #[cfg(feature = "openssl")]
    let keypair = russh_keys::key::KeyPair::generate_rsa(2048, key::SignatureHash::SHA1).unwrap();
    #[cfg(not(feature = "openssl"))]
    let keypair = russh_keys::key::KeyPair::generate_ed25519().unwrap();

    config
        .keys
        .push(keypair);
    let config = Arc::new(config);
    let sh = Server {
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: 0,
    };
    russh::server::run(
        config,
        &std::net::SocketAddr::from_str("0.0.0.0:2222").unwrap(),
        sh,
    )
    .await
    .unwrap();
}

#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<HashMap<(usize, ChannelId), russh::server::Handle>>>,
    id: usize,
}

impl Server {
    async fn post(&mut self, data: CryptoVec) {
        let mut clients = self.clients.lock().await;
        for ((id, channel), ref mut s) in clients.iter_mut() {
            if *id != self.id {
                let _ = s.data(*channel, data.clone()).await;
            }
        }
    }
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
    type Error = anyhow::Error;
    type FutureAuth =
        Pin<Box<dyn core::future::Future<Output = anyhow::Result<(Self, Auth)>> + Send>>;
    type FutureUnit =
        Pin<Box<dyn core::future::Future<Output = anyhow::Result<(Self, Session)>> + Send>>;
    type FutureBool =
        Pin<Box<dyn core::future::Future<Output = anyhow::Result<(Self, Session, bool)>> + Send>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        async { Ok((self, auth)) }.boxed()
    }

    fn finished_bool(self, b: bool, s: Session) -> Self::FutureBool {
        async move { Ok((self, s, b)) }.boxed()
    }

    fn finished(self, s: Session) -> Self::FutureUnit {
        async { Ok((self, s)) }.boxed()
    }

    fn channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureBool {
        async move {
            {
                let mut clients = self.clients.lock().await;
                clients.insert((self.id, channel), session.handle());
            }
            Ok((self, session, true))
        }
        .boxed()
    }

    fn auth_publickey(self, _: &str, _: &key::PublicKey) -> Self::FutureAuth {
        self.finished_auth(server::Auth::Accept)
    }

    fn data(mut self, channel: ChannelId, data: &[u8], mut session: Session) -> Self::FutureUnit {
        let data = CryptoVec::from(format!("Got data: {}\r\n", String::from_utf8_lossy(data)));
        async move {
            {
                self.post(data.clone()).await;
            }
            session.data(channel, data);
            Ok((self, session))
        }
        .boxed()
    }

    fn tcpip_forward(self, address: &str, port: u32, session: Session) -> Self::FutureBool {
        let handle = session.handle();
        let address = address.to_string();
        tokio::spawn(async move {
            let mut channel = handle
                .channel_open_forwarded_tcpip(address, port, "1.2.3.4", 1234)
                .await
                .unwrap();
            let _ = channel.data(&b"Hello from a forwarded port"[..]).await;
            let _ = channel.eof().await;
        });
        self.finished_bool(true, session)
    }
}
