use async_trait::async_trait;

use log::debug;
use russh::server::{Auth, Msg, Session};
use russh::*;
use russh_keys::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let mut config = russh::server::Config::default();
    config.auth_rejection_time = std::time::Duration::from_secs(3);
    config
        .keys
        .push(russh_keys::key::KeyPair::generate_ed25519().unwrap());
    let config = Arc::new(config);
    let sh = Server {
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: 0,
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        russh::server::run(config, ("0.0.0.0", 2222), sh),
    )
    .await
    .unwrap_or(Ok(()))?;

    Ok(())
}

#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<HashMap<(usize, ChannelId), Channel<Msg>>>>,
    id: usize,
}

impl server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        debug!("new client");
        let s = self.clone();
        self.id += 1;
        s
    }
}

#[async_trait]
impl server::Handler for Server {
    type Error = anyhow::Error;

    async fn channel_open_session(
        self,
        channel: Channel<Msg>,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        {
            debug!("channel open session");
            let mut clients = self.clients.lock().unwrap();
            clients.insert((self.id, channel.id()), channel);
        }
        Ok((self, true, session))
    }

    /// The client requests a shell.
    #[allow(unused_variables)]
    async fn shell_request(
        self,
        channel: ChannelId,
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        session.request_success();
        Ok((self, session))
    }

    async fn auth_publickey(
        self,
        _: &str,
        _: &key::PublicKey,
    ) -> Result<(Self, Auth), Self::Error> {
        Ok((self, server::Auth::Accept))
    }
    async fn data(
        self,
        _channel: ChannelId,
        data: &[u8],
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        debug!("data: {data:?}");
        {
            let mut clients = self.clients.lock().unwrap();
            for ((_, _channel_id), ref mut channel) in clients.iter_mut() {
                session.data(channel.id(), CryptoVec::from(data.to_vec()));
            }
        }
        Ok((self, session))
    }
}
