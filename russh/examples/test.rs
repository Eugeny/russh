use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use log::debug;
use russh::server::{Auth, Msg, Server as _, Session};
use russh::*;
use russh_keys::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let mut config = russh::server::Config::default();
    config.auth_rejection_time = std::time::Duration::from_secs(3);
    config
        .keys
        .push(russh_keys::key::KeyPair::generate_ed25519().unwrap());
    let config = Arc::new(config);
    let mut sh = Server {
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: 0,
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        sh.run_on_address(config, ("0.0.0.0", 2222)),
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
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        {
            debug!("channel open session");
            let mut clients = self.clients.lock().unwrap();
            clients.insert((self.id, channel.id()), channel);
        }
        Ok(true)
    }

    /// The client requests a shell.
    #[allow(unused_variables)]
    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.request_success();
        Ok(())
    }

    async fn auth_publickey(&mut self, _: &str, _: &key::PublicKey) -> Result<Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("data: {data:?}");
        {
            let mut clients = self.clients.lock().unwrap();
            for ((_, _channel_id), ref mut channel) in clients.iter_mut() {
                session.data(channel.id(), CryptoVec::from(data.to_vec()));
            }
        }
        Ok(())
    }
}
