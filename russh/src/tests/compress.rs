use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::keys::PrivateKeyWithHashAlg;
use crate::{client, server, Channel, ChannelId, ChannelMsg, Preferred};
use log::debug;
use rand_core::OsRng;
use russh_cryptovec::CryptoVec;
use ssh_key::PrivateKey;

use crate::server::Msg;
use crate::server::{Server as _, Session};

#[tokio::test]
async fn compress_local_test() {
    let _ = env_logger::try_init();

    let client_key = PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let mut config = crate::server::Config::default();
    config.preferred = Preferred::COMPRESSED;
    config.inactivity_timeout = None; // Some(std::time::Duration::from_secs(3));
    config.auth_rejection_time = std::time::Duration::from_secs(3);
    config
        .keys
        .push(PrivateKey::random(&mut OsRng, ssh_key::Algorithm::Ed25519).unwrap());
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
        msg => panic!("Unexpected message {:?}", msg),
    }
}

#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<HashMap<(usize, ChannelId), server::Handle>>>,
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
    type Error = crate::Error;

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
        session.data(channel, CryptoVec::from_slice(data))?;
        Ok(())
    }
}

struct Client {}

impl client::Handler for Client {
    type Error = crate::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &crate::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // println!("check_server_key: {:?}", server_public_key);
        Ok(true)
    }
}
