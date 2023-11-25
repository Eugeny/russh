use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use pty_process::OwnedWritePty;
use russh::server::{Auth, Msg, Response, Session};
use russh::*;
use russh_keys::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

#[derive(Clone)]
struct Server {
    clients: Arc<Mutex<HashMap<(usize, ChannelId), Channel<Msg>>>>,
    channel_pty_writers: Arc<Mutex<HashMap<ChannelId, OwnedWritePty>>>,
    id: usize,
}

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
        channel_pty_writers: Arc::new(Mutex::new(HashMap::new())),
        id: 0,
    };
    russh::server::run(config, ("0.0.0.0", 2222), sh).await?;
    Ok(())
}

impl server::Server for Server {
    type Handler = Self;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        log::debug!("new client");
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
            log::debug!("channel open session");
            let mut clients = self.clients.lock().await;
            clients.insert((self.id, channel.id()), channel);
        }
        Ok((self, true, session))
    }

    /// The client requests a shell.
    #[allow(unused_variables)]
    async fn shell_request(
        self,
        channel_id: ChannelId,
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        log::debug!("shell_request");

        // create pty
        let pty = pty_process::Pty::new().unwrap();
        if let Err(e) = pty.resize(pty_process::Size::new(24, 80)) {
            log::error!("pty.resize failed: {:?}", e);
        }
        // get pts from pty
        let pts = pty.pts()?;
        // split pty into reader + writer
        let (mut pty_reader, pty_writer) = pty.into_split();
        // insert pty_reader
        self.channel_pty_writers
            .lock()
            .await
            .insert(channel_id, pty_writer);

        // pty_reader -> session_handle
        let session_handle = session.handle();
        tokio::spawn(async move {
            let mut buffer = vec![0; 1024];
            while let Ok(size) = pty_reader.read(&mut buffer).await {
                if size == 0 {
                    log::info!("pty_reader read 0");
                    let _ = session_handle.close(channel_id).await;
                    break;
                }
                let _ = session_handle
                    .data(channel_id, CryptoVec::from_slice(&buffer[0..size]))
                    .await;
            }
        });

        // Spawn a new /bin/bash process in pty
        let child = pty_process::Command::new("/bin/bash")
            .spawn(&pts)
            .map_err(anyhow::Error::new)?;

        // mark request success
        session.request_success();

        Ok((self, session))
    }

    /// The client's pseudo-terminal window size has changed.
    #[allow(unused_variables)]
    async fn window_change_request(
        self,
        channel_id: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        log::info!("window_change_request channel_id = {channel_id:?} col_width = {col_width} row_height = {row_height}");
        let mut channel_pty_writers = self.channel_pty_writers.lock().await;
        if let Some(pty_writer) = channel_pty_writers.get_mut(&channel_id) {
            if let Err(e) =
                pty_writer.resize(pty_process::Size::new(row_height as u16, col_width as u16))
            {
                log::error!("pty.resize failed: {:?}", e);
            }
        }
        drop(channel_pty_writers);
        Ok((self, session))
    }

    #[allow(unused_variables)]
    async fn auth_publickey(
        self,
        user: &str,
        public_key: &key::PublicKey,
    ) -> Result<(Self, Auth), Self::Error> {
        log::debug!("auth_publickey: user: {user} public_key: {public_key:?}");
        Ok((self, server::Auth::Accept))
    }

    #[allow(unused_variables)]
    async fn auth_keyboard_interactive(
        self,
        user: &str,
        submethods: &str,
        response: Option<Response<'async_trait>>,
    ) -> Result<(Self, Auth), Self::Error> {
        log::debug!("auth_keyboard_interactive: user: {user}");
        Ok((
            self,
            Auth::Reject {
                proceed_with_methods: Some(MethodSet::PUBLICKEY | MethodSet::PASSWORD),
            },
        ))
    }

    #[allow(unused_variables)]
    async fn auth_none(self, user: &str) -> Result<(Self, Auth), Self::Error> {
        log::debug!("auth_none: user: {user}");
        Ok((
            self,
            Auth::Reject {
                proceed_with_methods: Some(MethodSet::PUBLICKEY | MethodSet::PASSWORD),
            },
        ))
    }

    async fn auth_password(self, user: &str, password: &str) -> Result<(Self, Auth), Self::Error> {
        log::debug!("auth_password: credentials: {}, {}", user, password);
        Ok((self, Auth::Accept))
    }

    async fn data(
        self,
        channel_id: ChannelId,
        data: &[u8],
        session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        // session -> pty_writer
        let mut channel_pty_writers = self.channel_pty_writers.lock().await;
        if let Some(pty_writer) = channel_pty_writers.get_mut(&channel_id) {
            log::info!("pty_writer: data = {data:02x?}");
            pty_writer
                .write_all(data)
                .await
                .map_err(anyhow::Error::new)?;
        }
        drop(channel_pty_writers);

        Ok((self, session))
    }
}
