use async_trait::async_trait;
use log::{error, info, LevelFilter};
use russh::{
    server::{Auth, Msg, Session},
    Channel, ChannelId,
};
use russh_keys::key::KeyPair;
use russh_sftp::protocol::{File, FileAttributes, Handle, Name, Status, StatusCode, Version};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Mutex;

#[derive(Clone)]
struct Server;

impl russh::server::Server for Server {
    type Handler = SshSession;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        SshSession::default()
    }
}

struct SshSession {
    clients: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl Default for SshSession {
    fn default() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl SshSession {
    pub async fn get_channel(&mut self, channel_id: ChannelId) -> Channel<Msg> {
        let mut clients = self.clients.lock().await;
        clients.remove(&channel_id).unwrap()
    }
}

#[async_trait]
impl russh::server::Handler for SshSession {
    type Error = anyhow::Error;

    async fn auth_password(self, user: &str, password: &str) -> Result<(Self, Auth), Self::Error> {
        info!("credentials: {}, {}", user, password);
        Ok((self, Auth::Accept))
    }

    async fn auth_publickey(
        self,
        user: &str,
        public_key: &russh_keys::key::PublicKey,
    ) -> Result<(Self, Auth), Self::Error> {
        info!("credentials: {}, {:?}", user, public_key);
        Ok((self, Auth::Accept))
    }

    async fn channel_open_session(
        mut self,
        channel: Channel<Msg>,
        session: Session,
    ) -> Result<(Self, bool, Session), Self::Error> {
        {
            let mut clients = self.clients.lock().await;
            clients.insert(channel.id(), channel);
        }
        Ok((self, true, session))
    }

    async fn subsystem_request(
        mut self,
        channel_id: ChannelId,
        name: &str,
        mut session: Session,
    ) -> Result<(Self, Session), Self::Error> {
        info!("subsystem: {}", name);

        if name == "sftp" {
            let channel = self.get_channel(channel_id).await;
            let sftp = SftpSession::default();
            session.channel_success(channel_id);
            russh_sftp::server::run(channel.into_stream(), sftp).await;
        } else {
            session.channel_failure(channel_id);
        }

        Ok((self, session))
    }
}

#[derive(Default)]
struct SftpSession {
    version: Option<u32>,
    root_dir_read_done: bool,
}

#[async_trait]
impl russh_sftp::server::Handler for SftpSession {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        version: u32,
        extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        if self.version.is_some() {
            error!("duplicate SSH_FXP_VERSION packet");
            return Err(StatusCode::ConnectionLost);
        }

        self.version = Some(version);
        info!("version: {:?}, extensions: {:?}", self.version, extensions);
        Ok(Version::new())
    }

    async fn close(&mut self, id: u32, _handle: String) -> Result<Status, Self::Error> {
        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        info!("opendir: {}", path);
        self.root_dir_read_done = false;
        Ok(Handle { id, handle: path })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        info!("readdir handle: {}", handle);
        if handle == "/" && !self.root_dir_read_done {
            self.root_dir_read_done = true;
            return Ok(Name {
                id,
                files: vec![
                    File {
                        filename: "foo".to_string(),
                        attrs: FileAttributes::default(),
                    },
                    File {
                        filename: "bar".to_string(),
                        attrs: FileAttributes::default(),
                    },
                ],
            });
        }
        Ok(Name { id, files: vec![] })
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        info!("realpath: {}", path);
        Ok(Name {
            id,
            files: vec![File {
                filename: "/".to_string(),
                attrs: FileAttributes::default(),
            }],
        })
    }
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(LevelFilter::Debug)
        .init();

    let config = russh::server::Config {
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![generate_keypair()],
        connection_timeout: Some(Duration::from_secs(3600)),
        ..Default::default()
    };

    let server = Server;

    russh::server::run(
        Arc::new(config),
        (
            "0.0.0.0",
            std::env::var("PORT")
                .unwrap_or("22".to_string())
                .parse()
                .unwrap(),
        ),
        server,
    )
    .await
    .unwrap();
}

#[cfg(feature = "rs-crypto")]
fn generate_keypair() -> KeyPair {
    KeyPair::generate_ed25519().unwrap()
}

#[cfg(not(feature = "rs-crypto"))]
fn generate_keypair() -> KeyPair {
    KeyPair::generate_rsa(1024, russh_keys::key::SignatureHash::SHA2_512).unwrap()
}
