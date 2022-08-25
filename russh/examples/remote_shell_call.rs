use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use log::info;
use russh::*;
use russh_keys::*;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let args: Vec<String> = std::env::args().collect();
    let (host, key) = match args.get(1..3) {
        Some(args) => (&args[0], &args[1]),
        None => {
            eprintln!("Usage: {} <host:port> <private-key-path>", args[0]);
            std::process::exit(1);
        }
    };

    info!("Connecting to {host}");
    info!("Key path: {key}");

    let mut ssh = Session::connect(key, "root", SocketAddr::from_str(host).unwrap()).await?;
    let r = ssh.call("whoami").await?;
    assert!(r.success());
    println!("Result: {}", r.output());
    ssh.close().await?;
    Ok(())
}

struct Client {}

impl client::Handler for Client {
    type Error = russh::Error;
    type FutureUnit = futures::future::Ready<Result<(Self, client::Session), Self::Error>>;
    type FutureBool = futures::future::Ready<Result<(Self, bool), Self::Error>>;

    fn finished_bool(self, b: bool) -> Self::FutureBool {
        futures::future::ready(Ok((self, b)))
    }
    fn finished(self, session: client::Session) -> Self::FutureUnit {
        futures::future::ready(Ok((self, session)))
    }
    fn check_server_key(self, _server_public_key: &key::PublicKey) -> Self::FutureBool {
        self.finished_bool(true)
    }
}

pub struct Session {
    session: client::Handle<Client>,
}

impl Session {
    async fn connect<P: AsRef<Path>>(
        key_path: P,
        user: impl Into<String>,
        addr: SocketAddr,
    ) -> Result<Self> {
        let key_pair = load_secret_key(key_path, None)?;
        let config = client::Config {
            connection_timeout: Some(Duration::from_secs(5)),
            ..<_>::default()
        };
        let config = Arc::new(config);
        let sh = Client {};
        let mut session = client::connect(config, addr, sh).await?;
        let _auth_res = session
            .authenticate_publickey(user, Arc::new(key_pair))
            .await?;
        Ok(Self { session })
    }

    async fn call(&mut self, command: &str) -> Result<CommandResult> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;
        let mut output = Vec::new();
        let mut code = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                russh::ChannelMsg::Data { ref data } => {
                    output.write_all(data).unwrap();
                }
                russh::ChannelMsg::ExitStatus { exit_status } => {
                    code = Some(exit_status);
                }
                _ => {}
            }
        }
        Ok(CommandResult { output, code })
    }

    async fn close(&mut self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}

struct CommandResult {
    output: Vec<u8>,
    code: Option<u32>,
}

impl CommandResult {
    fn output(&self) -> String {
        String::from_utf8_lossy(&self.output).into()
    }

    fn success(&self) -> bool {
        self.code == Some(0)
    }
}
