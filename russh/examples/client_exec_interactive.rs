///
/// Run this example with:
/// cargo run --all-features --example client_exec_interactive -- -k <private key path> <host> <command>
///
use std::convert::TryFrom;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use clap::Parser;
use log::info;
use russh::*;
use russh_keys::*;
use termion::raw::IntoRawMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::ToSocketAddrs;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .init();

    // CLI options are defined later in this file
    let cli = Cli::parse();

    info!("Connecting to {}:{}", cli.host, cli.port);
    info!("Key path: {:?}", cli.private_key);

    // Session is a wrapper around a russh client, defined down below
    let mut ssh = Session::connect(
        cli.private_key,
        cli.username.unwrap_or("root".to_string()),
        (cli.host, cli.port),
    )
    .await?;
    info!("Connected");

    let code = {
        // We're using `termion` to put the terminal into raw mode, so that we can
        // display the output of interactive applications correctly
        let _raw_term = std::io::stdout().into_raw_mode()?;
        ssh.call(
            &cli.command
                .into_iter()
                .map(|x| shell_escape::escape(x.into())) // arguments are escaped manually since the SSH protocol doesn't support quoting
                .collect::<Vec<_>>()
                .join(" "),
        )
        .await?
    };

    println!("Exitcode: {:?}", code);
    ssh.close().await?;
    Ok(())
}

struct Client {}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
#[async_trait]
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        self,
        _server_public_key: &key::PublicKey,
    ) -> Result<(Self, bool), Self::Error> {
        Ok((self, true))
    }
}

/// This struct is a convenience wrapper
/// around a russh client
/// that handles the input/output event loop
pub struct Session {
    session: client::Handle<Client>,
}

impl Session {
    async fn connect<P: AsRef<Path>, A: ToSocketAddrs>(
        key_path: P,
        user: impl Into<String>,
        addrs: A,
    ) -> Result<Self> {
        let key_pair = load_secret_key(key_path, None)?;
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            ..<_>::default()
        };

        let config = Arc::new(config);
        let sh = Client {};

        let mut session = client::connect(config, addrs, sh).await?;
        let auth_res = session
            .authenticate_publickey(user, Arc::new(key_pair))
            .await?;

        if !auth_res {
            anyhow::bail!("Authentication failed");
        }

        Ok(Self { session })
    }

    async fn call(&mut self, command: &str) -> Result<u32> {
        let mut channel = self.session.channel_open_session().await?;

        // This example doesn't terminal resizing after the connection is established
        let (w, h) = termion::terminal_size()?;

        // Request an interactive PTY from the server
        channel
            .request_pty(
                false,
                &env::var("TERM").unwrap_or("xterm".into()),
                w as u32,
                h as u32,
                0,
                0,
                &[], // ideally you want to pass the actual terminal modes here
            )
            .await?;
        channel.exec(true, command).await?;

        let code;
        let mut stdin = tokio_fd::AsyncFd::try_from(0)?;
        let mut stdout = tokio_fd::AsyncFd::try_from(1)?;
        let mut buf = vec![0; 1024];
        let mut stdin_closed = false;

        loop {
            // Handle one of the possible events:
            tokio::select! {
                // There's terminal input available from the user
                r = stdin.read(&mut buf), if !stdin_closed => {
                    match r {
                        Ok(0) => {
                            stdin_closed = true;
                            channel.eof().await?;
                        },
                        // Send it to the server
                        Ok(n) => channel.data(&buf[..n]).await?,
                        Err(e) => return Err(e.into()),
                    };
                },
                // There's an event available on the session channel
                Some(msg) = channel.wait() => {
                    match msg {
                        // Write data to the terminal
                        ChannelMsg::Data { ref data } => {
                            stdout.write_all(data).await?;
                            stdout.flush().await?;
                        }
                        // The command has returned an exit code
                        ChannelMsg::ExitStatus { exit_status } => {
                            code = exit_status;
                            if !stdin_closed {
                                channel.eof().await?;
                            }
                            break;
                        }
                        _ => {}
                    }
                },
            }
        }
        Ok(code)
    }

    async fn close(&mut self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}

#[derive(clap::Parser)]
#[clap(trailing_var_arg = true)]
pub struct Cli {
    #[clap(index = 1)]
    host: String,

    #[clap(long, short, default_value_t = 22)]
    port: u16,

    #[clap(long, short)]
    username: Option<String>,

    #[clap(long, short = 'k')]
    private_key: PathBuf,

    #[clap(multiple = true, index = 2, required = true)]
    command: Vec<String>,
}
