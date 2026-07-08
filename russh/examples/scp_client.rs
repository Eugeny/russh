///
/// SCP file transfer using SSH config aliases.
///
/// This example demonstrates how to:
/// - Parse ~/.ssh/config to resolve host aliases (hostname, port, user, identity file)
/// - Connect using `russh_config` for seamless SSH config integration
/// - Upload and download files via the SCP protocol
///
/// Setup: Add an alias to your ~/.ssh/config, e.g.:
///
///   Host myserver
///     Hostname 192.168.1.100
///     User alice
///     Port 22
///     IdentityFile ~/.ssh/id_ed25519
///
/// Run with:
///   cargo run --example scp_client -- upload myserver local_file.txt /tmp/remote_file.txt
///   cargo run --example scp_client -- download myserver /tmp/remote_file.txt local_copy.txt
///
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::Parser;
use log::info;
use russh::keys::*;
use russh::*;

#[derive(clap::Parser)]
pub struct Cli {
    /// SSH config host alias or hostname
    #[clap(index = 1)]
    host: String,

    #[clap(subcommand)]
    action: Action,

    /// Override SSH config file path
    #[clap(long)]
    ssh_config: Option<String>,
}

#[derive(clap::Subcommand)]
enum Action {
    /// Upload a local file to the remote host
    Upload {
        /// Local file path
        local: String,
        /// Remote file path
        remote: String,
    },
    /// Download a remote file to the local host
    Download {
        /// Remote file path
        remote: String,
        /// Local file path
        local: String,
    },
}

struct Client;

impl client::Handler for Client {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        // In production, verify the server key against known_hosts
        Ok(true)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let cli = Cli::parse();

    // Parse SSH config to resolve the host alias
    let ssh_config = if let Some(ref path) = cli.ssh_config {
        russh_config::parse_path(path, &cli.host)
            .context("Failed to parse SSH config file")?
    } else {
        russh_config::parse_home(&cli.host)
            .unwrap_or_else(|_| russh_config::Config::default(&cli.host))
    };

    let hostname = ssh_config.host().to_string();
    let port = ssh_config.port();
    let user = ssh_config.user();

    info!("Resolved config: {}@{}:{}", user, hostname, port);

    // Connect using the resolved config (supports ProxyCommand too)
    let config = Arc::new(russh::client::Config::default());
    let stream = ssh_config
        .stream()
        .await
        .context("Failed to connect to host")?;
    let mut session = russh::client::connect_stream(config, stream, Client)
        .await
        .context("SSH handshake failed")?;

    // Authenticate with the first available identity file from SSH config
    let key_path = ssh_config
        .identity_file()
        .and_then(|files| files.first().cloned())
        .unwrap_or_else(|| {
            let mut home = home::home_dir().expect("no home directory");
            home.push(".ssh/id_ed25519");
            home
        });

    info!("Using key: {}", key_path.display());
    let key_pair = load_secret_key(&key_path, None)
        .with_context(|| format!("Failed to load key: {}", key_path.display()))?;

    let auth_res = session
        .authenticate_publickey(
            &user,
            PrivateKeyWithHashAlg::new(
                Arc::new(key_pair),
                session.best_supported_rsa_hash().await?.flatten(),
            ),
        )
        .await?;

    if !auth_res.success() {
        bail!("Authentication failed for {user}@{hostname}");
    }

    info!("Authenticated as {user}");

    match cli.action {
        Action::Upload { local, remote } => scp_upload(&mut session, &local, &remote).await?,
        Action::Download { remote, local } => scp_download(&mut session, &remote, &local).await?,
    }

    session
        .disconnect(Disconnect::ByApplication, "", "English")
        .await?;
    Ok(())
}

/// Upload a local file to the remote host via SCP.
///
/// SCP upload protocol:
///   1. Execute `scp -t <remote_path>` on the server
///   2. Wait for server's \0 acknowledgment
///   3. Send file header: "C<mode> <size> <filename>\n"
///   4. Wait for \0 acknowledgment
///   5. Send file data
///   6. Send \0 to signal end of data
///   7. Wait for final \0 acknowledgment
async fn scp_upload(
    session: &mut client::Handle<Client>,
    local_path: &str,
    remote_path: &str,
) -> Result<()> {
    let file_data = std::fs::read(local_path)
        .with_context(|| format!("Failed to read local file: {local_path}"))?;

    let file_name = std::path::Path::new(local_path)
        .file_name()
        .context("Invalid local file path")?
        .to_string_lossy();

    let metadata = std::fs::metadata(local_path)?;
    let mode = get_file_mode(&metadata);

    info!(
        "Uploading {} ({} bytes) -> {}",
        local_path,
        file_data.len(),
        remote_path
    );

    let mut channel = session.channel_open_session().await?;
    channel
        .exec(true, format!("scp -t {remote_path}"))
        .await?;

    // Wait for initial \0 ack
    wait_for_ack(&mut channel).await?;

    // Send file header: C<mode> <size> <filename>\n
    let header = format!("C{mode:04o} {} {file_name}\n", file_data.len());
    channel.data(header.as_bytes()).await?;

    // Wait for header ack
    wait_for_ack(&mut channel).await?;

    // Send file contents
    channel.data(&file_data[..]).await?;

    // Send completion signal (\0)
    channel.data(&[0u8][..]).await?;

    // Wait for final ack
    wait_for_ack(&mut channel).await?;

    // Signal EOF and close
    channel.eof().await?;

    info!("Upload complete");
    Ok(())
}

/// Download a remote file to the local host via SCP.
///
/// SCP download protocol:
///   1. Execute `scp -f <remote_path>` on the server
///   2. Send \0 to signal readiness
///   3. Receive file header: "C<mode> <size> <filename>\n"
///   4. Send \0 acknowledgment
///   5. Receive file data (exactly <size> bytes)
///   6. Receive \0 end-of-data signal
///   7. Send final \0 acknowledgment
async fn scp_download(
    session: &mut client::Handle<Client>,
    remote_path: &str,
    local_path: &str,
) -> Result<()> {
    info!("Downloading {} -> {}", remote_path, local_path);

    let mut channel = session.channel_open_session().await?;
    channel
        .exec(true, format!("scp -f {remote_path}"))
        .await?;

    // Signal readiness
    channel.data(&[0u8][..]).await?;

    // Read the file header
    let mut header_buf = Vec::new();
    let mut file_data = Vec::new();
    let mut expected_size: Option<usize> = None;
    let mut done = false;

    loop {
        let Some(msg) = channel.wait().await else {
            break;
        };
        match msg {
            ChannelMsg::Data { ref data } => {
                if expected_size.is_none() {
                    // Still reading header
                    header_buf.extend_from_slice(data);

                    if let Some(newline_pos) = header_buf.iter().position(|&b| b == b'\n') {
                        let header_line =
                            String::from_utf8_lossy(&header_buf[..newline_pos]).to_string();

                        // Parse "C<mode> <size> <filename>"
                        if !header_line.starts_with('C') {
                            bail!("Unexpected SCP response: {header_line}");
                        }

                        let parts: Vec<&str> = header_line[1..].splitn(3, ' ').collect();
                        if parts.len() < 3 {
                            bail!("Malformed SCP header: {header_line}");
                        }

                        let size: usize = parts[1]
                            .parse()
                            .context("Invalid file size in SCP header")?;
                        info!(
                            "Receiving: mode={}, size={} bytes, name={}",
                            parts[0], size, parts[2]
                        );

                        expected_size = Some(size);

                        // Any data after the header newline is file content
                        let remaining = &header_buf[newline_pos + 1..];
                        file_data.extend_from_slice(remaining);

                        // Ack the header
                        channel.data(&[0u8][..]).await?;
                    }
                } else {
                    file_data.extend_from_slice(data);
                }

                // Check if we've received all data
                if let Some(size) = expected_size {
                    if file_data.len() >= size {
                        // Trim to exact size (there may be a trailing \0 from SCP)
                        file_data.truncate(size);

                        // Send final ack
                        channel.data(&[0u8][..]).await?;
                        done = true;
                    }
                }
            }
            ChannelMsg::ExitStatus { .. } | ChannelMsg::Eof => {
                break;
            }
            _ => {}
        }
        if done {
            break;
        }
    }

    let size = expected_size.context("No file header received from remote")?;
    if file_data.len() < size {
        bail!(
            "Incomplete download: got {} of {} bytes",
            file_data.len(),
            size
        );
    }

    std::fs::write(local_path, &file_data)
        .with_context(|| format!("Failed to write local file: {local_path}"))?;

    info!("Download complete: {} ({} bytes)", local_path, size);
    Ok(())
}

/// Wait for a \0 acknowledgment byte from the SCP server.
/// If the server sends \x01 or \x02, it's a warning or error message.
async fn wait_for_ack(channel: &mut Channel<client::Msg>) -> Result<()> {
    loop {
        let Some(msg) = channel.wait().await else {
            bail!("Channel closed while waiting for SCP ack");
        };
        match msg {
            ChannelMsg::Data { ref data } => {
                if data.is_empty() {
                    continue;
                }
                match data[0] {
                    0 => return Ok(()),
                    1 => {
                        // Warning
                        let msg = String::from_utf8_lossy(&data[1..]);
                        log::warn!("SCP warning: {msg}");
                    }
                    2 => {
                        // Error
                        let msg = String::from_utf8_lossy(&data[1..]);
                        bail!("SCP error: {msg}");
                    }
                    _ => bail!("Unexpected SCP response byte: {}", data[0]),
                }
            }
            ChannelMsg::ExitStatus { exit_status } => {
                if exit_status != 0 {
                    bail!("Remote scp exited with status {exit_status}");
                }
            }
            _ => {}
        }
    }
}

/// Get the file mode (permissions) from metadata.
#[cfg(unix)]
fn get_file_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn get_file_mode(_metadata: &std::fs::Metadata) -> u32 {
    0o644
}
