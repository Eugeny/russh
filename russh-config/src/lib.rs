#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
use std::io::Read;
use std::net::ToSocketAddrs;
use std::path::Path;

use log::debug;
use thiserror::*;

#[derive(Debug, Error)]
/// anyhow::Errors.
pub enum Error {
    #[error("Host not found")]
    HostNotFound,
    #[error("No home directory")]
    NoHome,
    #[error("Cannot resolve the address")]
    NotResolvable,
    #[error("{}", 0)]
    Io(#[from] std::io::Error),
}

mod proxy;
pub use proxy::*;

#[derive(Debug)]
pub struct Config {
    pub user: String,
    pub host_name: String,
    pub port: u16,
    pub identity_file: Option<String>,
    pub proxy_command: Option<String>,
    pub add_keys_to_agent: AddKeysToAgent,
}

impl Config {
    pub fn default(host_name: &str) -> Self {
        Config {
            user: whoami::username(),
            host_name: host_name.to_string(),
            port: 22,
            identity_file: None,
            proxy_command: None,
            add_keys_to_agent: AddKeysToAgent::default(),
        }
    }
}

impl Config {
    fn update_proxy_command(&mut self) {
        if let Some(ref mut prox) = self.proxy_command {
            *prox = prox.replace("%h", &self.host_name);
            *prox = prox.replace("%p", &format!("{}", self.port));
        }
    }

    pub async fn stream(&mut self) -> Result<Stream, Error> {
        self.update_proxy_command();
        if let Some(ref proxy_command) = self.proxy_command {
            let cmd: Vec<&str> = proxy_command.split(' ').collect();
            Stream::proxy_command(cmd.first().unwrap_or(&""), cmd.get(1..).unwrap_or(&[]))
                .await
                .map_err(Into::into)
        } else {
            let address = (self.host_name.as_str(), self.port)
                .to_socket_addrs()?
                .next()
                .ok_or(Error::NotResolvable)?;
            Stream::tcp_connect(&address).await.map_err(Into::into)
        }
    }
}

pub fn parse_home(host: &str) -> Result<Config, Error> {
    let mut home = if let Some(home) = dirs_next::home_dir() {
        home
    } else {
        return Err(Error::NoHome);
    };
    home.push(".ssh");
    home.push("config");
    parse_path(&home, host)
}

pub fn parse_path<P: AsRef<Path>>(path: P, host: &str) -> Result<Config, Error> {
    let mut s = String::new();
    let mut b = std::fs::File::open(path)?;
    b.read_to_string(&mut s)?;
    parse(&s, host)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum AddKeysToAgent {
    Yes,
    Confirm,
    Ask,
    #[default]
    No,
}



pub fn parse(file: &str, host: &str) -> Result<Config, Error> {
    let mut config: Option<Config> = None;
    for line in file.lines() {
        let line = line.trim();
        if let Some(n) = line.find(' ') {
            let (key, value) = line.split_at(n);
            let lower = key.to_lowercase();
            if let Some(ref mut config) = config {
                match lower.as_str() {
                    "host" => break,
                    "user" => {
                        config.user.clear();
                        config.user.push_str(value.trim_start());
                    }
                    "hostname" => {
                        config.host_name.clear();
                        config.host_name.push_str(value.trim_start())
                    }
                    "port" => {
                        if let Ok(port) = value.trim_start().parse() {
                            config.port = port
                        }
                    }
                    "identityfile" => {
                        let id = value.trim_start();
                        if id.starts_with("~/") {
                            if let Some(mut home) = dirs_next::home_dir() {
                                home.push(id.split_at(2).1);
                                config.identity_file = Some(
                                    home.to_str()
                                        .ok_or_else(|| {
                                            std::io::Error::new(
                                                std::io::ErrorKind::Other,
                                                "Failed to convert home directory to string",
                                            )
                                        })?
                                        .to_string(),
                                );
                            } else {
                                return Err(Error::NoHome);
                            }
                        } else {
                            config.identity_file = Some(id.to_string())
                        }
                    }
                    "proxycommand" => config.proxy_command = Some(value.trim_start().to_string()),
                    "addkeystoagent" => match value.to_lowercase().as_str() {
                        "yes" => config.add_keys_to_agent = AddKeysToAgent::Yes,
                        "confirm" => config.add_keys_to_agent = AddKeysToAgent::Confirm,
                        "ask" => config.add_keys_to_agent = AddKeysToAgent::Ask,
                        _ => config.add_keys_to_agent = AddKeysToAgent::No,
                    },
                    key => {
                        debug!("{:?}", key);
                    }
                }
            } else if lower.as_str() == "host" && value.trim_start() == host {
                let mut c = Config::default(host);
                c.port = 22;
                config = Some(c)
            }
        }
    }
    if let Some(config) = config {
        Ok(config)
    } else {
        Err(Error::HostNotFound)
    }
}
