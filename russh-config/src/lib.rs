#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
use std::io::Read;
use std::path::Path;

use globset::Glob;
use log::debug;
use thiserror::*;

#[derive(Debug, Error)]
/// anyhow::Errors.
pub enum Error {
    #[error("Host not found")]
    HostNotFound,
    #[error("No home directory")]
    NoHome,
    #[error("{}", 0)]
    Io(#[from] std::io::Error),
}

mod proxy;
pub use proxy::*;

#[derive(Clone, Debug)]
pub struct Config {
    pub user: String,
    pub host_name: String,
    pub port: u16,
    pub identity_file: Option<String>,
    pub proxy_command: Option<String>,
    pub proxy_jump: Option<String>,
    pub add_keys_to_agent: AddKeysToAgent,
    pub user_known_hosts_file: Option<String>,
    pub strict_host_key_checking: bool,
}

impl Config {
    pub fn default(host_name: &str) -> Self {
        Config {
            user: whoami::username(),
            host_name: host_name.to_string(),
            port: 22,
            identity_file: None,
            proxy_command: None,
            proxy_jump: None,
            add_keys_to_agent: AddKeysToAgent::default(),
            user_known_hosts_file: None,
            strict_host_key_checking: true,
        }
    }
}

impl Config {
    // Look for any of the ssh_config(5) percent-style tokens and expand them
    // based on current data in the struct, returning a new String. This function
    // can be employed late/lazy eg just before establishing a stream using ProxyCommand
    // but also can be used to modify Hostname as config parse time
    fn expand_tokens(&self, original: &str) -> String {
        let mut string = original.to_string();
        string = string.replace("%u", &self.user);
        string = string.replace("%h", &self.host_name); // remote hostname (from context "host")
        string = string.replace("%H", &self.host_name); // remote hostname (from context "host")
        string = string.replace("%p", &format!("{}", self.port)); // original typed hostname (from context "host")
        string = string.replace("%%", "%");
        string
    }

    pub async fn stream(&self) -> Result<Stream, Error> {
        if let Some(ref proxy_command) = self.proxy_command {
            let proxy_command = self.expand_tokens(proxy_command);
            let cmd: Vec<&str> = proxy_command.split(' ').collect();
            Stream::proxy_command(cmd.first().unwrap_or(&""), cmd.get(1..).unwrap_or(&[]))
                .await
                .map_err(Into::into)
        } else {
            Stream::tcp_connect((self.host_name.as_str(), self.port))
                .await
                .map_err(Into::into)
        }
    }
}

pub fn parse_home(host: &str) -> Result<Config, Error> {
    let mut home = if let Some(home) = home::home_dir() {
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

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum AddKeysToAgent {
    Yes,
    Confirm,
    Ask,
    #[default]
    No,
}

pub fn parse(file: &str, host: &str) -> Result<Config, Error> {
    let mut config = Config::default(host);
    let mut matches_current = false;
    for line in file.lines() {
        let tokens = line.trim().splitn(2, ' ').collect::<Vec<&str>>();
        if tokens.len() == 2 {
            let (key, value) = (tokens.first().unwrap_or(&""), tokens.get(1).unwrap_or(&""));
            let lower = key.to_lowercase();
            if lower.as_str() == "host" {
                matches_current = value
                    .split_whitespace()
                    .any(|x| check_host_against_glob_pattern(host, x));
            }
            if matches_current {
                match lower.as_str() {
                    "user" => {
                        config.user.clear();
                        config.user.push_str(value.trim_start());
                    }
                    "hostname" => config.host_name = config.expand_tokens(value.trim_start()),
                    "port" => {
                        if let Ok(port) = value.trim_start().parse() {
                            config.port = port
                        }
                    }
                    "identityfile" => {
                        config.identity_file =
                            Some(value.trim_start().strip_quotes().expand_home()?);
                    }
                    "proxycommand" => config.proxy_command = Some(value.trim_start().to_string()),
                    "proxyjump" => config.proxy_jump = Some(value.trim_start().to_string()),
                    "addkeystoagent" => match value.to_lowercase().as_str() {
                        "yes" => config.add_keys_to_agent = AddKeysToAgent::Yes,
                        "confirm" => config.add_keys_to_agent = AddKeysToAgent::Confirm,
                        "ask" => config.add_keys_to_agent = AddKeysToAgent::Ask,
                        _ => config.add_keys_to_agent = AddKeysToAgent::No,
                    },
                    "userknownhostsfile" => {
                        config.user_known_hosts_file =
                            Some(value.trim_start().strip_quotes().expand_home()?);
                    }
                    "stricthostkeychecking" => match value.to_lowercase().as_str() {
                        "no" => config.strict_host_key_checking = false,
                        _ => config.strict_host_key_checking = true,
                    },
                    key => {
                        debug!("{:?}", key);
                    }
                }
            }
        }
    }
    Ok(config)
}

fn check_host_against_glob_pattern(candidate: &str, glob_pattern: &str) -> bool {
    match Glob::new(glob_pattern) {
        Ok(glob) => glob.compile_matcher().is_match(candidate),
        _ => false,
    }
}

trait SshConfigStrExt {
    fn strip_quotes(&self) -> Self;
    fn expand_home(&self) -> Result<String, Error>;
}

impl SshConfigStrExt for &str {
    fn strip_quotes(&self) -> Self {
        if self.len() > 1
            && ((self.starts_with('\'') && self.ends_with('\''))
                || (self.starts_with('\"') && self.ends_with('\"')))
        {
            #[allow(clippy::indexing_slicing)] // length checked
            &self[1..self.len() - 1]
        } else {
            self
        }
    }

    fn expand_home(&self) -> Result<String, Error> {
        if self.starts_with("~/") {
            if let Some(mut home) = home::home_dir() {
                home.push(self.split_at(2).1);
                Ok(home
                    .to_str()
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Failed to convert home directory to string",
                        )
                    })?
                    .to_string())
            } else {
                Err(Error::NoHome)
            }
        } else {
            Ok(self.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use crate::{parse, AddKeysToAgent, Config, SshConfigStrExt};

    #[test]
    fn strip_quotes() {
        let value = "'this is a test'";
        assert_eq!("this is a test", value.strip_quotes());
        let value = "\"this is a test\"";
        assert_eq!("this is a test", value.strip_quotes());
        let value = "'this is a test\"";
        assert_eq!("'this is a test\"", value.strip_quotes());
        let value = "'this is a test";
        assert_eq!("'this is a test", value.strip_quotes());
        let value = "this is a test'";
        assert_eq!("this is a test'", value.strip_quotes());
        let value = "this is a test";
        assert_eq!("this is a test", value.strip_quotes());
        let value = "";
        assert_eq!("", value.strip_quotes());
        let value = "'";
        assert_eq!("'", value.strip_quotes());
        let value = "''";
        assert_eq!("", value.strip_quotes());
    }

    #[test]
    fn expand_home() {
        let value = "~/some/folder".expand_home().expect("expand_home");
        assert_eq!(
            format!(
                "{}{}",
                home::home_dir().expect("homedir").to_str().expect("to_str"),
                "/some/folder"
            ),
            value
        );
    }

    #[test]
    fn default_config() {
        let config: Config = Config::default("some_host");
        assert_eq!(whoami::username(), config.user);
        assert_eq!("some_host", config.host_name);
        assert_eq!(22, config.port);
        assert_eq!(None, config.identity_file);
        assert_eq!(None, config.proxy_command);
        assert_eq!(None, config.proxy_jump);
        assert_eq!(AddKeysToAgent::No, config.add_keys_to_agent);
        assert_eq!(None, config.user_known_hosts_file);
        assert!(config.strict_host_key_checking);
    }

    #[test]
    fn basic_config() {
        let value = r"#
Host test_host
  IdentityFile '~/.ssh/id_ed25519'
  User trinity
  Hostname foo.com
  Port 23
  UserKnownHostsFile /some/special/host_file
  StrictHostKeyChecking no
#";
        let identity_file = format!(
            "{}{}",
            home::home_dir().expect("homedir").to_str().expect("to_str"),
            "/.ssh/id_ed25519"
        );
        let config = parse(value, "test_host").expect("parse");
        assert_eq!("trinity", config.user);
        assert_eq!("foo.com", config.host_name);
        assert_eq!(23, config.port);
        assert_eq!(Some(identity_file), config.identity_file);
        assert_eq!(None, config.proxy_command);
        assert_eq!(None, config.proxy_jump);
        assert_eq!(AddKeysToAgent::No, config.add_keys_to_agent);
        assert_eq!(
            Some("/some/special/host_file"),
            config.user_known_hosts_file.as_deref()
        );
        assert!(!config.strict_host_key_checking);
    }

    #[test]
    fn is_clone() {
        let config: Config = Config::default("some_host");
        let _ = config.clone();
    }
}
