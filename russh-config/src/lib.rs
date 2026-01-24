#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
use std::io::Read;
use std::path::{Path, PathBuf};

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

#[derive(Clone, Debug, Default)]
struct HostConfig {
    /// http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#User
    user: Option<String>,
    /// http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#Hostname
    hostname: Option<String>,
    /// http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#Port
    port: Option<u16>,
    /// http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#IdentityFile
    identity_file: Option<Vec<PathBuf>>,
    /// http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#ProxyCommand
    proxy_command: Option<String>,
    /// http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#ProxyJump
    proxy_jump: Option<String>,
    /// http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#AddKeysToAgent
    add_keys_to_agent: Option<AddKeysToAgent>,
    /// http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#UserKnownHostsFile
    user_known_hosts_file: Option<PathBuf>,
    /// http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#StrictHostKeyChecking
    strict_host_key_checking: Option<bool>,
}

impl HostConfig {
    fn merge(mut left: Self, right: &Self) -> Self {
        macro_rules! clone_if_none {
            ($left:ident, $right:ident, $($field:ident),+) => {
                $(if $left.$field.is_none() {
                    $left.$field = $right.$field.clone();
                })+
            };
        }

        clone_if_none!(
            left,
            right,
            user,
            hostname,
            port,
            proxy_command,
            proxy_jump,
            add_keys_to_agent,
            user_known_hosts_file,
            strict_host_key_checking
        );

        // Special-case IdentityFile param
        if let Some(right_identity_files) = right.identity_file.as_deref() {
            if let Some(identity_files) = left.identity_file.as_mut() {
                identity_files.extend(right_identity_files.iter().cloned())
            } else {
                left.identity_file = Some(Vec::from_iter(right_identity_files.iter().cloned()))
            }
        }
        left
    }
}

/// https://man.openbsd.org/OpenBSD-current/man5/ssh_config.5#PATTERNS
#[derive(Clone, Debug)]
struct HostPattern {
    pattern: String,
    negated: bool,
}

#[derive(Clone, Debug, Default)]
struct HostEntry {
    host_patterns: Vec<HostPattern>,
    host_config: HostConfig,
}

impl HostEntry {
    fn matches(&self, host: &str) -> bool {
        let mut matches = false;
        for host_pattern in self.host_patterns.iter() {
            if check_host_against_glob_pattern(host, &host_pattern.pattern) {
                if host_pattern.negated {
                    // "If a negated entry is matched, then the Host entry is ignored, regardless of whether any other patterns on the line match."
                    return false;
                }
                matches = true;
            }
        }
        matches
    }
}

struct SshConfig {
    entries: Vec<HostEntry>,
}

impl SshConfig {
    pub fn query(&self, host: &str) -> HostConfig {
        self.entries
            .iter()
            .filter_map(|e| {
                if e.matches(host) {
                    Some(&e.host_config)
                } else {
                    None
                }
            })
            .fold(HostConfig::default(), HostConfig::merge)
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    host_name: String,
    user: Option<String>,
    port: Option<u16>,
    host_config: HostConfig,
}

impl Config {
    pub fn default(host: &str) -> Self {
        Self {
            host_name: host.to_string(),
            user: None,
            port: None,
            host_config: HostConfig::default(),
        }
    }

    pub fn user(&self) -> String {
        self.user
            .as_deref()
            .or(self.host_config.user.as_deref())
            .map(ToString::to_string)
            .unwrap_or_else(whoami::username)
    }

    pub fn port(&self) -> u16 {
        self.host_config.port.or(self.port).unwrap_or(22)
    }

    pub fn host(&self) -> &str {
        self.host_config
            .hostname
            .as_ref()
            .unwrap_or(&self.host_name)
    }

    // Look for any of the ssh_config(5) percent-style tokens and expand them
    // based on current data in the struct, returning a new String. This function
    // can be employed late/lazy eg just before establishing a stream using ProxyCommand
    // but also can be used to modify Hostname as config parse time
    fn expand_tokens(&self, original: &str) -> String {
        let mut string = original.to_string();
        string = string.replace("%u", &self.user());
        string = string.replace("%h", self.host()); // remote hostname (from context "host")
        string = string.replace("%H", self.host()); // remote hostname (from context "host")
        string = string.replace("%p", &format!("{}", self.port())); // original typed hostname (from context "host")
        string = string.replace("%%", "%");
        string
    }

    pub async fn stream(&self) -> Result<Stream, Error> {
        if let Some(ref proxy_command) = self.host_config.proxy_command {
            let proxy_command = self.expand_tokens(proxy_command);
            let cmd: Vec<&str> = proxy_command.split(' ').collect();
            Stream::proxy_command(cmd.first().unwrap_or(&""), cmd.get(1..).unwrap_or(&[]))
                .await
                .map_err(Into::into)
        } else {
            Stream::tcp_connect((self.host(), self.port()))
                .await
                .map_err(Into::into)
        }
    }
}

fn parse_ssh_config(contents: &str) -> Result<SshConfig, Error> {
    let mut entries = Vec::new();

    let mut host_patterns: Option<Vec<HostPattern>> = None;
    let mut config = HostConfig::default();
    let mut found_params = false;

    for line in contents.lines().map(|line| line.trim()) {
        if line.is_empty() || line.starts_with('#') {
            // skip comments and empty lines
            //
            // Reference: http://man.openbsd.org/OpenBSD-current/man5/ssh_config.5
            // "Lines starting with ‘#’ and empty lines are interpreted as comments."
            continue;
        }
        let tokens = line.splitn(2, ' ').collect::<Vec<&str>>();
        if tokens.len() == 2 {
            let (key, value) = (tokens.first().unwrap_or(&""), tokens.get(1).unwrap_or(&""));
            let lower = key.to_lowercase();
            if lower != "host" {
                found_params = true;
            }
            match lower.as_str() {
                "host" => {
                    let patterns = value
                        .split_ascii_whitespace()
                        .filter_map(|pattern| {
                            if pattern.is_empty() {
                                None
                            } else {
                                let (pattern, negated) =
                                    if let Some(pattern) = pattern.strip_prefix('!') {
                                        (pattern, true)
                                    } else {
                                        (pattern, false)
                                    };
                                Some(HostPattern {
                                    pattern: pattern.to_string(),
                                    negated,
                                })
                            }
                        })
                        .collect();

                    if let Some(host_patterns) = host_patterns.take() {
                        let host_config = std::mem::take(&mut config);
                        entries.push(HostEntry {
                            host_patterns,
                            host_config,
                        });
                    } else if found_params {
                        return Err(Error::HostNotFound);
                    }

                    found_params = false;
                    host_patterns = Some(patterns);
                }
                "user" => config.user = Some(value.trim_start().to_string()),
                "hostname" => config.hostname = Some(value.trim_start().to_string()),
                "port" => {
                    if let Ok(port) = value.trim_start().parse::<u16>() {
                        config.port = Some(port)
                    }
                }
                "identityfile" => {
                    let identity_file = value.trim_start().strip_quotes().expand_home()?;
                    if let Some(files) = config.identity_file.as_mut() {
                        files.push(identity_file);
                    } else {
                        config.identity_file = Some(vec![identity_file])
                    }
                }
                "proxycommand" => config.proxy_command = Some(value.trim_start().to_string()),
                "proxyjump" => config.proxy_jump = Some(value.trim_start().to_string()),
                "addkeystoagent" => {
                    let value = match value.to_lowercase().as_str() {
                        "yes" => AddKeysToAgent::Yes,
                        "confirm" => AddKeysToAgent::Confirm,
                        "ask" => AddKeysToAgent::Ask,
                        _ => AddKeysToAgent::No,
                    };
                    config.add_keys_to_agent = Some(value)
                }
                "userknownhostsfile" => {
                    config.user_known_hosts_file =
                        Some(value.trim_start().strip_quotes().expand_home()?);
                }
                "stricthostkeychecking" => match value.to_lowercase().as_str() {
                    "no" => config.strict_host_key_checking = Some(false),
                    _ => config.strict_host_key_checking = Some(true),
                },
                key => {
                    debug!("{key:?}");
                }
            }
        }
    }

    if let Some(host_patterns) = host_patterns.take() {
        let host_config = std::mem::take(&mut config);
        entries.push(HostEntry {
            host_patterns,
            host_config,
        });
    } else if found_params {
        // Found configurations, but no Host (or Match) key.
        return Err(Error::HostNotFound);
    }

    Ok(SshConfig { entries })
}

pub fn parse(file: &str, host: &str) -> Result<Config, Error> {
    let ssh_config = parse_ssh_config(file)?;
    let host_config = ssh_config.query(host);
    Ok(Config {
        host_name: host.to_string(),
        user: None,
        port: None,
        host_config,
    })
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

fn check_host_against_glob_pattern(candidate: &str, glob_pattern: &str) -> bool {
    match Glob::new(glob_pattern) {
        Ok(glob) => glob.compile_matcher().is_match(candidate),
        _ => false,
    }
}

trait SshConfigStrExt {
    fn strip_quotes(&self) -> Self;
    fn expand_home(&self) -> Result<PathBuf, Error>;
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

    fn expand_home(&self) -> Result<PathBuf, Error> {
        if self.starts_with("~/") {
            if let Some(mut home) = home::home_dir() {
                home.push(self.split_at(2).1);
                Ok(home)
            } else {
                Err(Error::NoHome)
            }
        } else {
            Ok(self.into())
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    use std::path::{Path, PathBuf};

    use crate::{AddKeysToAgent, Config, Error, SshConfigStrExt, parse};

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
            value.to_str().unwrap()
        );
    }

    #[test]
    fn default_config() {
        let config: Config = Config::default("some_host");
        assert_eq!(whoami::username(), config.user());
        assert_eq!("some_host", config.host_name);
        assert_eq!(22, config.port());
        assert_eq!(None, config.host_config.identity_file);
        assert_eq!(None, config.host_config.proxy_command);
        assert_eq!(None, config.host_config.proxy_jump);
        assert_eq!(None, config.host_config.add_keys_to_agent);
        assert_eq!(None, config.host_config.user_known_hosts_file);
        assert_eq!(None, config.host_config.strict_host_key_checking);
    }

    #[test]
    fn basic_config() {
        let value = r"#
Host test_host
  IdentityFile '~/.ssh/id_ed25519'
  User trinity
  Hostname foo.com
  Port 23
  AddKeysToAgent confirm
  UserKnownHostsFile /some/special/host_file
  StrictHostKeyChecking no
#";
        let identity_file = PathBuf::from(format!(
            "{}{}",
            home::home_dir().expect("homedir").to_str().expect("to_str"),
            "/.ssh/id_ed25519"
        ));
        let config = parse(value, "test_host").expect("parse");
        assert_eq!("trinity", config.user());
        assert_eq!("foo.com", config.host());
        assert_eq!(23, config.port());
        assert_eq!(Some(vec![identity_file,]), config.host_config.identity_file);
        assert_eq!(None, config.host_config.proxy_command);
        assert_eq!(None, config.host_config.proxy_jump);
        assert_eq!(
            Some(AddKeysToAgent::Confirm),
            config.host_config.add_keys_to_agent
        );
        assert_eq!(
            Some(Path::new("/some/special/host_file")),
            config.host_config.user_known_hosts_file.as_deref()
        );
        assert_eq!(Some(false), config.host_config.strict_host_key_checking);
    }

    #[test]
    fn multiple_patterns() {
        let config = parse(
            r#"
Host a.test_host
    Port 42
    IdentityFile '/path/to/id_ed25519'
Host b.test_host
    User invalid
Host *.test_host
    Hostname foo.com
Host *.test_host !a.test_host
    User invalid
Host *
    User trinity
    Hostname invalid
    IdentityFile '/path/to/id_rsa'
        "#,
            "a.test_host",
        )
        .expect("config is valid");

        assert_eq!("trinity", config.user());
        assert_eq!("foo.com", config.host());
        assert_eq!(42, config.port());
        assert_eq!(
            Some(vec![
                PathBuf::from("/path/to/id_ed25519"),
                PathBuf::from("/path/to/id_rsa")
            ]),
            config.host_config.identity_file
        )
    }

    #[test]
    fn empty_ssh_config() {
        let ssh_config = parse("\n\n\n", "test_host").expect("parse");
        assert_eq!(ssh_config.host(), "test_host");
        assert_eq!(ssh_config.port(), 22);
    }

    #[test]
    fn malformed() {
        assert!(matches!(
            parse("Hostname foo.com", "malformed"),
            Err(Error::HostNotFound)
        ));
        assert!(matches!(
            parse("Hostname foo.com\nHost foo", "malformed"),
            Err(Error::HostNotFound)
        ))
    }

    #[test]
    fn is_clone() {
        let config: Config = Config::default("some_host");
        let _ = config.clone();
    }

    #[test]
    fn comment_handling() {
        const CONFIG: &str = r#"
# top of the config file
Host a.test_host
    # indented comment
    User a
    # indented comment between parameters
    Hostname alias_of_a
# middle of the config file
Host b.test_host
    # multiple line
    # indented comment
    User b
    # multiple line
    # indented comment between parameters
    Hostname alias_of_b
# end of the config file
    "#;
        let config = parse(CONFIG, "a.test_host").expect("config is invalid");
        assert_eq!("a", config.user());
        assert_eq!("alias_of_a", config.host());

        let config = parse(CONFIG, "b.test_host").expect("config is invalid");
        assert_eq!("b", config.user());
        assert_eq!("alias_of_b", config.host());
    }
}
