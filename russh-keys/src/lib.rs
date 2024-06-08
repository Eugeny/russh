#![deny(trivial_casts, unstable_features, unused_import_braces)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! This crate contains methods to deal with SSH keys, as defined in
//! crate Russh. This includes in particular various functions for
//! opening key files, deciphering encrypted keys, and dealing with
//! agents.
//!
//! The following example shows how to do all these in a single example:
//! start and SSH agent server, connect to it with a client, decipher
//! an encrypted private key (the password is `b"blabla"`), send it to
//! the agent, and ask the agent to sign a piece of data
//! (`b"Please sign this"`, below).
//!
//!```
//! use russh_keys::*;
//! use futures::Future;
//!
//! #[derive(Clone)]
//! struct X{}
//! impl agent::server::Agent for X {
//!     fn confirm(self, _: std::sync::Arc<key::KeyPair>) -> Box<dyn Future<Output = (Self, bool)> + Send + Unpin> {
//!         Box::new(futures::future::ready((self, true)))
//!     }
//! }
//!
//! const PKCS8_ENCRYPTED: &'static str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQITo1O0b8YrS0CAggA\nMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBtLH4T1KOfo1GGr7salhR8BIIE\n0KN9ednYwcTGSX3hg7fROhTw7JAJ1D4IdT1fsoGeNu2BFuIgF3cthGHe6S5zceI2\nMpkfwvHbsOlDFWMUIAb/VY8/iYxhNmd5J6NStMYRC9NC0fVzOmrJqE1wITqxtORx\nIkzqkgFUbaaiFFQPepsh5CvQfAgGEWV329SsTOKIgyTj97RxfZIKA+TR5J5g2dJY\nj346SvHhSxJ4Jc0asccgMb0HGh9UUDzDSql0OIdbnZW5KzYJPOx+aDqnpbz7UzY/\nP8N0w/pEiGmkdkNyvGsdttcjFpOWlLnLDhtLx8dDwi/sbEYHtpMzsYC9jPn3hnds\nTcotqjoSZ31O6rJD4z18FOQb4iZs3MohwEdDd9XKblTfYKM62aQJWH6cVQcg+1C7\njX9l2wmyK26Tkkl5Qg/qSfzrCveke5muZgZkFwL0GCcgPJ8RixSB4GOdSMa/hAMU\nkvFAtoV2GluIgmSe1pG5cNMhurxM1dPPf4WnD+9hkFFSsMkTAuxDZIdDk3FA8zof\nYhv0ZTfvT6V+vgH3Hv7Tqcxomy5Qr3tj5vvAqqDU6k7fC4FvkxDh2mG5ovWvc4Nb\nXv8sed0LGpYitIOMldu6650LoZAqJVv5N4cAA2Edqldf7S2Iz1QnA/usXkQd4tLa\nZ80+sDNv9eCVkfaJ6kOVLk/ghLdXWJYRLenfQZtVUXrPkaPpNXgD0dlaTN8KuvML\nUw/UGa+4ybnPsdVflI0YkJKbxouhp4iB4S5ACAwqHVmsH5GRnujf10qLoS7RjDAl\no/wSHxdT9BECp7TT8ID65u2mlJvH13iJbktPczGXt07nBiBse6OxsClfBtHkRLzE\nQF6UMEXsJnIIMRfrZQnduC8FUOkfPOSXc8r9SeZ3GhfbV/DmWZvFPCpjzKYPsM5+\nN8Bw/iZ7NIH4xzNOgwdp5BzjH9hRtCt4sUKVVlWfEDtTnkHNOusQGKu7HkBF87YZ\nRN/Nd3gvHob668JOcGchcOzcsqsgzhGMD8+G9T9oZkFCYtwUXQU2XjMN0R4VtQgZ\nrAxWyQau9xXMGyDC67gQ5xSn+oqMK0HmoW8jh2LG/cUowHFAkUxdzGadnjGhMOI2\nzwNJPIjF93eDF/+zW5E1l0iGdiYyHkJbWSvcCuvTwma9FIDB45vOh5mSR+YjjSM5\nnq3THSWNi7Cxqz12Q1+i9pz92T2myYKBBtu1WDh+2KOn5DUkfEadY5SsIu/Rb7ub\n5FBihk2RN3y/iZk+36I69HgGg1OElYjps3D+A9AjVby10zxxLAz8U28YqJZm4wA/\nT0HLxBiVw+rsHmLP79KvsT2+b4Diqih+VTXouPWC/W+lELYKSlqnJCat77IxgM9e\nYIhzD47OgWl33GJ/R10+RDoDvY4koYE+V5NLglEhbwjloo9Ryv5ywBJNS7mfXMsK\n/uf+l2AscZTZ1mhtL38efTQCIRjyFHc3V31DI0UdETADi+/Omz+bXu0D5VvX+7c6\nb1iVZKpJw8KUjzeUV8yOZhvGu3LrQbhkTPVYL555iP1KN0Eya88ra+FUKMwLgjYr\nJkUx4iad4dTsGPodwEP/Y9oX/Qk3ZQr+REZ8lg6IBoKKqqrQeBJ9gkm1jfKE6Xkc\nCog3JMeTrb3LiPHgN6gU2P30MRp6L1j1J/MtlOAr5rux\n-----END ENCRYPTED PRIVATE KEY-----\n";
//!
//! #[cfg(unix)]
//! fn main() {
//!    env_logger::try_init().unwrap_or(());
//!    let dir = tempdir::TempDir::new("russh").unwrap();
//!    let agent_path = dir.path().join("agent");
//!
//!    let mut core = tokio::runtime::Runtime::new().unwrap();
//!    let agent_path_ = agent_path.clone();
//!    // Starting a server
//!    core.spawn(async move {
//!        let mut listener = tokio::net::UnixListener::bind(&agent_path_)
//!            .unwrap();
//!        russh_keys::agent::server::serve(tokio_stream::wrappers::UnixListenerStream::new(listener), X {}).await
//!    });
//!    let key = decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
//!    let public = key.clone_public_key().unwrap();
//!    core.block_on(async move {
//!        let stream = tokio::net::UnixStream::connect(&agent_path).await?;
//!        let mut client = agent::client::AgentClient::connect(stream);
//!        client.add_identity(&key, &[agent::Constraint::KeyLifetime { seconds: 60 }]).await?;
//!        client.request_identities().await?;
//!        let buf = b"signed message";
//!        let sig = client.sign_request(&public, russh_cryptovec::CryptoVec::from_slice(&buf[..])).await.1.unwrap();
//!        // Here, `sig` is encoded in a format usable internally by the SSH protocol.
//!        Ok::<(), Error>(())
//!    }).unwrap()
//! }
//!
//! #[cfg(not(unix))]
//! fn main() {}
//!
//! ```

use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use aes::cipher::block_padding::UnpadError;
use aes::cipher::inout::PadError;
use byteorder::{BigEndian, WriteBytesExt};
use data_encoding::BASE64_MIME;
use hmac::{Hmac, Mac};
use log::debug;
use sha1::Sha1;
use ssh_key::Certificate;
use thiserror::Error;

pub mod ec;
pub mod encoding;
pub mod key;
pub mod protocol;
pub mod signature;

mod format;
pub use format::*;

#[cfg(feature = "openssl")]
#[path = "backend_openssl.rs"]
mod backend;
#[cfg(not(feature = "openssl"))]
#[path = "backend_rust.rs"]
mod backend;

/// A module to write SSH agent.
pub mod agent;

#[derive(Debug, Error)]
pub enum Error {
    /// The key could not be read, for an unknown reason
    #[error("Could not read key")]
    CouldNotReadKey,
    /// The type of the key is unsupported
    #[error("Unsupported key type {}", key_type_string)]
    UnsupportedKeyType {
        key_type_string: String,
        key_type_raw: Vec<u8>,
    },
    /// The type of the key is unsupported
    #[error("Invalid Ed25519 key data")]
    Ed25519KeyError(#[from] ed25519_dalek::SignatureError),
    /// The type of the key is unsupported
    #[error("Invalid ECDSA key data")]
    EcdsaKeyError(#[from] p256::elliptic_curve::Error),
    /// The key is encrypted (should supply a password?)
    #[error("The key is encrypted")]
    KeyIsEncrypted,
    /// The key contents are inconsistent
    #[error("The key is corrupt")]
    KeyIsCorrupt,
    /// Home directory could not be found
    #[error("No home directory found")]
    NoHomeDir,
    /// The server key has changed
    #[error("The server key changed at line {}", line)]
    KeyChanged { line: usize },
    /// The key uses an unsupported algorithm
    #[error("Unknown key algorithm: {0}")]
    UnknownAlgorithm(::pkcs8::ObjectIdentifier),
    /// Index out of bounds
    #[error("Index out of bounds")]
    IndexOutOfBounds,
    /// Unknown signature type
    #[error("Unknown signature type: {}", sig_type)]
    UnknownSignatureType { sig_type: String },
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid parameters")]
    InvalidParameters,
    /// Agent protocol error
    #[error("Agent protocol error")]
    AgentProtocolError,
    #[error("Agent failure")]
    AgentFailure,
    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[cfg(feature = "openssl")]
    #[error(transparent)]
    Openssl(#[from] openssl::error::ErrorStack),

    #[cfg(not(feature = "openssl"))]
    #[error("Rsa: {0}")]
    Rsa(#[from] rsa::Error),

    #[error(transparent)]
    Pad(#[from] PadError),

    #[error(transparent)]
    Unpad(#[from] UnpadError),

    #[error("Base64 decoding error: {0}")]
    Decode(#[from] data_encoding::DecodeError),
    #[error("Der: {0}")]
    Der(#[from] der::Error),
    #[error("Spki: {0}")]
    Spki(#[from] spki::Error),
    #[error("Pkcs1: {0}")]
    Pkcs1(#[from] pkcs1::Error),
    #[error("Pkcs8: {0}")]
    Pkcs8(#[from] ::pkcs8::Error),
    #[error("Sec1: {0}")]
    Sec1(#[from] sec1::Error),

    #[error("SshKey: {0}")]
    SshKey(#[from] ssh_key::Error),
    #[error("SshEncoding: {0}")]
    SshEncoding(#[from] ssh_encoding::Error),

    #[error("Environment variable `{0}` not found")]
    EnvVar(&'static str),
    #[error(
        "Unable to connect to ssh-agent. The environment variable `SSH_AUTH_SOCK` was set, but it \
         points to a nonexistent file or directory."
    )]
    BadAuthSock,
}

const KEYTYPE_ECDSA_SHA2_NISTP256: &[u8] = ECDSA_SHA2_NISTP256.as_bytes();
const KEYTYPE_ECDSA_SHA2_NISTP384: &[u8] = ECDSA_SHA2_NISTP384.as_bytes();
const KEYTYPE_ECDSA_SHA2_NISTP521: &[u8] = ECDSA_SHA2_NISTP521.as_bytes();

const ECDSA_SHA2_NISTP256: &str = "ecdsa-sha2-nistp256";
const ECDSA_SHA2_NISTP384: &str = "ecdsa-sha2-nistp384";
const ECDSA_SHA2_NISTP521: &str = "ecdsa-sha2-nistp521";

/// Load a public key from a file. Ed25519, EC-DSA and RSA keys are supported.
///
/// ```
/// russh_keys::load_public_key("../files/id_ed25519.pub").unwrap();
/// ```
pub fn load_public_key<P: AsRef<Path>>(path: P) -> Result<key::PublicKey, Error> {
    let mut pubkey = String::new();
    let mut file = File::open(path.as_ref())?;
    file.read_to_string(&mut pubkey)?;

    let mut split = pubkey.split_whitespace();
    match (split.next(), split.next()) {
        (Some(_), Some(key)) => parse_public_key_base64(key),
        (Some(key), None) => parse_public_key_base64(key),
        _ => Err(Error::CouldNotReadKey),
    }
}

/// Reads a public key from the standard encoding. In some cases, the
/// encoding is prefixed with a key type identifier and a space (such
/// as `ssh-ed25519 AAAAC3N...`).
///
/// ```
/// russh_keys::parse_public_key_base64("AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ").is_ok();
/// ```
pub fn parse_public_key_base64(key: &str) -> Result<key::PublicKey, Error> {
    let base = BASE64_MIME.decode(key.as_bytes())?;
    key::parse_public_key(&base, None)
}

pub trait PublicKeyBase64 {
    /// Create the base64 part of the public key blob.
    fn public_key_bytes(&self) -> Vec<u8>;
    fn public_key_base64(&self) -> String {
        let mut s = BASE64_MIME.encode(&self.public_key_bytes());
        assert_eq!(s.pop(), Some('\n'));
        assert_eq!(s.pop(), Some('\r'));
        s.replace("\r\n", "")
    }
}

impl PublicKeyBase64 for key::PublicKey {
    fn public_key_bytes(&self) -> Vec<u8> {
        let mut s = Vec::new();
        match *self {
            key::PublicKey::Ed25519(ref publickey) => {
                let name = b"ssh-ed25519";
                #[allow(clippy::unwrap_used)] // Vec<>.write can't fail
                s.write_u32::<BigEndian>(name.len() as u32).unwrap();
                s.extend_from_slice(name);
                #[allow(clippy::unwrap_used)] // Vec<>.write can't fail
                s.write_u32::<BigEndian>(publickey.as_bytes().len() as u32)
                    .unwrap();
                s.extend_from_slice(publickey.as_bytes());
            }
            key::PublicKey::RSA { ref key, .. } => {
                use encoding::Encoding;
                let name = b"ssh-rsa";
                #[allow(clippy::unwrap_used)] // Vec<>.write_all can't fail
                s.write_u32::<BigEndian>(name.len() as u32).unwrap();
                s.extend_from_slice(name);
                s.extend_ssh(&protocol::RsaPublicKey::from(key));
            }
            key::PublicKey::EC { ref key } => {
                write_ec_public_key(&mut s, key);
            }
        }
        s
    }
}

impl PublicKeyBase64 for key::KeyPair {
    fn public_key_bytes(&self) -> Vec<u8> {
        let name = self.name().as_bytes();
        let mut s = Vec::new();
        #[allow(clippy::unwrap_used)] // Vec<>.write_all can't fail
        s.write_u32::<BigEndian>(name.len() as u32).unwrap();
        s.extend_from_slice(name);
        match *self {
            key::KeyPair::Ed25519(ref key) => {
                let public = key.verifying_key().to_bytes();
                #[allow(clippy::unwrap_used)] // Vec<>.write can't fail
                s.write_u32::<BigEndian>(public.len() as u32).unwrap();
                s.extend_from_slice(public.as_slice());
            }
            key::KeyPair::RSA { ref key, .. } => {
                use encoding::Encoding;
                s.extend_ssh(&protocol::RsaPublicKey::from(key));
            }
            key::KeyPair::EC { ref key } => {
                write_ec_public_key(&mut s, &key.to_public_key());
            }
        }
        s
    }
}

fn write_ec_public_key(buf: &mut Vec<u8>, key: &ec::PublicKey) {
    let algorithm = key.algorithm().as_bytes();
    let ident = key.ident().as_bytes();
    let q = key.to_sec1_bytes();

    use encoding::Encoding;
    buf.extend_ssh_string(algorithm);
    buf.extend_ssh_string(ident);
    buf.extend_ssh_string(&q);
}

/// Write a public key onto the provided `Write`, encoded in base-64.
pub fn write_public_key_base64<W: Write>(
    mut w: W,
    publickey: &key::PublicKey,
) -> Result<(), Error> {
    let pk = publickey.public_key_base64();
    writeln!(w, "{} {}", publickey.name(), pk)?;
    Ok(())
}

/// Load a secret key, deciphering it with the supplied password if necessary.
pub fn load_secret_key<P: AsRef<Path>>(
    secret_: P,
    password: Option<&str>,
) -> Result<key::KeyPair, Error> {
    let mut secret_file = std::fs::File::open(secret_)?;
    let mut secret = String::new();
    secret_file.read_to_string(&mut secret)?;
    decode_secret_key(&secret, password)
}

/// Load a openssh certificate
pub fn load_openssh_certificate<P: AsRef<Path>>(cert_: P) -> Result<Certificate, ssh_key::Error> {
    let mut cert_file = std::fs::File::open(cert_)?;
    let mut cert = String::new();
    cert_file.read_to_string(&mut cert)?;

    Certificate::from_openssh(&cert)
}

fn is_base64_char(c: char) -> bool {
    c.is_ascii_lowercase()
        || c.is_ascii_uppercase()
        || c.is_ascii_digit()
        || c == '/'
        || c == '+'
        || c == '='
}

/// Record a host's public key into the user's known_hosts file.
pub fn learn_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<(), Error> {
    learn_known_hosts_path(host, port, pubkey, known_hosts_path()?)
}

/// Record a host's public key into a nonstandard location.
pub fn learn_known_hosts_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    pubkey: &key::PublicKey,
    path: P,
) -> Result<(), Error> {
    if let Some(parent) = path.as_ref().parent() {
        std::fs::create_dir_all(parent)?
    }
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(path)?;

    // Test whether the known_hosts file ends with a \n
    let mut buf = [0; 1];
    let mut ends_in_newline = false;
    if file.seek(SeekFrom::End(-1)).is_ok() {
        file.read_exact(&mut buf)?;
        ends_in_newline = buf[0] == b'\n';
    }

    // Write the key.
    file.seek(SeekFrom::End(0))?;
    let mut file = std::io::BufWriter::new(file);
    if !ends_in_newline {
        file.write_all(b"\n")?;
    }
    if port != 22 {
        write!(file, "[{}]:{} ", host, port)?
    } else {
        write!(file, "{} ", host)?
    }
    write_public_key_base64(&mut file, pubkey)?;
    file.write_all(b"\n")?;
    Ok(())
}

/// Get the server key that matches the one recorded in the user's known_hosts file.
pub fn known_host_keys(host: &str, port: u16) -> Result<Vec<(usize, key::PublicKey)>, Error> {
    known_host_keys_path(host, port, known_hosts_path()?)
}

/// Get the server key that matches the one recorded in `path`.
pub fn known_host_keys_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    path: P,
) -> Result<Vec<(usize, key::PublicKey)>, Error> {
    let mut f = if let Ok(f) = File::open(path) {
        BufReader::new(f)
    } else {
        return Ok(vec![]);
    };
    let mut buffer = String::new();

    let host_port = if port == 22 {
        Cow::Borrowed(host)
    } else {
        Cow::Owned(format!("[{}]:{}", host, port))
    };
    debug!("host_port = {:?}", host_port);
    let mut line = 1;
    let mut matches = vec![];
    while f.read_line(&mut buffer)? > 0 {
        {
            if buffer.as_bytes().first() == Some(&b'#') {
                buffer.clear();
                continue;
            }
            debug!("line = {:?}", buffer);
            let mut s = buffer.split(' ');
            let hosts = s.next();
            let _ = s.next();
            let key = s.next();
            if let (Some(h), Some(k)) = (hosts, key) {
                debug!("{:?} {:?}", h, k);
                if match_hostname(&host_port, h) {
                    matches.push((line, parse_public_key_base64(k)?));
                }
            }
        }
        buffer.clear();
        line += 1;
    }
    Ok(matches)
}

fn match_hostname(host: &str, pattern: &str) -> bool {
    for entry in pattern.split(',') {
        if entry.starts_with("|1|") {
            let mut parts = entry.split('|').skip(2);
            let Some(Ok(salt)) = parts.next().map(|p| BASE64_MIME.decode(p.as_bytes())) else {
                continue;
            };
            let Some(Ok(hash)) = parts.next().map(|p| BASE64_MIME.decode(p.as_bytes())) else {
                continue;
            };
            if let Ok(hmac) = Hmac::<Sha1>::new_from_slice(&salt) {
                if hmac.chain_update(host).verify_slice(&hash).is_ok() {
                    return true;
                }
            }
        } else if host == entry {
            return true;
        }
    }
    false
}

/// Check whether the host is known, from its standard location.
pub fn check_known_hosts(host: &str, port: u16, pubkey: &key::PublicKey) -> Result<bool, Error> {
    check_known_hosts_path(host, port, pubkey, known_hosts_path()?)
}

/// Check that a server key matches the one recorded in file `path`.
pub fn check_known_hosts_path<P: AsRef<Path>>(
    host: &str,
    port: u16,
    pubkey: &key::PublicKey,
    path: P,
) -> Result<bool, Error> {
    let check = known_host_keys_path(host, port, path)?
        .into_iter()
        .map(
            |(line, recorded)| match (pubkey.name() == recorded.name(), *pubkey == recorded) {
                (true, true) => Ok(true),
                (true, false) => Err(Error::KeyChanged { line }),
                _ => Ok(false),
            },
        )
        // If any Err was returned, we stop here
        .collect::<Result<Vec<bool>, Error>>()?
        .into_iter()
        // Now we check the results for a match
        .any(|x| x);

    Ok(check)
}

#[cfg(target_os = "windows")]
fn known_hosts_path() -> Result<PathBuf, Error> {
    if let Some(home_dir) = dirs::home_dir() {
        Ok(home_dir.join("ssh").join("known_hosts"))
    } else {
        Err(Error::NoHomeDir)
    }
}

#[cfg(not(target_os = "windows"))]
fn known_hosts_path() -> Result<PathBuf, Error> {
    if let Some(home_dir) = dirs::home_dir() {
        Ok(home_dir.join(".ssh").join("known_hosts"))
    } else {
        Err(Error::NoHomeDir)
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Write;

    #[cfg(unix)]
    use futures::Future;

    use super::*;

    const ED25519_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABDLGyfA39
J2FcJygtYqi5ISAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIN+Wjn4+4Fcvl2Jl
KpggT+wCRxpSvtqqpVrQrKN1/A22AAAAkOHDLnYZvYS6H9Q3S3Nk4ri3R2jAZlQlBbUos5
FkHpYgNw65KCWCTXtP7ye2czMC3zjn2r98pJLobsLYQgRiHIv/CUdAdsqbvMPECB+wl/UQ
e+JpiSq66Z6GIt0801skPh20jxOO3F52SoX1IeO5D5PXfZrfSZlw6S8c7bwyp2FHxDewRx
7/wNsnDM0T7nLv/Q==
-----END OPENSSH PRIVATE KEY-----";

    // password is 'test'
    const ED25519_AESCTR_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD1phlku5
A2G7Q9iP+DcOc9AAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIHeLC1lWiCYrXsf/
85O/pkbUFZ6OGIt49PX3nw8iRoXEAAAAkKRF0st5ZI7xxo9g6A4m4l6NarkQre3mycqNXQ
dP3jryYgvsCIBAA5jMWSjrmnOTXhidqcOy4xYCrAttzSnZ/cUadfBenL+DQq6neffw7j8r
0tbCxVGp6yCQlKrgSZf6c0Hy7dNEIU2bJFGxLe6/kWChcUAt/5Ll5rI7DVQPJdLgehLzvv
sJWR7W+cGvJ/vLsw==
-----END OPENSSH PRIVATE KEY-----";

    const RSA_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAuSvQ9m76zhRB4m0BUKPf17lwccj7KQ1Qtse63AOqP/VYItqEH8un
rxPogXNBgrcCEm/ccLZZsyE3qgp3DRQkkqvJhZ6O8VBPsXxjZesRCqoFNCczy+Mf0R/Qmv
Rnpu5+4DDLz0p7vrsRZW9ji/c98KzxeUonWgkplQaCBYLN875WdeUYMGtb1MLfNCEj177j
gZl3CzttLRK3su6dckowXcXYv1gPTPZAwJb49J43o1QhV7+1zdwXvuFM6zuYHdu9ZHSKir
6k1dXOET3/U+LWG5ofAo8oxUWv/7vs6h7MeajwkUeIBOWYtD+wGYRvVpxvj7nyOoWtg+jm
0X6ndnsD+QAAA8irV+ZAq1fmQAAAAAdzc2gtcnNhAAABAQC5K9D2bvrOFEHibQFQo9/XuX
BxyPspDVC2x7rcA6o/9Vgi2oQfy6evE+iBc0GCtwISb9xwtlmzITeqCncNFCSSq8mFno7x
UE+xfGNl6xEKqgU0JzPL4x/RH9Ca9Gem7n7gMMvPSnu+uxFlb2OL9z3wrPF5SidaCSmVBo
IFgs3zvlZ15Rgwa1vUwt80ISPXvuOBmXcLO20tErey7p1ySjBdxdi/WA9M9kDAlvj0njej
VCFXv7XN3Be+4UzrO5gd271kdIqKvqTV1c4RPf9T4tYbmh8CjyjFRa//u+zqHsx5qPCRR4
gE5Zi0P7AZhG9WnG+PufI6ha2D6ObRfqd2ewP5AAAAAwEAAQAAAQAdELqhI/RsSpO45eFR
9hcZtnrm8WQzImrr9dfn1w9vMKSf++rHTuFIQvi48Q10ZiOGH1bbvlPAIVOqdjAPtnyzJR
HhzmyjhjasJlk30zj+kod0kz63HzSMT9EfsYNfmYoCyMYFCKz52EU3xc87Vhi74XmZz0D0
CgIj6TyZftmzC4YJCiwwU8K+29nxBhcbFRxpgwAksFL6PCSQsPl4y7yvXGcX+7lpZD8547
v58q3jIkH1g2tBOusIuaiphDDStVJhVdKA55Z0Kju2kvCqsRIlf1efrq43blRgJFFFCxNZ
8Cpolt4lOHhg+o3ucjILlCOgjDV8dB21YLxmgN5q+xFNAAAAgQC1P+eLUkHDFXnleCEVrW
xL/DFxEyneLQz3IawGdw7cyAb7vxsYrGUvbVUFkxeiv397pDHLZ5U+t5cOYDBZ7G43Mt2g
YfWBuRNvYhHA9Sdf38m5qPA6XCvm51f+FxInwd/kwRKH01RHJuRGsl/4Apu4DqVob8y00V
WTYyV6JBNDkQAAAIEA322lj7ZJXfK/oLhMM/RS+DvaMea1g/q43mdRJFQQso4XRCL6IIVn
oZXFeOxrMIRByVZBw+FSeB6OayWcZMySpJQBo70GdJOc3pJb3js0T+P2XA9+/jwXS58K9a
+IkgLkv9XkfxNGNKyPEEzXC8QQzvjs1LbmO59VLko8ypwHq/cAAACBANQqaULI0qdwa0vm
d3Ae1+k3YLZ0kapSQGVIMT2lkrhKV35tj7HIFpUPa4vitHzcUwtjYhqFezVF+JyPbJ/Fsp
XmEc0g1fFnQp5/SkUwoN2zm8Up52GBelkq2Jk57mOMzWO0QzzNuNV/feJk02b2aE8rrAqP
QR+u0AypRPmzHnOPAAAAEXJvb3RAMTQwOTExNTQ5NDBkAQ==
-----END OPENSSH PRIVATE KEY-----";

    #[test]
    fn test_decode_ed25519_secret_key() {
        env_logger::try_init().unwrap_or(());
        decode_secret_key(ED25519_KEY, Some("blabla")).unwrap();
    }

    #[test]
    fn test_decode_ed25519_aesctr_secret_key() {
        env_logger::try_init().unwrap_or(());
        decode_secret_key(ED25519_AESCTR_KEY, Some("test")).unwrap();
    }

    // Key from RFC 8410 Section 10.3. This is a key using PrivateKeyInfo structure.
    const RFC8410_ED25519_PRIVATE_ONLY_KEY: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----";

    #[test]
    fn test_decode_rfc8410_ed25519_private_only_key() {
        env_logger::try_init().unwrap_or(());
        assert!(matches!(
            decode_secret_key(RFC8410_ED25519_PRIVATE_ONLY_KEY, None),
            Ok(key::KeyPair::Ed25519 { .. })
        ));
        // We always encode public key, skip test_decode_encode_symmetry.
    }

    // Key from RFC 8410 Section 10.3. This is a key using OneAsymmetricKey structure.
    const RFC8410_ED25519_PRIVATE_PUBLIC_KEY: &str = "-----BEGIN PRIVATE KEY-----
MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
oB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrB
Z9w7lshQhqowtrbLDFw4rXAxZuE=
-----END PRIVATE KEY-----";

    #[test]
    fn test_decode_rfc8410_ed25519_private_public_key() {
        env_logger::try_init().unwrap_or(());
        assert!(matches!(
            decode_secret_key(RFC8410_ED25519_PRIVATE_PUBLIC_KEY, None),
            Ok(key::KeyPair::Ed25519 { .. })
        ));
        // We can't encode attributes, skip test_decode_encode_symmetry.
    }

    #[test]
    fn test_decode_rsa_secret_key() {
        env_logger::try_init().unwrap_or(());
        decode_secret_key(RSA_KEY, None).unwrap();
    }

    #[test]
    fn test_decode_openssh_p256_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 256 -m rfc4716 -f $file
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQ/i+HCsmZZPy0JhtT64vW7EmeA1DeA
M/VnPq3vAhu+xooJ7IMMK3lUHlBDosyvA2enNbCWyvNQc25dVt4oh9RhAAAAqHG7WMFxu1
jBAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD+L4cKyZlk/LQmG
1Pri9bsSZ4DUN4Az9Wc+re8CG77GignsgwwreVQeUEOizK8DZ6c1sJbK81Bzbl1W3iiH1G
EAAAAgLAmXR6IlN0SdiD6o8qr+vUr0mXLbajs/m0UlegElOmoAAAANcm9iZXJ0QGJic2Rl
dgECAw==
-----END OPENSSH PRIVATE KEY-----
";
        assert!(matches!(
            decode_secret_key(key, None),
            Ok(key::KeyPair::EC {
                key: ec::PrivateKey::P256(_),
            })
        ));
    }

    #[test]
    fn test_decode_openssh_p384_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 384 -m rfc4716 -f $file
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQTkLnKPk/1NZD9mQ8XoebD7ASv9/svh
5jO75HF7RYAqKK3fl5wsHe4VTJAOT3qH841yTcK79l0dwhHhHeg60byL7F9xOEzr2kqGeY
Uwrl7fVaL7hfHzt6z+sG8smSQ3tF8AAADYHjjBch44wXIAAAATZWNkc2Etc2hhMi1uaXN0
cDM4NAAAAAhuaXN0cDM4NAAAAGEE5C5yj5P9TWQ/ZkPF6Hmw+wEr/f7L4eYzu+Rxe0WAKi
it35ecLB3uFUyQDk96h/ONck3Cu/ZdHcIR4R3oOtG8i+xfcThM69pKhnmFMK5e31Wi+4Xx
87es/rBvLJkkN7RfAAAAMFzt6053dxaQT0Ta/CGfZna0nibHzxa55zgBmje/Ho3QDNlBCH
Ylv0h4Wyzto8NfLQAAAA1yb2JlcnRAYmJzZGV2AQID
-----END OPENSSH PRIVATE KEY-----
";
        assert!(matches!(
            decode_secret_key(key, None),
            Ok(key::KeyPair::EC {
                key: ec::PrivateKey::P384(_),
            })
        ));
    }

    #[test]
    fn test_decode_openssh_p521_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 521 -m rfc4716 -f $file
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQA7a9awmFeDjzYiuUOwMfXkKTevfQI
iGlduu8BkjBOWXpffJpKsdTyJI/xI05l34OvqfCCkPUcfFWHK+LVRGahMBgBcGB9ZZOEEq
iKNIT6C9WcJTGDqcBSzQ2yTSOxPXfUmVTr4D76vbYu5bjd9aBKx8HdfMvPeo0WD0ds/LjX
LdJoDXcAAAEQ9fxlIfX8ZSEAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
AAAIUEAO2vWsJhXg482IrlDsDH15Ck3r30CIhpXbrvAZIwTll6X3yaSrHU8iSP8SNOZd+D
r6nwgpD1HHxVhyvi1URmoTAYAXBgfWWThBKoijSE+gvVnCUxg6nAUs0Nsk0jsT131JlU6+
A++r22LuW43fWgSsfB3XzLz3qNFg9HbPy41y3SaA13AAAAQgH4DaftY0e/KsN695VJ06wy
Ve0k2ddxoEsSE15H4lgNHM2iuYKzIqZJOReHRCTff6QGgMYPDqDfFfL1Hc1Ntql0pwAAAA
1yb2JlcnRAYmJzZGV2AQIDBAU=
-----END OPENSSH PRIVATE KEY-----
";
        assert!(matches!(
            decode_secret_key(key, None),
            Ok(key::KeyPair::EC {
                key: ec::PrivateKey::P521(_),
            })
        ));
    }

    #[test]
    fn test_fingerprint() {
        let key = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAILagOJFgwaMNhBWQINinKOXmqS4Gh5NgxgriXwdOoINJ",
        )
        .unwrap();
        assert_eq!(
            key.fingerprint(),
            "ldyiXa1JQakitNU5tErauu8DvWQ1dZ7aXu+rm7KQuog"
        );
    }

    #[test]
    fn test_check_known_hosts() {
        env_logger::try_init().unwrap_or(());
        let dir = tempdir::TempDir::new("russh").unwrap();
        let path = dir.path().join("known_hosts");
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(b"[localhost]:13265 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ\n").unwrap();
            f.write_all(b"#pijul.org,37.120.161.53 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X\n").unwrap();
            f.write_all(b"pijul.org,37.120.161.53 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X\n").unwrap();
            f.write_all(b"|1|O33ESRMWPVkMYIwJ1Uw+n877jTo=|nuuC5vEqXlEZ/8BXQR7m619W6Ak= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF\n").unwrap();
        }

        // Valid key, non-standard port.
        let host = "localhost";
        let port = 13265;
        let hostkey = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ",
        )
        .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).unwrap());

        // Valid key, hashed.
        let host = "example.com";
        let port = 22;
        let hostkey = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAILIG2T/B0l0gaqj3puu510tu9N1OkQ4znY3LYuEm5zCF",
        )
        .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).unwrap());

        // Valid key, several hosts, port 22
        let host = "pijul.org";
        let port = 22;
        let hostkey = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G1sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X",
        )
        .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).unwrap());

        // Now with the key in a comment above, check that it's not recognized
        let host = "pijul.org";
        let port = 22;
        let hostkey = parse_public_key_base64(
            "AAAAC3NzaC1lZDI1NTE5AAAAIA6rWI3G2sz07DnfFlrouTcysQlj2P+jpNSOEWD9OJ3X",
        )
        .unwrap();
        assert!(check_known_hosts_path(host, port, &hostkey, &path).is_err());
    }

    #[test]
    fn test_parse_p256_public_key() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMxBTpMIGvo7CnordO7wP0QQRqpBwUjOLl4eMhfucfE1sjTYyK5wmTl1UqoSDS1PtRVTBdl+0+9pquFb46U7fwg=";

        assert!(matches!(
            parse_public_key_base64(key),
            Ok(key::PublicKey::EC {
                key: ec::PublicKey::P256(_),
            })
        ));
    }

    #[test]
    fn test_parse_p384_public_key() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBBVFgxJxpCaAALZG/S5BHT8/IUQ5mfuKaj7Av9g7Jw59fBEGHfPBz1wFtHGYw5bdLmfVZTIDfogDid5zqJeAKr1AcD06DKTXDzd2EpUjqeLfQ5b3erHuX758fgu/pSDGRA==";

        assert!(matches!(
            parse_public_key_base64(key),
            Ok(key::PublicKey::EC {
                key: ec::PublicKey::P384(_),
            })
        ));
    }

    #[test]
    fn test_parse_p521_public_key() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAAQepXEpOrzlX22r4E5zEHjhHWeZUe//zaevTanOWRBnnaCGWJFGCdjeAbNOuAmLtXc+HZdJTCZGREeSLSrpJa71QDCgZl0N7DkDUanCpHZJe/DCK6qwtHYbEMn28iLMlGCOrCIa060EyJHbp1xcJx4I1SKj/f/fm3DhhID/do6zyf8Cg==";

        assert!(matches!(
            parse_public_key_base64(key),
            Ok(key::PublicKey::EC {
                key: ec::PublicKey::P521(_),
            })
        ));
    }

    #[test]
    fn test_srhb() {
        env_logger::try_init().unwrap_or(());
        let key = "AAAAB3NzaC1yc2EAAAADAQABAAACAQC0Xtz3tSNgbUQAXem4d+d6hMx7S8Nwm/DOO2AWyWCru+n/+jQ7wz2b5+3oG2+7GbWZNGj8HCc6wJSA3jUsgv1N6PImIWclD14qvoqY3Dea1J0CJgXnnM1xKzBz9C6pDHGvdtySg+yzEO41Xt4u7HFn4Zx5SGuI2NBsF5mtMLZXSi33jCIWVIkrJVd7sZaY8jiqeVZBB/UvkLPWewGVuSXZHT84pNw4+S0Rh6P6zdNutK+JbeuO+5Bav4h9iw4t2sdRkEiWg/AdMoSKmo97Gigq2mKdW12ivnXxz3VfxrCgYJj9WwaUUWSfnAju5SiNly0cTEAN4dJ7yB0mfLKope1kRhPsNaOuUmMUqlu/hBDM/luOCzNjyVJ+0LLB7SV5vOiV7xkVd4KbEGKou8eeCR3yjFazUe/D1pjYPssPL8cJhTSuMc+/UC9zD8yeEZhB9V+vW4NMUR+lh5+XeOzenl65lWYd/nBZXLBbpUMf1AOfbz65xluwCxr2D2lj46iApSIpvE63i3LzFkbGl9GdUiuZJLMFJzOWdhGGc97cB5OVyf8umZLqMHjaImxHEHrnPh1MOVpv87HYJtSBEsN4/omINCMZrk++CRYAIRKRpPKFWV7NQHcvw3m7XLR3KaTYe+0/MINIZwGdou9fLUU3zSd521vDjA/weasH0CyDHq7sZw==";

        parse_public_key_base64(key).unwrap();
    }

    #[test]
    fn test_nikao() {
        env_logger::try_init().unwrap_or(());
        let key = "-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAw/FG8YLVoXhsUVZcWaY7iZekMxQ2TAfSVh0LTnRuzsumeLhb
0fh4scIt4C4MLwpGe/u3vj290C28jLkOtysqnIpB4iBUrFNRmEz2YuvjOzkFE8Ju
0l1VrTZ9APhpLZvzT2N7YmTXcLz1yWopCe4KqTHczEP4lfkothxEoACXMaxezt5o
wIYfagDaaH6jXJgJk1SQ5VYrROVpDjjX8/Zg01H1faFQUikYx0M8EwL1fY5B80Hd
6DYSok8kUZGfkZT8HQ54DBgocjSs449CVqkVoQC1aDB+LZpMWovY15q7hFgfQmYD
qulbZRWDxxogS6ui/zUR2IpX7wpQMKKkBS1qdQIDAQABAoIBAQCodpcCKfS2gSzP
uapowY1KvP/FkskkEU18EDiaWWyzi1AzVn5LRo+udT6wEacUAoebLU5K2BaMF+aW
Lr1CKnDWaeA/JIDoMDJk+TaU0i5pyppc5LwXTXvOEpzi6rCzL/O++88nR4AbQ7sm
Uom6KdksotwtGvttJe0ktaUi058qaoFZbels5Fwk5bM5GHDdV6De8uQjSfYV813P
tM/6A5rRVBjC5uY0ocBHxPXkqAdHfJuVk0uApjLrbm6k0M2dg1X5oyhDOf7ZIzAg
QGPgvtsVZkQlyrD1OoCMPwzgULPXTe8SktaP9EGvKdMf5kQOqUstqfyx+E4OZa0A
T82weLjBAoGBAOUChhaLQShL3Vsml/Nuhhw5LsxU7Li34QWM6P5AH0HMtsSncH8X
ULYcUKGbCmmMkVb7GtsrHa4ozy0fjq0Iq9cgufolytlvC0t1vKRsOY6poC2MQgaZ
bqRa05IKwhZdHTr9SUwB/ngtVNWRzzbFKLkn2W5oCpQGStAKqz3LbKstAoGBANsJ
EyrXPbWbG+QWzerCIi6shQl+vzOd3cxqWyWJVaZglCXtlyySV2eKWRW7TcVvaXQr
Nzm/99GNnux3pUCY6szy+9eevjFLLHbd+knzCZWKTZiWZWr503h/ztfFwrMzhoAh
z4nukD/OETugPvtG01c2sxZb/F8LH9KORznhlSlpAoGBAJnqg1J9j3JU4tZTbwcG
fo5ThHeCkINp2owPc70GPbvMqf4sBzjz46QyDaM//9SGzFwocplhNhaKiQvrzMnR
LSVucnCEm/xdXLr/y6S6tEiFCwnx3aJv1uQRw2bBYkcDmBTAjVXPdUcyOHU+BYXr
Jv6ioMlKlel8/SUsNoFWypeVAoGAXhr3Bjf1xlm+0O9PRyZjQ0RR4DN5eHbB/XpQ
cL8hclsaK3V5tuek79JL1f9kOYhVeVi74G7uzTSYbCY3dJp+ftGCjDAirNEMaIGU
cEMgAgSqs/0h06VESwg2WRQZQ57GkbR1E2DQzuj9FG4TwSe700OoC9o3gqon4PHJ
/j9CM8kCgYEAtPJf3xaeqtbiVVzpPAGcuPyajTzU0QHPrXEl8zr/+iSK4Thc1K+c
b9sblB+ssEUQD5IQkhTWcsXdslINQeL77WhIMZ2vBAH8Hcin4jgcLmwUZfpfnnFs
QaChXiDsryJZwsRnruvMRX9nedtqHrgnIsJLTXjppIhGhq5Kg4RQfOU=
-----END RSA PRIVATE KEY-----
";
        decode_secret_key(key, None).unwrap();
    }

    #[test]
    fn test_decode_pkcs8_rsa_secret_key() {
        // Generated using: ssh-keygen -t rsa -b 1024 -m pkcs8 -f $file
        let key = "-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKMR20Sc+tU5dS7C
YzIuWnzobqTrIi9JExPTq4GEj01HJ1RJoOoezuiZuIg3iSRRETjXR+pKSzlLEh4v
9VmaDNQMT08EHYCc7NEKXb3c3k/4RNSHtvxKAsyK2ucrvaJGO5GDP7W+yQXpt8Os
KlD8G5LHZJMrZ5m1a+sHYdGzphRXAgMBAAECgYBSG8CjaMOoL3lApSJbdxmbAVIM
+lRJKOtRNWiLG5soVyaHe1dp6z9VwWk4NXZ5cdRRIZ0VbHk6DQG/b3iDuFyybqu3
M7B40+4N7DCJfoWxALCEDSPQQ/Rp7rQ15YdNahZqe+/c8BHVxHdUZNXvMY8QX8jI
ZmoH8e17tRFKB0SZqQJBANjtPcEo5goaaZlly5VWs8SdNrG/ZM4vKQgpwQmtiNJg
TznqMPBcc8Qk43a6BlPDdn8CrBBjeYRF7qGh0cVdca0CQQDAcTQzF+HfWImqttB0
dCo+jOqKOovXTTJcp4JUMzgvnMHwQZUJRNQxxqkIrmh/gUwWacSK/yxpLgKlXzBz
msaTAkEAk7VPVISVxxFfEE2pR0HnXJy0TmoFqQOhy+YqhH1+acmciNH3iuNZDJkV
rZVTk5vHxwo5wVsKtk+sArEeFmbfbQJAMbUL5qakkSwtYwsVjP70anO7oTi+Jj6q
Y4RhBZ61RJcZARXviRVeOf02bCeglk6veJqZSc3fist3o3+S5El2QQJBAJjjKA9q
bjFFWPDS9kyrpZL1SOjRIM/Mb0K1hCQd/kfbRTCamqvfuPDQ2A9N40bfBiQFQPph
csKph4+a9f37jyE=
-----END PRIVATE KEY-----
";
        assert!(matches!(
            decode_secret_key(key, None),
            Ok(key::KeyPair::RSA { .. })
        ));
        test_decode_encode_symmetry(key);
    }

    #[test]
    fn test_decode_pkcs8_p256_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 256 -m pkcs8 -f $file
        let key = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgE0C7/pyJDcZTAgWo
ydj6EE8QkZ91jtGoGmdYAVd7LaqhRANCAATWkGOof7R/PAUuOr2+ZPUgB8rGVvgr
qa92U3p4fkJToKXku5eq/32OBj23YMtz76jO3yfMbtG3l1JWLowPA8tV
-----END PRIVATE KEY-----
";
        assert!(matches!(
            decode_secret_key(key, None),
            Ok(key::KeyPair::EC {
                key: ec::PrivateKey::P256(_)
            })
        ));
        test_decode_encode_symmetry(key);
    }

    #[test]
    fn test_decode_pkcs8_p384_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 384 -m pkcs8 -f $file
        let key = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCaqAL30kg+T5BUOYG9
MrzeDXiUwy9LM8qJGNXiMYou0pVjFZPZT3jAsrUQo47PLQ6hZANiAARuEHbXJBYK
9uyJj4PjT56OHjT2GqMa6i+FTG9vdLtu4OLUkXku+kOuFNjKvEI1JYBrJTpw9kSZ
CI3WfCsQvVjoC7m8qRyxuvR3Rv8gGXR1coQciIoCurLnn9zOFvXCS2Y=
-----END PRIVATE KEY-----
";
        assert!(matches!(
            decode_secret_key(key, None),
            Ok(key::KeyPair::EC {
                key: ec::PrivateKey::P384(_)
            })
        ));
        test_decode_encode_symmetry(key);
    }

    #[test]
    fn test_decode_pkcs8_p521_secret_key() {
        // Generated using: ssh-keygen -t ecdsa -b 521 -m pkcs8 -f $file
        let key = "-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIB1As9UBUsCiMK7Rzs
EoMgqDM/TK7y7+HgCWzw5UujXvSXCzYCeBgfJszn7dVoJE9G/1ejmpnVTnypdKEu
iIvd4LyhgYkDgYYABAADBCrg7hkomJbCsPMuMcq68ulmo/6Tv8BDS13F8T14v5RN
/0iT/+nwp6CnbBFewMI2TOh/UZNyPpQ8wOFNn9zBmAFCMzkQibnSWK0hrRstY5LT
iaOYDwInbFDsHu8j3TGs29KxyVXMexeV6ROQyXzjVC/quT1R5cOQ7EadE4HvaWhT
Ow==
-----END PRIVATE KEY-----
";
        assert!(matches!(
            decode_secret_key(key, None),
            Ok(key::KeyPair::EC {
                key: ec::PrivateKey::P521(_)
            })
        ));
        test_decode_encode_symmetry(key);
    }

    fn test_decode_encode_symmetry(key: &str) {
        let original_key_bytes = data_encoding::BASE64_MIME
            .decode(
                &key.lines()
                    .filter(|line| !line.starts_with("-----"))
                    .collect::<Vec<&str>>()
                    .join("")
                    .as_bytes(),
            )
            .unwrap();
        let decoded_key = decode_secret_key(key, None).unwrap();
        let encoded_key_bytes = pkcs8::encode_pkcs8(&decoded_key).unwrap();
        assert_eq!(original_key_bytes, encoded_key_bytes);
    }

    fn ecdsa_sign_verify(key: &str, public: &str) {
        let key = decode_secret_key(key, None).unwrap();
        let buf = b"blabla";
        let sig = key.sign_detached(buf).unwrap();
        // Verify using the provided public key.
        {
            let public = parse_public_key_base64(public).unwrap();
            assert!(public.verify_detached(buf, sig.as_ref()));
        }
        // Verify using public key derived from the secret key.
        {
            let public = key.clone_public_key().unwrap();
            assert!(public.verify_detached(buf, sig.as_ref()));
        }
        // Sanity check that it uses a different random number.
        {
            let sig2 = key.sign_detached(buf).unwrap();
            match (sig, sig2) {
                (
                    key::Signature::ECDSA {
                        algorithm,
                        signature,
                    },
                    key::Signature::ECDSA {
                        algorithm: algorithm2,
                        signature: signature2,
                    },
                ) => {
                    assert_eq!(algorithm, algorithm2);
                    assert_ne!(signature, signature2);
                }
                _ => assert!(false),
            }
        }
        // Verify (r, s) = (0, 0) is an invalid signature. (CVE-2022-21449)
        {
            use crate::encoding::Encoding;
            let mut sig = Vec::new();
            sig.extend_ssh_string(&[0]);
            sig.extend_ssh_string(&[0]);
            let public = key.clone_public_key().unwrap();
            assert_eq!(false, public.verify_detached(buf, &sig));
        }
    }

    #[test]
    fn test_ecdsa_sha2_nistp256_sign_verify() {
        env_logger::try_init().unwrap_or(());
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRQh23nB1wSlbAwhX3hrbNa35Z6vuY1
CnEhAjk4FSWR1/tcna7RKCMXdYEiPs5rHr+mMoJxeQxmCd+ny8uIBrg1AAAAqKgQe5KoEH
uSAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFCHbecHXBKVsDCF
feGts1rflnq+5jUKcSECOTgVJZHX+1ydrtEoIxd1gSI+zmsev6YygnF5DGYJ36fLy4gGuD
UAAAAgFOgyq4FDOtEe+vBy1O1dqMLjXrKmqcgPpOO3+9cbPM0AAAAKZWNkc2FAdGVzdAEC
AwQFBg==
-----END OPENSSH PRIVATE KEY-----
";
        let public = "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFCHbecHXBKVsDCFfeGts1rflnq+5jUKcSECOTgVJZHX+1ydrtEoIxd1gSI+zmsev6YygnF5DGYJ36fLy4gGuDU=";
        ecdsa_sign_verify(key, public);
    }

    #[test]
    fn test_ecdsa_sha2_nistp384_sign_verify() {
        env_logger::try_init().unwrap_or(());
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS
1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQRC1ed+3MGnknPWE6rdbw9p5f91AJSC
a469EDg5+EkDdVEEN1dWakAtI+gLRlpMotYD0Cso1Nx2MU9nW5fWLBmLtOWU6C1SX6INXB
527U0Ex5AYetNPBIhdTWB1UhbVkxgAAADYiT5XRYk+V0UAAAATZWNkc2Etc2hhMi1uaXN0
cDM4NAAAAAhuaXN0cDM4NAAAAGEEQtXnftzBp5Jz1hOq3W8PaeX/dQCUgmuOvRA4OfhJA3
VRBDdXVmpALSPoC0ZaTKLWA9ArKNTcdjFPZ1uX1iwZi7TllOgtUl+iDVwedu1NBMeQGHrT
TwSIXU1gdVIW1ZMYAAAAMH13rmHaaOv7SG4v/e3AV6yY49DzZD8YTzHRS62KDUPB/6t774
PCeBxYsjjIg5q1FwAAAAplY2RzYUB0ZXN0AQIDBAUG
-----END OPENSSH PRIVATE KEY-----
";
        let public = "AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBELV537cwaeSc9YTqt1vD2nl/3UAlIJrjr0QODn4SQN1UQQ3V1ZqQC0j6AtGWkyi1gPQKyjU3HYxT2dbl9YsGYu05ZToLVJfog1cHnbtTQTHkBh6008EiF1NYHVSFtWTGA==";
        ecdsa_sign_verify(key, public);
    }

    #[test]
    fn test_ecdsa_sha2_nistp521_sign_verify() {
        env_logger::try_init().unwrap_or(());
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS
1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQBVr19z0rsH1q3nly7RMJBfcHQER5H
oyqEAfX6NnGsa6atBcILGTKYNk/wqf58WabI1XY0ZGsJrx9twIbD6Wu0IcMAlS4MEYNjk7
/J0FWEfYVKRIRRSK8bzT2uiDxRwmH1ZkQSEE/ghur46O4pA4H++w699LU3alWtDx+bJfx7
zu4XjHwAAAEQqaEnO6mhJzsAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQ
AAAIUEAVa9fc9K7B9at55cu0TCQX3B0BEeR6MqhAH1+jZxrGumrQXCCxkymDZP8Kn+fFmm
yNV2NGRrCa8fbcCGw+lrtCHDAJUuDBGDY5O/ydBVhH2FSkSEUUivG809rog8UcJh9WZEEh
BP4Ibq+OjuKQOB/vsOvfS1N2pVrQ8fmyX8e87uF4x8AAAAQgE10hd4g3skdWl4djRX4kE3
ZgmnWhuwhyxErC5UkMHiEvTOZllxBvefs7XeJqL11pqQIHY4Gb5OQGiCNHiRRjg0egAAAA
1yb2JlcnRAYmJzZGV2AQIDBAU=
-----END OPENSSH PRIVATE KEY-----
";
        let public = "AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAFWvX3PSuwfWreeXLtEwkF9wdARHkejKoQB9fo2caxrpq0FwgsZMpg2T/Cp/nxZpsjVdjRkawmvH23AhsPpa7QhwwCVLgwRg2OTv8nQVYR9hUpEhFFIrxvNPa6IPFHCYfVmRBIQT+CG6vjo7ikDgf77Dr30tTdqVa0PH5sl/HvO7heMfA==";
        ecdsa_sign_verify(key, public);
    }

    pub const PKCS8_RSA: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwBGetHjW+3bDQpVktdemnk7JXgu1NBWUM+ysifYLDBvJ9ttX
GNZSyQKA4v/dNr0FhAJ8I9BuOTjYCy1YfKylhl5D/DiSSXFPsQzERMmGgAlYvU2U
+FTxpBC11EZg69CPVMKKevfoUD+PZA5zB7Hc1dXFfwqFc5249SdbAwD39VTbrOUI
WECvWZs6/ucQxHHXP2O9qxWqhzb/ddOnqsDHUNoeceiNiCf2anNymovrIMjAqq1R
t2UP3f06/Zt7Jx5AxKqS4seFkaDlMAK8JkEDuMDOdKI36raHkKanfx8CnGMSNjFQ
QtvnpD8VSGkDTJN3Qs14vj2wvS477BQXkBKN1QIDAQABAoIBABb6xLMw9f+2ENyJ
hTggagXsxTjkS7TElCu2OFp1PpMfTAWl7oDBO7xi+UqvdCcVbHCD35hlWpqsC2Ui
8sBP46n040ts9UumK/Ox5FWaiuYMuDpF6vnfJ94KRcb0+KmeFVf9wpW9zWS0hhJh
jC+yfwpyfiOZ/ad8imGCaOguGHyYiiwbRf381T/1FlaOGSae88h+O8SKTG1Oahq4
0HZ/KBQf9pij0mfVQhYBzsNu2JsHNx9+DwJkrXT7K9SHBpiBAKisTTCnQmS89GtE
6J2+bq96WgugiM7X6OPnmBmE/q1TgV18OhT+rlvvNi5/n8Z1ag5Xlg1Rtq/bxByP
CeIVHsECgYEA9dX+LQdv/Mg/VGIos2LbpJUhJDj0XWnTRq9Kk2tVzr+9aL5VikEb
09UPIEa2ToL6LjlkDOnyqIMd/WY1W0+9Zf1ttg43S/6Rvv1W8YQde0Nc7QTcuZ1K
9jSSP9hzsa3KZtx0fCtvVHm+ac9fP6u80tqumbiD2F0cnCZcSxOb4+UCgYEAyAKJ
70nNKegH4rTCStAqR7WGAsdPE3hBsC814jguplCpb4TwID+U78Xxu0DQF8WtVJ10
SJuR0R2q4L9uYWpo0MxdawSK5s9Am27MtJL0mkFQX0QiM7hSZ3oqimsdUdXwxCGg
oktxCUUHDIPJNVd4Xjg0JTh4UZT6WK9hl1zLQzECgYEAiZRCFGc2KCzVLF9m0cXA
kGIZUxFAyMqBv+w3+zq1oegyk1z5uE7pyOpS9cg9HME2TAo4UPXYpLAEZ5z8vWZp
45sp/BoGnlQQsudK8gzzBtnTNp5i/MnnetQ/CNYVIVnWjSxRUHBqdMdRZhv0/Uga
e5KA5myZ9MtfSJA7VJTbyHUCgYBCcS13M1IXaMAt3JRqm+pftfqVs7YeJqXTrGs/
AiDlGQigRk4quFR2rpAV/3rhWsawxDmb4So4iJ16Wb2GWP4G1sz1vyWRdSnmOJGC
LwtYrvfPHegqvEGLpHa7UsgDpol77hvZriwXwzmLO8A8mxkeW5dfAfpeR5o+mcxW
pvnTEQKBgQCKx6Ln0ku6jDyuDzA9xV2/PET5D75X61R2yhdxi8zurY/5Qon3OWzk
jn/nHT3AZghGngOnzyv9wPMKt9BTHyTB6DlB6bRVLDkmNqZh5Wi8U1/IjyNYI0t2
xV/JrzLAwPoKk3bkqys3bUmgo6DxVC/6RmMwPQ0rmpw78kOgEej90g==
-----END RSA PRIVATE KEY-----
";

    #[test]
    fn test_loewenheim() -> Result<(), Error> {
        env_logger::try_init().unwrap_or(());
        let key = "-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,80E4FCAD049EE007CCE1C65D52CDB87A

ZKBKtex8+DA/d08TTPp4vY8RV+r+1nUC1La+r0dSiXsfunRNDPcYhHbyA/Fdr9kQ
+d1/E3cEb0k2nq7xYyMzy8hpNp/uHu7UfllGdaBusiPjHR+feg6AQfbM0FWpdGzo
9l/Vho5Ocw8abQq1Q9aPW5QQXBURC7HtCQXbpuYjUAQBeea1LzPCw6UIF80GUUkY
1AycXxVfx1AeURAKTZR4hsxC5pqI4yhAvVNXxP+tTTa9NE8lOP0yqVNurfIqyAnp
5ELMwNdHXZyUcT+EH5PsC69ocQgEZqLs0chvke62woMOjeSpsW5cIjGohW9lOD1f
nJkECVZ50kE0SDvcL4Y338tHwMt7wdwdj1dkAWSUjAJT4ShjqV/TzaLAiNAyRxLl
cm3mAccaFIIBZG/bPLGI0B5+mf9VExXGJrbGlvURhtE3nwmjLg1vT8lVfqbyL3a+
0tFvmDYn71L97t/3hcD2tVnKLv9g8+/OCsUAk3+/0eS7D6GpmlOMRHdLLUHc4SOm
bIDT/dE6MjsCSm7n/JkTb8P+Ta1Hp94dUnX4pfjzZ+O8V1H8wv7QW5KsuJhJ8cn4
eS3BEgNH1I4FCCjLsZdWve9ehV3/19WXh+BF4WXFq9b3plmfJgTiZslvjy4dgThm
OhEK44+fN1UhzguofxTR4Maz7lcehQxGAxp14hf1EnaAEt3LVjEPEShgK5dx1Ftu
LWFz9nR4vZcMsaiszElrevqMhPQHXY7cnWqBenkMfkdcQDoZjKvV86K98kBIDMu+
kf855vqRF8b2n/6HPdm3eqFh/F410nSB0bBSglUfyOZH1nS+cs79RQZEF9fNUmpH
EPQtQ/PALohicj9Vh7rRaMKpsORdC8/Ahh20s01xL6siZ334ka3BLYT94UG796/C
4K1S2kPdUP8POJ2HhaK2l6qaG8tcEX7HbwwZeKiEHVNvWuIGQO9TiDONLycp9x4y
kNM3sv2pI7vEhs7d2NapWgNha1RcTSv0CQ6Th/qhGo73LBpVmKwombVImHAyMGAE
aVF32OycVd9c9tDgW5KdhWedbeaxD6qkSs0no71083kYIS7c6iC1R3ZeufEkMhmx
dwrciWTJ+ZAk6rS975onKz6mo/4PytcCY7Df/6xUxHF3iJCnuK8hNpLdJcdOiqEK
zj/d5YGyw3J2r+NrlV1gs3FyvR3eMCWWH2gpIQISBpnEANY40PxA/ogH+nCUvI/O
n8m437ZeLTg6lnPqsE4nlk2hUEwRdy/SVaQURbn7YlcYIt0e81r5sBXb4MXkLrf0
XRWmpSggdcaaMuXi7nVSdkgCMjGP7epS7HsfP46OrTtJLHn5LxvdOEaW53nPOVQg
/PlVfDbwWl8adE3i3PDQOw9jhYXnYS3sv4R8M8y2GYEXbINrTJyUGrlNggKFS6oh
Hjgt0gsM2N/D8vBrQwnRtyymRnFd4dXFEYKAyt+vk0sa36eLfl0z6bWzIchkJbdu
raMODVc+NiJE0Qe6bwAi4HSpJ0qw2lKwVHYB8cdnNVv13acApod326/9itdbb3lt
KJaj7gc0n6gmKY6r0/Ddufy1JZ6eihBCSJ64RARBXeg2rZpyT+xxhMEZLK5meOeR
-----END RSA PRIVATE KEY-----
";
        let key = decode_secret_key(key, Some("passphrase")).unwrap();
        let public = key.clone_public_key()?;
        let buf = b"blabla";
        let sig = key.sign_detached(buf).unwrap();
        assert!(public.verify_detached(buf, sig.as_ref()));
        Ok(())
    }

    #[test]
    fn test_o01eg() {
        env_logger::try_init().unwrap_or(());

        let key = "-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,EA77308AAF46981303D8C44D548D097E

QR18hXmAgGehm1QMMYGF34PAtBpTj+8/ZPFx2zZxir7pzDpfYoNAIf/fzLsW1ruG
0xo/ZK/T3/TpMgjmLsCR6q+KU4jmCcCqWQIGWYJt9ljFI5y/CXr5uqP3DKcqtdxQ
fbBAfXJ8ITF+Tj0Cljm2S1KYHor+mkil5Lf/ZNiHxcLfoI3xRnpd+2cemN9Ly9eY
HNTbeWbLosfjwdfPJNWFNV5flm/j49klx/UhXhr5HNFNgp/MlTrvkH4rBt4wYPpE
cZBykt4Fo1KGl95pT22inGxQEXVHF1Cfzrf5doYWxjiRTmfhpPSz/Tt0ev3+jIb8
Htx6N8tNBoVxwCiQb7jj3XNim2OGohIp5vgW9sh6RDfIvr1jphVOgCTFKSo37xk0
156EoCVo3VcLf+p0/QitbUHR+RGW/PvUJV/wFR5ShYqjI+N2iPhkD24kftJ/MjPt
AAwCm/GYoYjGDhIzQMB+FETZKU5kz23MQtZFbYjzkcI/RE87c4fkToekNCdQrsoZ
wG0Ne2CxrwwEnipHCqT4qY+lZB9EbqQgbWOXJgxA7lfznBFjdSX7uDc/mnIt9Y6B
MZRXH3PTfotHlHMe+Ypt5lfPBi/nruOl5wLo3L4kY5pUyqR0cXKNycIJZb/pJAnE
ryIb59pZP7njvoHzRqnC9dycnTFW3geK5LU+4+JMUS32F636aorunRCl6IBmVQHL
uZ+ue714fn/Sn6H4dw6IH1HMDG1hr8ozP4sNUCiAQ05LsjDMGTdrUsr2iBBpkQhu
VhUDZy9g/5XF1EgiMbZahmqi5WaJ5K75ToINHb7RjOE7MEiuZ+RPpmYLE0HXyn9X
HTx0ZGr022dDI6nkvUm6OvEwLUUmmGKRHKe0y1EdICGNV+HWqnlhGDbLWeMyUcIY
M6Zh9Dw3WXD3kROf5MrJ6n9MDIXx9jy7nmBh7m6zKjBVIw94TE0dsRcWb0O1IoqS
zLQ6ihno+KsQHDyMVLEUz1TuE52rIpBmqexDm3PdDfCgsNdBKP6QSTcoqcfHKeex
K93FWgSlvFFQQAkJumJJ+B7ZWnK+2pdjdtWwTpflAKNqc8t//WmjWZzCtbhTHCXV
1dnMk7azWltBAuXnjW+OqmuAzyh3ayKgqfW66mzSuyQNa1KqFhqpJxOG7IHvxVfQ
kYeSpqODnL87Zd/dU8s0lOxz3/ymtjPMHlOZ/nHNqW90IIeUwWJKJ46Kv6zXqM1t
MeD1lvysBbU9rmcUdop0D3MOgGpKkinR5gy4pUsARBiz4WhIm8muZFIObWes/GDS
zmmkQRO1IcfXKAHbq/OdwbLBm4vM9nk8vPfszoEQCnfOSd7aWrLRjDR+q2RnzNzh
K+fodaJ864JFIfB/A+aVviVWvBSt0eEbEawhTmNPerMrAQ8tRRhmNxqlDP4gOczi
iKUmK5recsXk5us5Ik7peIR/f9GAghpoJkF0HrHio47SfABuK30pzcj62uNWGljS
3d9UQLCepT6RiPFhks/lgimbtSoiJHql1H9Q/3q4MuO2PuG7FXzlTnui3zGw/Vvy
br8gXU8KyiY9sZVbmplRPF+ar462zcI2kt0a18mr0vbrdqp2eMjb37QDbVBJ+rPE
-----END RSA PRIVATE KEY-----
";
        decode_secret_key(key, Some("12345")).unwrap();
    }
    #[test]
    fn test_pkcs8() {
        env_logger::try_init().unwrap_or(());
        println!("test");
        decode_secret_key(PKCS8_RSA, Some("blabla")).unwrap();
    }

    const PKCS8_ENCRYPTED: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQITo1O0b8YrS0CAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBBtLH4T1KOfo1GGr7salhR8BIIE
0KN9ednYwcTGSX3hg7fROhTw7JAJ1D4IdT1fsoGeNu2BFuIgF3cthGHe6S5zceI2
MpkfwvHbsOlDFWMUIAb/VY8/iYxhNmd5J6NStMYRC9NC0fVzOmrJqE1wITqxtORx
IkzqkgFUbaaiFFQPepsh5CvQfAgGEWV329SsTOKIgyTj97RxfZIKA+TR5J5g2dJY
j346SvHhSxJ4Jc0asccgMb0HGh9UUDzDSql0OIdbnZW5KzYJPOx+aDqnpbz7UzY/
P8N0w/pEiGmkdkNyvGsdttcjFpOWlLnLDhtLx8dDwi/sbEYHtpMzsYC9jPn3hnds
TcotqjoSZ31O6rJD4z18FOQb4iZs3MohwEdDd9XKblTfYKM62aQJWH6cVQcg+1C7
jX9l2wmyK26Tkkl5Qg/qSfzrCveke5muZgZkFwL0GCcgPJ8RixSB4GOdSMa/hAMU
kvFAtoV2GluIgmSe1pG5cNMhurxM1dPPf4WnD+9hkFFSsMkTAuxDZIdDk3FA8zof
Yhv0ZTfvT6V+vgH3Hv7Tqcxomy5Qr3tj5vvAqqDU6k7fC4FvkxDh2mG5ovWvc4Nb
Xv8sed0LGpYitIOMldu6650LoZAqJVv5N4cAA2Edqldf7S2Iz1QnA/usXkQd4tLa
Z80+sDNv9eCVkfaJ6kOVLk/ghLdXWJYRLenfQZtVUXrPkaPpNXgD0dlaTN8KuvML
Uw/UGa+4ybnPsdVflI0YkJKbxouhp4iB4S5ACAwqHVmsH5GRnujf10qLoS7RjDAl
o/wSHxdT9BECp7TT8ID65u2mlJvH13iJbktPczGXt07nBiBse6OxsClfBtHkRLzE
QF6UMEXsJnIIMRfrZQnduC8FUOkfPOSXc8r9SeZ3GhfbV/DmWZvFPCpjzKYPsM5+
N8Bw/iZ7NIH4xzNOgwdp5BzjH9hRtCt4sUKVVlWfEDtTnkHNOusQGKu7HkBF87YZ
RN/Nd3gvHob668JOcGchcOzcsqsgzhGMD8+G9T9oZkFCYtwUXQU2XjMN0R4VtQgZ
rAxWyQau9xXMGyDC67gQ5xSn+oqMK0HmoW8jh2LG/cUowHFAkUxdzGadnjGhMOI2
zwNJPIjF93eDF/+zW5E1l0iGdiYyHkJbWSvcCuvTwma9FIDB45vOh5mSR+YjjSM5
nq3THSWNi7Cxqz12Q1+i9pz92T2myYKBBtu1WDh+2KOn5DUkfEadY5SsIu/Rb7ub
5FBihk2RN3y/iZk+36I69HgGg1OElYjps3D+A9AjVby10zxxLAz8U28YqJZm4wA/
T0HLxBiVw+rsHmLP79KvsT2+b4Diqih+VTXouPWC/W+lELYKSlqnJCat77IxgM9e
YIhzD47OgWl33GJ/R10+RDoDvY4koYE+V5NLglEhbwjloo9Ryv5ywBJNS7mfXMsK
/uf+l2AscZTZ1mhtL38efTQCIRjyFHc3V31DI0UdETADi+/Omz+bXu0D5VvX+7c6
b1iVZKpJw8KUjzeUV8yOZhvGu3LrQbhkTPVYL555iP1KN0Eya88ra+FUKMwLgjYr
JkUx4iad4dTsGPodwEP/Y9oX/Qk3ZQr+REZ8lg6IBoKKqqrQeBJ9gkm1jfKE6Xkc
Cog3JMeTrb3LiPHgN6gU2P30MRp6L1j1J/MtlOAr5rux
-----END ENCRYPTED PRIVATE KEY-----";

    #[test]
    fn test_gpg() {
        env_logger::try_init().unwrap_or(());
        let algo = [115, 115, 104, 45, 114, 115, 97];
        let key = [
            0, 0, 0, 7, 115, 115, 104, 45, 114, 115, 97, 0, 0, 0, 3, 1, 0, 1, 0, 0, 1, 129, 0, 163,
            72, 59, 242, 4, 248, 139, 217, 57, 126, 18, 195, 170, 3, 94, 154, 9, 150, 89, 171, 236,
            192, 178, 185, 149, 73, 210, 121, 95, 126, 225, 209, 199, 208, 89, 130, 175, 229, 163,
            102, 176, 155, 69, 199, 155, 71, 214, 170, 61, 202, 2, 207, 66, 198, 147, 65, 10, 176,
            20, 105, 197, 133, 101, 126, 193, 252, 245, 254, 182, 14, 250, 118, 113, 18, 220, 38,
            220, 75, 247, 50, 163, 39, 2, 61, 62, 28, 79, 199, 238, 189, 33, 194, 190, 22, 87, 91,
            1, 215, 115, 99, 138, 124, 197, 127, 237, 228, 170, 42, 25, 117, 1, 106, 36, 54, 163,
            163, 207, 129, 133, 133, 28, 185, 170, 217, 12, 37, 113, 181, 182, 180, 178, 23, 198,
            233, 31, 214, 226, 114, 146, 74, 205, 177, 82, 232, 238, 165, 44, 5, 250, 150, 236, 45,
            30, 189, 254, 118, 55, 154, 21, 20, 184, 235, 223, 5, 20, 132, 249, 147, 179, 88, 146,
            6, 100, 229, 200, 221, 157, 135, 203, 57, 204, 43, 27, 58, 85, 54, 219, 138, 18, 37,
            80, 106, 182, 95, 124, 140, 90, 29, 48, 193, 112, 19, 53, 84, 201, 153, 52, 249, 15,
            41, 5, 11, 147, 18, 8, 27, 31, 114, 45, 224, 118, 111, 176, 86, 88, 23, 150, 184, 252,
            128, 52, 228, 90, 30, 34, 135, 234, 123, 28, 239, 90, 202, 239, 188, 175, 8, 141, 80,
            59, 194, 80, 43, 205, 34, 137, 45, 140, 244, 181, 182, 229, 247, 94, 216, 115, 173,
            107, 184, 170, 102, 78, 249, 4, 186, 234, 169, 148, 98, 128, 33, 115, 232, 126, 84, 76,
            222, 145, 90, 58, 1, 4, 163, 243, 93, 215, 154, 205, 152, 178, 109, 241, 197, 82, 148,
            222, 78, 44, 193, 248, 212, 157, 118, 217, 75, 211, 23, 229, 121, 28, 180, 208, 173,
            204, 14, 111, 226, 25, 163, 220, 95, 78, 175, 189, 168, 67, 159, 179, 176, 200, 150,
            202, 248, 174, 109, 25, 89, 176, 220, 226, 208, 187, 84, 169, 157, 14, 88, 217, 221,
            117, 254, 51, 45, 93, 184, 80, 225, 158, 29, 76, 38, 69, 72, 71, 76, 50, 191, 210, 95,
            152, 175, 26, 207, 91, 7,
        ];
        debug!("algo = {:?}", std::str::from_utf8(&algo));
        key::PublicKey::parse(&algo, &key).unwrap();
    }

    #[test]
    fn test_pkcs8_encrypted() {
        env_logger::try_init().unwrap_or(());
        println!("test");
        decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
    }

    #[cfg(unix)]
    async fn test_client_agent(key: key::KeyPair) -> Result<(), Box<dyn std::error::Error>> {
        env_logger::try_init().unwrap_or(());
        use std::process::Stdio;

        let dir = tempdir::TempDir::new("russh")?;
        let agent_path = dir.path().join("agent");
        let mut agent = tokio::process::Command::new("ssh-agent")
            .arg("-a")
            .arg(&agent_path)
            .arg("-D")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        // Wait for the socket to be created
        while agent_path.canonicalize().is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let public = key.clone_public_key()?;
        let stream = tokio::net::UnixStream::connect(&agent_path).await?;
        let mut client = agent::client::AgentClient::connect(stream);
        client.add_identity(&key, &[]).await?;
        client.request_identities().await?;
        let buf = russh_cryptovec::CryptoVec::from_slice(b"blabla");
        let len = buf.len();
        let (_, buf) = client.sign_request(&public, buf).await;
        let buf = buf?;
        let (a, b) = buf.split_at(len);
        match key {
            key::KeyPair::Ed25519 { .. } => {
                let sig = &b[b.len() - 64..];
                assert!(public.verify_detached(a, sig));
            }
            key::KeyPair::EC { .. } => {}
            _ => {}
        }

        agent.kill().await?;
        agent.wait().await?;

        Ok(())
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_client_agent_ed25519() {
        let key = decode_secret_key(ED25519_KEY, Some("blabla")).unwrap();
        test_client_agent(key).await.expect("ssh-agent test failed")
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_client_agent_rsa() {
        let key = decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
        test_client_agent(key).await.expect("ssh-agent test failed")
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn test_client_agent_openssh_rsa() {
        let key = decode_secret_key(RSA_KEY, None).unwrap();
        test_client_agent(key).await.expect("ssh-agent test failed")
    }

    #[test]
    #[cfg(unix)]
    fn test_agent() {
        env_logger::try_init().unwrap_or(());
        let dir = tempdir::TempDir::new("russh").unwrap();
        let agent_path = dir.path().join("agent");

        let core = tokio::runtime::Runtime::new().unwrap();
        use agent;

        #[derive(Clone)]
        struct X {}
        impl agent::server::Agent for X {
            fn confirm(
                self,
                _: std::sync::Arc<key::KeyPair>,
            ) -> Box<dyn Future<Output = (Self, bool)> + Send + Unpin> {
                Box::new(futures::future::ready((self, true)))
            }
        }
        let agent_path_ = agent_path.clone();
        core.spawn(async move {
            let mut listener = tokio::net::UnixListener::bind(&agent_path_).unwrap();

            agent::server::serve(
                Incoming {
                    listener: &mut listener,
                },
                X {},
            )
            .await
        });
        let key = decode_secret_key(PKCS8_ENCRYPTED, Some("blabla")).unwrap();
        core.block_on(async move {
            let public = key.clone_public_key()?;
            let stream = tokio::net::UnixStream::connect(&agent_path).await?;
            let mut client = agent::client::AgentClient::connect(stream);
            client
                .add_identity(&key, &[agent::Constraint::KeyLifetime { seconds: 60 }])
                .await?;
            client.request_identities().await?;
            let buf = russh_cryptovec::CryptoVec::from_slice(b"blabla");
            let len = buf.len();
            let (_, buf) = client.sign_request(&public, buf).await;
            let buf = buf?;
            let (a, b) = buf.split_at(len);
            match key {
                key::KeyPair::Ed25519 { .. } => {
                    let sig = &b[b.len() - 64..];
                    assert!(public.verify_detached(a, sig));
                }
                _ => {}
            }
            Ok::<(), Error>(())
        })
        .unwrap()
    }

    #[cfg(unix)]
    struct Incoming<'a> {
        listener: &'a mut tokio::net::UnixListener,
    }

    #[cfg(unix)]
    impl futures::stream::Stream for Incoming<'_> {
        type Item = Result<tokio::net::UnixStream, std::io::Error>;

        fn poll_next(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            let (sock, _addr) = futures::ready!(self.get_mut().listener.poll_accept(cx))?;
            std::task::Poll::Ready(Some(Ok(sock)))
        }
    }
}
