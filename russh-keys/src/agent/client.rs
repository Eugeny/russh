use core::str;

use byteorder::{BigEndian, ByteOrder};
use log::debug;
use russh_cryptovec::CryptoVec;
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey, Signature};
use tokio;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{msg, Constraint};
use crate::encoding::{Encoding, Reader};
use crate::helpers::EncodedExt;
use crate::{key, Error};

pub trait AgentStream: AsyncRead + AsyncWrite {}

impl<S: AsyncRead + AsyncWrite> AgentStream for S {}

/// SSH agent client.
pub struct AgentClient<S: AgentStream> {
    stream: S,
    buf: CryptoVec,
}

impl<S: AgentStream + Send + Unpin + 'static> AgentClient<S> {
    /// Wraps the internal stream in a Box<dyn _>, allowing different client
    /// implementations to have the same type
    pub fn dynamic(self) -> AgentClient<Box<dyn AgentStream + Send + Unpin + 'static>> {
        AgentClient {
            stream: Box::new(self.stream),
            buf: self.buf,
        }
    }

    pub fn into_inner(self) -> Box<dyn AgentStream + Send + Unpin + 'static> {
        Box::new(self.stream)
    }
}

// https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-4.1
impl<S: AgentStream + Unpin> AgentClient<S> {
    /// Build a future that connects to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub fn connect(stream: S) -> Self {
        AgentClient {
            stream,
            buf: CryptoVec::new(),
        }
    }
}

#[cfg(unix)]
impl AgentClient<tokio::net::UnixStream> {
    /// Connect to an SSH agent via the provided
    /// stream (on Unix, usually a Unix-domain socket).
    pub async fn connect_uds<P: AsRef<std::path::Path>>(path: P) -> Result<Self, Error> {
        let stream = tokio::net::UnixStream::connect(path).await?;
        Ok(AgentClient {
            stream,
            buf: CryptoVec::new(),
        })
    }

    /// Connect to an SSH agent specified by the SSH_AUTH_SOCK
    /// environment variable.
    pub async fn connect_env() -> Result<Self, Error> {
        let var = if let Ok(var) = std::env::var("SSH_AUTH_SOCK") {
            var
        } else {
            return Err(Error::EnvVar("SSH_AUTH_SOCK"));
        };
        match Self::connect_uds(var).await {
            Err(Error::IO(io_err)) if io_err.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::BadAuthSock)
            }
            owise => owise,
        }
    }
}

#[cfg(windows)]
const ERROR_PIPE_BUSY: u32 = 231u32;

#[cfg(windows)]
impl AgentClient<pageant::PageantStream> {
    /// Connect to a running Pageant instance
    pub async fn connect_pageant() -> Self {
        Self::connect(pageant::PageantStream::new())
    }
}

#[cfg(windows)]
impl AgentClient<tokio::net::windows::named_pipe::NamedPipeClient> {
    /// Connect to an SSH agent via a Windows named pipe
    pub async fn connect_named_pipe<P: AsRef<std::ffi::OsStr>>(path: P) -> Result<Self, Error> {
        let stream = loop {
            match tokio::net::windows::named_pipe::ClientOptions::new().open(path.as_ref()) {
                Ok(client) => break client,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => (),
                Err(e) => return Err(e.into()),
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        };

        Ok(AgentClient {
            stream,
            buf: CryptoVec::new(),
        })
    }
}

impl<S: AgentStream + Unpin> AgentClient<S> {
    async fn read_response(&mut self) -> Result<(), Error> {
        // Writing the message
        self.stream.write_all(&self.buf).await?;
        self.stream.flush().await?;

        // Reading the length
        self.buf.clear();
        self.buf.resize(4);
        self.stream.read_exact(&mut self.buf).await?;

        // Reading the rest of the buffer
        let len = BigEndian::read_u32(&self.buf) as usize;
        self.buf.clear();
        self.buf.resize(len);
        self.stream.read_exact(&mut self.buf).await?;

        Ok(())
    }

    async fn read_success(&mut self) -> Result<(), Error> {
        self.read_response().await?;
        if self.buf.first() == Some(&msg::SUCCESS) {
            Ok(())
        } else {
            Err(Error::AgentFailure)
        }
    }

    /// Send a key to the agent, with a (possibly empty) slice of
    /// constraints to apply when using the key to sign.
    pub async fn add_identity(
        &mut self,
        key: &PrivateKey,
        constraints: &[Constraint],
    ) -> Result<(), Error> {
        // See IETF draft-miller-ssh-agent-13, section 3.2 for format.
        // https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent
        self.buf.clear();
        self.buf.resize(4);
        if constraints.is_empty() {
            self.buf.push(msg::ADD_IDENTITY)
        } else {
            self.buf.push(msg::ADD_ID_CONSTRAINED)
        }

        self.buf.extend(key.key_data().encoded()?.as_slice());
        self.buf.extend_ssh_string(&[]); // comment field

        if !constraints.is_empty() {
            for cons in constraints {
                match *cons {
                    Constraint::KeyLifetime { seconds } => {
                        self.buf.push(msg::CONSTRAIN_LIFETIME);
                        self.buf.push_u32_be(seconds);
                    }
                    Constraint::Confirm => self.buf.push(msg::CONSTRAIN_CONFIRM),
                    Constraint::Extensions {
                        ref name,
                        ref details,
                    } => {
                        self.buf.push(msg::CONSTRAIN_EXTENSION);
                        self.buf.extend_ssh_string(name);
                        self.buf.extend_ssh_string(details);
                    }
                }
            }
        }
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);

        self.read_success().await?;
        Ok(())
    }

    /// Add a smart card to the agent, with a (possibly empty) set of
    /// constraints to apply when signing.
    pub async fn add_smartcard_key(
        &mut self,
        id: &str,
        pin: &[u8],
        constraints: &[Constraint],
    ) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        if constraints.is_empty() {
            self.buf.push(msg::ADD_SMARTCARD_KEY)
        } else {
            self.buf.push(msg::ADD_SMARTCARD_KEY_CONSTRAINED)
        }
        self.buf.extend_ssh_string(id.as_bytes());
        self.buf.extend_ssh_string(pin);
        if !constraints.is_empty() {
            self.buf.push_u32_be(constraints.len() as u32);
            for cons in constraints {
                match *cons {
                    Constraint::KeyLifetime { seconds } => {
                        self.buf.push(msg::CONSTRAIN_LIFETIME);
                        self.buf.push_u32_be(seconds)
                    }
                    Constraint::Confirm => self.buf.push(msg::CONSTRAIN_CONFIRM),
                    Constraint::Extensions {
                        ref name,
                        ref details,
                    } => {
                        self.buf.push(msg::CONSTRAIN_EXTENSION);
                        self.buf.extend_ssh_string(name);
                        self.buf.extend_ssh_string(details);
                    }
                }
            }
        }
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_response().await?;
        Ok(())
    }

    /// Lock the agent, making it refuse to sign until unlocked.
    pub async fn lock(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::LOCK);
        self.buf.extend_ssh_string(passphrase);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_response().await?;
        Ok(())
    }

    /// Unlock the agent, allowing it to sign again.
    pub async fn unlock(&mut self, passphrase: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::UNLOCK);
        self.buf.extend_ssh_string(passphrase);
        let len = self.buf.len() - 4;
        #[allow(clippy::indexing_slicing)] // static length
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_response().await?;
        Ok(())
    }

    /// Ask the agent for a list of the currently registered secret
    /// keys.
    pub async fn request_identities(&mut self) -> Result<Vec<PublicKey>, Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REQUEST_IDENTITIES);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);

        self.read_response().await?;
        debug!("identities: {:?}", &self.buf[..]);
        let mut keys = Vec::new();

        #[allow(clippy::indexing_slicing)] // static length
        if self.buf[0] == msg::IDENTITIES_ANSWER {
            let mut r = self.buf.reader(1);
            let n = r.read_u32()?;
            for _ in 0..n {
                let key_blob = r.read_string()?;
                let _comment = r.read_string()?;
                keys.push(key::parse_public_key(key_blob)?);
            }
        }

        Ok(keys)
    }

    /// Ask the agent to sign the supplied piece of data.
    pub async fn sign_request(
        &mut self,
        public: &PublicKey,
        mut data: CryptoVec,
    ) -> Result<CryptoVec, Error> {
        debug!("sign_request: {:?}", data);
        let hash = self.prepare_sign_request(public, &data)?;

        self.read_response().await?;

        if self.buf.first() == Some(&msg::SIGN_RESPONSE) {
            self.write_signature(hash, &mut data)?;
            Ok(data)
        } else if self.buf.first() == Some(&msg::FAILURE) {
            Err(Error::AgentFailure)
        } else {
            debug!("self.buf = {:?}", &self.buf[..]);
            Ok(data)
        }
    }

    fn prepare_sign_request(
        &mut self,
        public: &ssh_key::PublicKey,
        data: &[u8],
    ) -> Result<u32, Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::SIGN_REQUEST);
        key_blob(public, &mut self.buf)?;
        self.buf.extend_ssh_string(data);
        debug!("public = {:?}", public);
        let hash = match public.algorithm() {
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            } => 2,
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            } => 4,
            Algorithm::Rsa { hash: None } => 0,
            _ => 0,
        };
        self.buf.push_u32_be(hash);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        Ok(hash)
    }

    fn write_signature(&self, hash: u32, data: &mut CryptoVec) -> Result<(), Error> {
        let mut r = self.buf.reader(1);
        let mut resp = r.read_string()?.reader(0);
        let t = resp.read_string()?;
        if (hash == 2 && t == b"rsa-sha2-256") || (hash == 4 && t == b"rsa-sha2-512") || hash == 0 {
            let sig = resp.read_string()?;
            data.push_u32_be((t.len() + sig.len() + 8) as u32);
            data.extend_ssh_string(t);
            data.extend_ssh_string(sig);
        }
        Ok(())
    }

    /// Ask the agent to sign the supplied piece of data.
    pub fn sign_request_base64(
        mut self,
        public: &ssh_key::PublicKey,
        data: &[u8],
    ) -> impl futures::Future<Output = (Self, Result<String, Error>)> {
        debug!("sign_request: {:?}", data);
        let r = self.prepare_sign_request(public, data);
        async move {
            if let Err(e) = r {
                return (self, Err(e));
            }

            let resp = self.read_response().await;
            if let Err(e) = resp {
                return (self, Err(e));
            }

            #[allow(clippy::indexing_slicing)] // length is checked
            if !self.buf.is_empty() && self.buf[0] == msg::SIGN_RESPONSE {
                let base64 = data_encoding::BASE64_NOPAD.encode(&self.buf[1..]);
                (self, Ok(base64))
            } else {
                (self, Ok(String::new()))
            }
        }
    }

    /// Ask the agent to sign the supplied piece of data, and return a `Signature`.
    pub async fn sign_request_signature(
        &mut self,
        public: &ssh_key::PublicKey,
        data: &[u8],
    ) -> Result<Signature, Error> {
        debug!("sign_request: {:?}", data);

        self.prepare_sign_request(public, data)?;
        self.read_response().await?;

        #[allow(clippy::indexing_slicing)] // length is checked
        if !self.buf.is_empty() && self.buf[0] == msg::SIGN_RESPONSE {
            let mut r = self.buf.reader(1);
            let mut resp = r.read_string()?.reader(0);
            let typ = String::from_utf8(resp.read_string()?.into())?;
            let sig = resp.read_string()?;
            let algo = Algorithm::new(&typ)?;
            let sig = Signature::new(algo, sig.to_vec())?;
            Ok(sig)
        } else {
            Err(Error::AgentProtocolError)
        }
    }

    /// Ask the agent to remove a key from its memory.
    pub async fn remove_identity(&mut self, public: &ssh_key::PublicKey) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REMOVE_IDENTITY);
        key_blob(public, &mut self.buf)?;
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_response().await?;
        Ok(())
    }

    /// Ask the agent to remove a smartcard from its memory.
    pub async fn remove_smartcard_key(&mut self, id: &str, pin: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REMOVE_SMARTCARD_KEY);
        self.buf.extend_ssh_string(id.as_bytes());
        self.buf.extend_ssh_string(pin);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_response().await?;
        Ok(())
    }

    /// Ask the agent to forget all known keys.
    pub async fn remove_all_identities(&mut self) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::REMOVE_ALL_IDENTITIES);
        BigEndian::write_u32(&mut self.buf[..], 1);
        self.read_success().await?;
        Ok(())
    }

    /// Send a custom message to the agent.
    pub async fn extension(&mut self, typ: &[u8], ext: &[u8]) -> Result<(), Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::EXTENSION);
        self.buf.extend_ssh_string(typ);
        self.buf.extend_ssh_string(ext);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_response().await?;
        Ok(())
    }

    /// Ask the agent what extensions about supported extensions.
    pub async fn query_extension(&mut self, typ: &[u8], mut ext: CryptoVec) -> Result<bool, Error> {
        self.buf.clear();
        self.buf.resize(4);
        self.buf.push(msg::EXTENSION);
        self.buf.extend_ssh_string(typ);
        let len = self.buf.len() - 4;
        BigEndian::write_u32(&mut self.buf[..], len as u32);
        self.read_response().await?;

        let mut r = self.buf.reader(1);
        ext.extend(r.read_string()?);

        #[allow(clippy::indexing_slicing)] // length is checked
        Ok(!self.buf.is_empty() && self.buf[0] == msg::SUCCESS)
    }
}

fn key_blob(public: &ssh_key::PublicKey, buf: &mut CryptoVec) -> Result<(), Error> {
    buf.extend_ssh_string(public.key_data().encoded()?.as_slice());
    Ok(())
}
