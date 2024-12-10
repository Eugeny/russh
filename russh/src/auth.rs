// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use std::sync::Arc;

use async_trait::async_trait;
use bitflags::bitflags;
use russh_keys::helpers::NameList;
use russh_keys::key::PrivateKeyWithHashAlg;
use ssh_key::{Certificate, PrivateKey};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::CryptoVec;

bitflags! {
    /// Set of authentication methods, represented by bit flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MethodSet: u32 {
        /// The SSH `none` method (no authentication).
        const NONE = 1;
        /// The SSH `password` method (plaintext passwords).
        const PASSWORD = 2;
        /// The SSH `publickey` method (sign a challenge sent by the
        /// server).
        const PUBLICKEY = 4;
        /// The SSH `hostbased` method (certain hostnames are allowed
        /// by the server).
        const HOSTBASED = 8;
        /// The SSH `keyboard-interactive` method (answer to a
        /// challenge, where the "challenge" can be a password prompt,
        /// a bytestring to sign with a smartcard, or something else).
        const KEYBOARD_INTERACTIVE = 16;
    }
}

#[async_trait]
pub trait Signer: Sized {
    type Error: From<crate::SendError>;

    async fn auth_publickey_sign(
        &mut self,
        key: &ssh_key::PublicKey,
        to_sign: CryptoVec,
    ) -> Result<CryptoVec, Self::Error>;
}

#[derive(Debug, Error)]
pub enum AgentAuthError {
    #[error(transparent)]
    Send(#[from] crate::SendError),
    #[error(transparent)]
    Key(#[from] russh_keys::Error),
}

#[async_trait]
impl<R: AsyncRead + AsyncWrite + Unpin + Send + 'static> Signer
    for russh_keys::agent::client::AgentClient<R>
{
    type Error = AgentAuthError;

    async fn auth_publickey_sign(
        &mut self,
        key: &ssh_key::PublicKey,
        to_sign: CryptoVec,
    ) -> Result<CryptoVec, Self::Error> {
        self.sign_request(key, to_sign).await.map_err(Into::into)
    }
}

#[derive(Debug)]
pub enum Method {
    None,
    Password {
        password: String,
    },
    PublicKey {
        key: PrivateKeyWithHashAlg,
    },
    OpenSshCertificate {
        key: Arc<PrivateKey>,
        cert: Certificate,
    },
    FuturePublicKey {
        key: ssh_key::PublicKey,
    },
    KeyboardInteractive {
        submethods: String,
    },
    // Hostbased,
}

impl From<MethodSet> for &'static str {
    fn from(value: MethodSet) -> Self {
        match value {
            MethodSet::NONE => "none",
            MethodSet::PASSWORD => "password",
            MethodSet::PUBLICKEY => "publickey",
            MethodSet::HOSTBASED => "hostbased",
            MethodSet::KEYBOARD_INTERACTIVE => "keyboard-interactive",
            _ => "",
        }
    }
}

impl From<MethodSet> for String {
    fn from(value: MethodSet) -> Self {
        <&str>::from(value).to_string()
    }
}

impl From<MethodSet> for NameList {
    fn from(value: MethodSet) -> Self {
        Self(value.into_iter().map(|x| x.into()).collect())
    }
}

impl MethodSet {
    pub(crate) fn from_str(b: &str) -> Option<MethodSet> {
        match b {
            "none" => Some(MethodSet::NONE),
            "password" => Some(MethodSet::PASSWORD),
            "publickey" => Some(MethodSet::PUBLICKEY),
            "hostbased" => Some(MethodSet::HOSTBASED),
            "keyboard-interactive" => Some(MethodSet::KEYBOARD_INTERACTIVE),
            _ => None,
        }
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct AuthRequest {
    pub methods: MethodSet,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub partial_success: bool,
    pub current: Option<CurrentRequest>,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub rejection_count: usize,
}

#[doc(hidden)]
#[derive(Debug)]
pub enum CurrentRequest {
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    PublicKey {
        #[allow(dead_code)]
        key: CryptoVec,
        #[allow(dead_code)]
        algo: CryptoVec,
        sent_pk_ok: bool,
    },
    KeyboardInteractive {
        #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
        submethods: String,
    },
}
