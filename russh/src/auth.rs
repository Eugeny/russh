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

use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use ssh_key::{Certificate, HashAlg, PrivateKey};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::helpers::NameList;
use crate::keys::key::PrivateKeyWithHashAlg;
use crate::CryptoVec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodKind {
    None,
    Password,
    PublicKey,
    HostBased,
    KeyboardInteractive,
}

impl From<&MethodKind> for &'static str {
    fn from(value: &MethodKind) -> Self {
        match value {
            MethodKind::None => "none",
            MethodKind::Password => "password",
            MethodKind::PublicKey => "publickey",
            MethodKind::HostBased => "hostbased",
            MethodKind::KeyboardInteractive => "keyboard-interactive",
        }
    }
}

impl FromStr for MethodKind {
    fn from_str(b: &str) -> Result<MethodKind, Self::Err> {
        match b {
            "none" => Ok(MethodKind::None),
            "password" => Ok(MethodKind::Password),
            "publickey" => Ok(MethodKind::PublicKey),
            "hostbased" => Ok(MethodKind::HostBased),
            "keyboard-interactive" => Ok(MethodKind::KeyboardInteractive),
            _ => Err(()),
        }
    }

    type Err = ();
}

impl From<&MethodKind> for String {
    fn from(value: &MethodKind) -> Self {
        <&str>::from(value).to_string()
    }
}

/// An ordered set of authentication methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodSet(Vec<MethodKind>);

impl Deref for MethodSet {
    type Target = [MethodKind];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<&[MethodKind]> for MethodSet {
    fn from(value: &[MethodKind]) -> Self {
        let mut this = Self::empty();
        for method in value {
            this.push(*method);
        }
        this
    }
}

impl From<&MethodSet> for NameList {
    fn from(value: &MethodSet) -> Self {
        Self(value.iter().map(|x| x.into()).collect())
    }
}

impl From<&NameList> for MethodSet {
    fn from(value: &NameList) -> Self {
        Self(
            value
                .0
                .iter()
                .filter_map(|x| MethodKind::from_str(x).ok())
                .collect(),
        )
    }
}

impl MethodSet {
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn all() -> Self {
        Self(vec![
            MethodKind::None,
            MethodKind::Password,
            MethodKind::PublicKey,
            MethodKind::HostBased,
            MethodKind::KeyboardInteractive,
        ])
    }

    pub fn remove(&mut self, method: MethodKind) {
        self.0.retain(|x| *x != method);
    }

    /// Push a method to the end of the list.
    /// If the method is already in the list, it is moved to the end.
    pub fn push(&mut self, method: MethodKind) {
        self.remove(method);
        self.0.push(method);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthResult {
    Success,
    Failure { remaining_methods: MethodSet },
}

impl AuthResult {
    pub fn success(&self) -> bool {
        matches!(self, AuthResult::Success)
    }
}

#[async_trait]
pub trait Signer: Sized {
    type Error: From<crate::SendError>;

    async fn auth_publickey_sign(
        &mut self,
        key: &ssh_key::PublicKey,
        hash_alg: Option<HashAlg>,
        to_sign: CryptoVec,
    ) -> Result<CryptoVec, Self::Error>;
}

#[derive(Debug, Error)]
pub enum AgentAuthError {
    #[error(transparent)]
    Send(#[from] crate::SendError),
    #[error(transparent)]
    Key(#[from] crate::keys::Error),
}

#[async_trait]
impl<R: AsyncRead + AsyncWrite + Unpin + Send + 'static> Signer
    for crate::keys::agent::client::AgentClient<R>
{
    type Error = AgentAuthError;

    async fn auth_publickey_sign(
        &mut self,
        key: &ssh_key::PublicKey,
        hash_alg: Option<HashAlg>,
        to_sign: CryptoVec,
    ) -> Result<CryptoVec, Self::Error> {
        self.sign_request(key, hash_alg, to_sign)
            .await
            .map_err(Into::into)
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
