//! This file implements the SSH session-bind protocol.
//! https://raw.githubusercontent.com/openssh/openssh-portable/refs/heads/master/PROTOCOL.agent

use crate::{
    encoding::{Position, Reader},
    ssh_agent::Agent,
};
use anyhow::Error;
use rsa::{
    sha2::{self, Digest},
    BigUint, Pkcs1v15Sign,
};
use russh_cryptovec::CryptoVec;
use ssh_key::{
    public::{EcdsaPublicKey, Ed25519PublicKey, KeyData, RsaPublicKey},
    EcdsaCurve,
};

use crate::ssh_agent::SSHAgentError;

#[derive(Debug)]
pub struct SessionBindInfo {
    pub is_forwarding: bool,
    pub host_key: Vec<u8>,
    pub session_identifier: Vec<u8>,
}

#[derive(Debug)]
pub enum SessionBindResult {
    Success(SessionBindInfo),
    SignatureFailure,
}

fn verify_ed25519_signature(
    key: &Ed25519PublicKey,
    signature: &[u8],
    _alg: String,
    session_identifier: &[u8],
) -> Result<(), Error> {
    ed25519_dalek::VerifyingKey::from_bytes(&key.0)?
        .verify_strict(
            session_identifier,
            &ed25519_dalek::Signature::from_slice(signature)?,
        )
        .map_err(Into::into)
}

fn verify_rsa_signature(
    key: &RsaPublicKey,
    signature: &[u8],
    alg: String,
    session_identifier: &[u8],
) -> Result<(), Error> {
    let n = key
        .n
        .as_positive_bytes()
        .map(BigUint::from_bytes_be)
        .ok_or(anyhow::anyhow!("Failed to parse RSA modulus"))?;
    let e = key
        .e
        .as_positive_bytes()
        .map(BigUint::from_bytes_be)
        .ok_or(anyhow::anyhow!("Failed to parse RSA exponent"))?;
    let verifying_key = rsa::RsaPublicKey::new(n, e)?;

    if alg == "rsa-sha2-256" {
        verifying_key
            .verify(
                Pkcs1v15Sign::new::<sha2::Sha256>(),
                sha2::Sha256::digest(session_identifier).as_slice(),
                signature,
            )
            .map_err(Into::into)
    } else if alg == "rsa-sha2-512" {
        verifying_key
            .verify(
                Pkcs1v15Sign::new::<sha2::Sha512>(),
                sha2::Sha512::digest(session_identifier).as_slice(),
                signature,
            )
            .map_err(Into::into)
    } else {
        Err(SSHAgentError::AgentFailure.into())
    }
}

fn verify_ecdsa_signature(
    key: &EcdsaPublicKey,
    signature: &[u8],
    _alg: String,
    session_identifier: &[u8],
) -> Result<(), Error> {
    match key.curve() {
        EcdsaCurve::NistP256 => {
            use p256::ecdsa::signature::Verifier;
            p256::ecdsa::VerifyingKey::from_sec1_bytes(key.as_sec1_bytes())?.verify(
                session_identifier,
                &p256::ecdsa::Signature::from_slice(signature)?,
            )
        }
        EcdsaCurve::NistP384 => {
            use p384::ecdsa::signature::Verifier;
            p384::ecdsa::VerifyingKey::from_sec1_bytes(key.as_sec1_bytes())?.verify(
                session_identifier,
                &p384::ecdsa::Signature::from_slice(signature)?,
            )
        }
        EcdsaCurve::NistP521 => {
            use p521::ecdsa::signature::Verifier;
            p521::ecdsa::VerifyingKey::from_sec1_bytes(key.as_sec1_bytes())?.verify(
                session_identifier,
                &p521::ecdsa::Signature::from_slice(signature)?,
            )
        }
    }
    .map_err(Into::into)
}

pub(crate) async fn respond_extension_session_bind<
    'a,
    A: Agent<I> + Send + Sync + 'static,
    I: Clone,
>(
    agent: &mut A,
    r: &mut Position<'a>,
    connection_info: I,
) -> Result<(), Error> {
    let hostkey_bytes = r.read_string()?;
    let hostkey =
        ssh_key::PublicKey::from_bytes(hostkey_bytes).map_err(|_| SSHAgentError::AgentFailure)?;
    let session_identifier = r.read_string()?;

    let signature = CryptoVec::from_slice(r.read_string()?);
    let mut signature = signature.reader(0);
    let alg = String::from_utf8(signature.read_string()?.to_vec())
        .map_err(|_| SSHAgentError::AgentFailure)?;
    let signature = signature.read_string()?.to_vec();

    let is_forwarding = r.read_byte()? == 1;

    let signature_verified = match hostkey.key_data() {
        KeyData::Ed25519(key) => verify_ed25519_signature(key, &signature, alg, session_identifier),
        KeyData::Rsa(key) => verify_rsa_signature(key, &signature, alg, session_identifier),
        KeyData::Ecdsa(key) => verify_ecdsa_signature(key, &signature, alg, session_identifier),
        _ => Ok(()),
    }
    .is_ok();

    if !signature_verified {
        agent
            .set_sessionbind_info(&SessionBindResult::SignatureFailure, &connection_info)
            .await;
        Err(SSHAgentError::SignatureVerificationFailed.into())
    } else {
        agent
            .set_sessionbind_info(
                &SessionBindResult::Success(SessionBindInfo {
                    is_forwarding,
                    host_key: hostkey_bytes.to_vec(),
                    session_identifier: session_identifier.to_vec(),
                }),
                &connection_info,
            )
            .await;
        Ok(())
    }
}
