#![cfg(all(feature = "rsa", not(target_arch = "wasm32")))]
//! The certificate type in an RSA certificate auth request must match the
//! signature hash
use std::sync::Arc;

use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::ssh_key::{Algorithm, HashAlg, PrivateKey};
use russh::keys::{Certificate, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{client, server};

struct AcceptServerKey;

impl client::Handler for AcceptServerKey {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct AcceptCertificates;

impl server::Handler for AcceptCertificates {
    type Error = russh::Error;

    async fn auth_openssh_certificate(
        &mut self,
        _user: &str,
        _certificate: &Certificate,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
}

async fn connect() -> client::Handle<AcceptServerKey> {
    let mut config = server::Config::default();
    config
        .keys
        .push(PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap());
    let config = Arc::new(config);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let _ = server::run_stream(config, socket, AcceptCertificates)
            .await
            .unwrap();
    });

    client::connect(Arc::new(client::Config::default()), addr, AcceptServerKey)
        .await
        .unwrap()
}

#[tokio::test]
async fn rsa_certificate_authenticates_with_every_hash() {
    let key =
        Arc::new(PrivateKey::random(&mut rand::rng(), Algorithm::Rsa { hash: None }).unwrap());
    let ca = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
    let mut builder =
        Builder::new_with_random_nonce(&mut rand::rng(), key.public_key().clone(), 0, u64::MAX)
            .unwrap();
    builder.cert_type(CertType::User).unwrap();
    builder.valid_principal("alice").unwrap();
    let cert = builder.sign(&ca).unwrap();

    for hash in [None, Some(HashAlg::Sha256), Some(HashAlg::Sha512)] {
        let result = connect()
            .await
            .authenticate_openssh_cert(
                "alice",
                PrivateKeyWithHashAlg::new(key.clone(), hash),
                cert.clone(),
            )
            .await
            .unwrap();
        assert!(result.success(), "hash {hash:?}: {result:?}");
    }
}
