#![cfg(not(target_arch = "wasm32"))]
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::ssh_key::rand_core::OsRng;
use russh::keys::ssh_key::{self, Algorithm, HashAlg, PrivateKey};
use russh::*;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

#[tokio::test]
async fn test_server_certificate_auth() {
    let _ = env_logger::try_init();

    // Generate CA key
    let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let ca_public_key = ca_key.public_key();

    // Generate Server key
    let server_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let server_public_key = server_key.public_key();

    //. Create Server Certificate signed by CA
    let start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let end = start + 3600;

    let mut builder =
        Builder::new_with_random_nonce(&mut OsRng, server_public_key.clone(), start, end).unwrap();
    builder.serial(42).unwrap();
    builder.key_id("test-server").unwrap();
    builder.cert_type(CertType::Host).unwrap();
    builder.valid_principal("localhost").unwrap();

    let cert = builder.sign(&ca_key).unwrap();

    // Configure Server
    let mut config = server::Config::default();
    config.keys.push(server_key);
    config.certificates.push(cert);
    let config = Arc::new(config);

    // Start Server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_finished = Arc::new(Mutex::new(false));
    let server_finished_clone = server_finished.clone();

    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        server::run_stream(config, socket, TestServer {})
            .await
            .unwrap();
        *server_finished_clone.lock().unwrap() = true;
    });

    // Configure Client
    let mut client_config = client::Config::default();

    // Add certificate algorithm to preferred keys
    let mut preferred_keys = client_config.preferred.key.into_owned();
    preferred_keys.insert(
        0,
        Algorithm::from_str(&Algorithm::Ed25519.to_certificate_type()).unwrap(),
    );

    client_config.preferred.key = std::borrow::Cow::Owned(preferred_keys);
    client_config.preferred.kex =
        std::borrow::Cow::Owned(vec![russh::kex::CURVE25519, russh::kex::ECDH_SHA2_NISTP256]);
    let client_config = Arc::new(client_config);

    let client = TestClient {
        ca_public_key: ca_public_key.clone(),
        verified: Arc::new(Mutex::new(false)),
    };

    // Connect Client
    let session = client::connect(client_config, addr, client).await.unwrap();

    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}
#[tokio::test]
async fn test_server_wrong_ca_certificate_auth() {
    let _ = env_logger::try_init();

    //Generate CA key
    let ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let ca_public_key = ca_key.public_key();

    //Generate second CA key
    let evil_ca_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();

    assert_ne!(evil_ca_key, ca_key);

    // Generate Server key
    let server_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let server_public_key = server_key.public_key();

    // Create Server Certificate signed by CA
    // Builder::new_with_random_nonce(rng, public_key, valid_after, valid_before)
    let start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let end = start + 3600;

    let mut builder =
        Builder::new_with_random_nonce(&mut OsRng, server_public_key.clone(), start, end).unwrap();
    builder.serial(42).unwrap();
    builder.key_id("test-server").unwrap();
    builder.cert_type(CertType::Host).unwrap();
    builder.valid_principal("localhost").unwrap();

    let cert = builder.sign(&evil_ca_key).unwrap();

    // Configure Server
    let mut config = server::Config::default();
    config.keys.push(server_key);
    config.certificates.push(cert);
    let config = Arc::new(config);

    // Start Server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_finished = Arc::new(Mutex::new(false));
    let server_finished_clone = server_finished.clone();

    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        server::run_stream(config, socket, TestServer {})
            .await
            .unwrap();
        *server_finished_clone.lock().unwrap() = true;
    });

    // Configure Client
    let mut client_config = client::Config::default();

    // Add certificate algorithm to preferred keys
    let mut preferred_keys = client_config.preferred.key.into_owned();
    preferred_keys.insert(
        0,
        Algorithm::from_str(&Algorithm::Ed25519.to_certificate_type()).unwrap(),
    );

    client_config.preferred.key = std::borrow::Cow::Owned(preferred_keys);
    client_config.preferred.kex =
        std::borrow::Cow::Owned(vec![russh::kex::CURVE25519, russh::kex::ECDH_SHA2_NISTP256]);
    let client_config = Arc::new(client_config);

    let client = TestClient {
        ca_public_key: ca_public_key.clone(),
        verified: Arc::new(Mutex::new(false)),
    };

    // Connect Client
    if let Ok(session) = client::connect(client_config, addr, client).await {
        session
            .disconnect(Disconnect::ByApplication, "", "")
            .await
            .unwrap();
        panic!("client connected to server with wrong ca in certificate");
    }
}

#[tokio::test]
async fn test_server_rsa_sha2_512_certificate_auth() {
    let _ = env_logger::try_init();

    // Generate CA key (RSA, SHA-512)
    let ca_key = PrivateKey::random(
        &mut OsRng,
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        },
    )
    .unwrap();
    let ca_public_key = ca_key.public_key();

    // Generate Server key (RSA, SHA-512)
    let server_key = PrivateKey::random(
        &mut OsRng,
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        },
    )
    .unwrap();
    let server_public_key = server_key.public_key();

    // Create Server Certificate signed by CA
    let start = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let end = start + 3600;

    let mut builder =
        Builder::new_with_random_nonce(&mut OsRng, server_public_key.clone(), start, end).unwrap();
    builder.serial(42).unwrap();
    builder.key_id("test-server-rsa").unwrap();
    builder.cert_type(CertType::Host).unwrap();
    builder.valid_principal("localhost").unwrap();

    let cert = builder.sign(&ca_key).unwrap();

    // Configure Server
    let mut config = server::Config::default();
    config.keys.push(server_key);
    config.certificates.push(cert);
    let config = Arc::new(config);

    // Start Server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_finished = Arc::new(Mutex::new(false));
    let server_finished_clone = server_finished.clone();

    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        server::run_stream(config, socket, TestServer {})
            .await
            .unwrap();
        *server_finished_clone.lock().unwrap() = true;
    });

    // Configure Client
    let mut client_config = client::Config::default();

    // Advertise rsa-sha2-512-cert-v01@openssh.com as first preferred host key algorithm
    let cert_algo_str = Algorithm::Rsa {
        hash: Some(HashAlg::Sha512),
    }
    .to_certificate_type();
    let mut preferred_keys = client_config.preferred.key.into_owned();
    preferred_keys.insert(0, Algorithm::from_str(&cert_algo_str).unwrap());

    client_config.preferred.key = std::borrow::Cow::Owned(preferred_keys);
    client_config.preferred.kex =
        std::borrow::Cow::Owned(vec![russh::kex::CURVE25519, russh::kex::ECDH_SHA2_NISTP256]);
    let client_config = Arc::new(client_config);

    let client = TestClient {
        ca_public_key: ca_public_key.clone(),
        verified: Arc::new(Mutex::new(false)),
    };

    // Connect Client — must succeed and certificate must validate
    let session = client::connect(client_config, addr, client).await.unwrap();

    session
        .disconnect(Disconnect::ByApplication, "", "")
        .await
        .unwrap();
}
struct TestServer {}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: &ssh_key::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }
}

struct TestClient {
    ca_public_key: ssh_key::PublicKey,
    verified: Arc<Mutex<bool>>,
}

impl client::Handler for TestClient {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::cert::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        println!("check_server_key: {server_public_key:?}");
        match server_public_key {
            russh::cert::PublicKeyOrCertificate::Certificate(cert) => {
                // Perform the signature verification using your trusted CA public key.
                // This checks if the certificate was genuinely signed by your CA.
                let fingerprint = self.ca_public_key.fingerprint(HashAlg::Sha256);
                if let Err(e) = cert.validate([&fingerprint]) {
                    eprintln!("Host certificate signature verification failed: {}", e);
                    return Ok(false);
                }

                // Check the certificate's validity period.
                let current_unix_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                if current_unix_time < cert.valid_after() || current_unix_time > cert.valid_before()
                {
                    eprintln!("Host certificate is outside its validity period.");
                    return Ok(false);
                }

                // (Optional but recommended) Check the certificate's valid principals.
                let target_hostname = "localhost";
                if !cert
                    .valid_principals()
                    .contains(&target_hostname.to_string())
                {
                    eprintln!(
                        "Host certificate is not valid for principal: {}",
                        target_hostname
                    );
                    return Ok(false);
                }

                // If all checks pass, the certificate is valid.
                println!("Host certificate successfully validated.");
                Ok(true)
            }
            russh::cert::PublicKeyOrCertificate::PublicKey { .. } => {
                // If the server presents a plain public key (not a certificate), decide
                // whether to accept it. For certificate-only environments, you might reject.
                eprintln!("Server presented a plain public key, not a certificate.");
                Ok(false)
            }
        }
    }
}
