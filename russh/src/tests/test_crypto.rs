use super::test_framework::*;
use crate::cipher::ALL_CIPHERS;
use crate::mac::ALL_MAC_ALGORITHMS;
use crate::tests::test_init;

/// Configuration for cipher and MAC algorithm testing
#[derive(Debug, Clone)]
pub(crate) struct CryptoTestConfig {
    /// The cipher to test (optional, uses default if None)
    pub cipher: Option<crate::cipher::Name>,
    /// The MAC algorithm to test (optional, uses default if None)
    pub mac: Option<crate::mac::Name>,
    /// The username to use for authentication (default: "testuser")
    pub user: Option<String>,
    /// Additional actions to perform after basic auth and session setup
    pub additional_actions: Vec<Action>,
    /// Additional expected events beyond the basic auth and session events
    pub additional_expected_events: Vec<ExpectedEvent>,
}

impl Default for CryptoTestConfig {
    fn default() -> Self {
        Self {
            cipher: None,
            mac: None,
            user: None,
            additional_actions: Vec::new(),
            additional_expected_events: Vec::new(),
        }
    }
}

impl CryptoTestConfig {
    /// Create a new config with the specified cipher
    pub fn with_cipher(cipher: crate::cipher::Name) -> Self {
        Self {
            cipher: Some(cipher),
            ..Default::default()
        }
    }

    /// Create a new config with the specified MAC algorithm
    pub fn with_mac(mac: crate::mac::Name) -> Self {
        Self {
            mac: Some(mac),
            ..Default::default()
        }
    }

    /// Get the username, defaulting to "testuser" if not specified
    pub fn get_user(&self) -> &str {
        self.user.as_deref().unwrap_or("testuser")
    }
}

/// Test all supported cipher algorithms
#[tokio::test]
async fn test_all_ciphers() -> Result<(), TestError> {
    test_init();

    for &cipher in ALL_CIPHERS {
        // Skip insecure/testing ciphers in comprehensive tests
        if cipher == &crate::cipher::CLEAR || cipher == &crate::cipher::NONE {
            continue;
        }

        println!("Testing cipher: {}", cipher.as_ref());

        test_cipher(*cipher)
            .await
            .map_err(|e| TestError::Client(format!("Failed testing cipher {}: {}", cipher.as_ref(), e)))
            .unwrap();
    }

    Ok(())
}

/// Test all supported MAC algorithms
#[tokio::test]
async fn test_all_macs() -> Result<(), TestError> {
    test_init();

    for &mac_alg in ALL_MAC_ALGORITHMS {
        // Skip NONE MAC for this test as we want to test actual MAC algorithms
        if mac_alg == &crate::mac::NONE {
            continue;
        }

        println!("Testing MAC: {}", mac_alg.as_ref());

        test_mac(*mac_alg)
            .await
            .map_err(|e| TestError::Client(format!("Failed testing MAC {}: {}", mac_alg.as_ref(), e)))
            .unwrap();
    }

    Ok(())
}

/// Create a server config with a specific cipher
pub fn server_config_with_cipher(cipher: crate::cipher::Name) -> Result<crate::server::Config, TestError> {
    let server_key =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .map_err(|e| TestError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    let mut preferred = crate::Preferred::default();
    preferred.cipher = vec![cipher].into();

    Ok(crate::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(10)),
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![server_key],
        preferred,
        ..Default::default()
    })
}

/// Create a client config with a specific cipher
pub fn client_config_with_cipher(cipher: crate::cipher::Name) -> Result<crate::client::Config, TestError> {
    let mut preferred = crate::Preferred::default();
    preferred.cipher = vec![cipher].into();

    Ok(crate::client::Config {
        preferred,
        ..Default::default()
    })
}

/// Create a server config with a specific MAC algorithm
pub fn server_config_with_mac(mac: crate::mac::Name) -> Result<crate::server::Config, TestError> {
    let server_key =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .map_err(|e| TestError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    let mut preferred = crate::Preferred::default();
    // Use AES-128-CTR as the cipher since it supports MACs
    preferred.cipher = vec![crate::cipher::AES_128_CTR].into();
    preferred.mac = vec![mac].into();

    Ok(crate::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(10)),
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![server_key],
        preferred,
        ..Default::default()
    })
}

/// Create a client config with a specific MAC algorithm
pub fn client_config_with_mac(mac: crate::mac::Name) -> Result<crate::client::Config, TestError> {
    let mut preferred = crate::Preferred::default();
    // Use AES-128-CTR as the cipher since it supports MACs
    preferred.cipher = vec![crate::cipher::AES_128_CTR].into();
    preferred.mac = vec![mac].into();

    Ok(crate::client::Config {
        preferred,
        ..Default::default()
    })
}

/// Unified method to test crypto algorithms with configurable parameters
pub async fn test_crypto_with_config(config: CryptoTestConfig) -> Result<(), TestError> {
    let (server_config, client_config) = match (config.cipher, config.mac) {
        (Some(cipher), None) => (
            server_config_with_cipher(cipher)?,
            client_config_with_cipher(cipher)?,
        ),
        (None, Some(mac)) => (
            server_config_with_mac(mac)?,
            client_config_with_mac(mac)?,
        ),
        (Some(_), Some(_)) => {
            return Err(TestError::Client("Cannot test both cipher and MAC in the same config".to_string()));
        },
        (None, None) => {
            return Err(TestError::Client("Must specify either cipher or MAC to test".to_string()));
        },
    };

    let context = TestFramework::setup_with_configs(Some(server_config), Some(client_config)).await?;

    let user = config.get_user().to_string();

    // Build the actions: basic auth and session + any additional actions
    let mut actions = vec![
        Action::ClientAuthenticate { user: user.clone() },
        Action::ClientOpenSession,
    ];
    actions.extend(config.additional_actions);

    // Build expected events: basic auth and session + any additional events
    let mut expected_events = vec![
        ExpectedEvent::ServerAuthPublickey { user: user.clone() },
        ExpectedEvent::ServerChannelOpenSession,
        ExpectedEvent::ClientCheckServerKey,
    ];
    expected_events.extend(config.additional_expected_events);

    // Run the test with strict event verification
    TestFramework::run_test(context, actions, expected_events).await
}

/// Test basic authentication and session setup with a specific cipher
pub async fn test_cipher(cipher: crate::cipher::Name) -> Result<(), TestError> {
    test_crypto_with_config(CryptoTestConfig::with_cipher(cipher)).await
}

/// Test basic authentication and session setup with a specific MAC algorithm
pub async fn test_mac(mac: crate::mac::Name) -> Result<(), TestError> {
    test_crypto_with_config(CryptoTestConfig::with_mac(mac)).await
}
