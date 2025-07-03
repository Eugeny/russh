use super::test_framework::*;
use crate::cipher::ALL_CIPHERS;
use crate::mac::ALL_MAC_ALGORITHMS;
use crate::tests::test_init;

/// Configuration for cipher and MAC algorithm testing
#[derive(Debug, Clone)]
pub(crate) struct CryptoTestConfig {
    /// The preferred algorithms to test
    pub preferred: crate::Preferred,
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
            preferred: crate::Preferred::default(),
            user: None,
            additional_actions: Vec::new(),
            additional_expected_events: Vec::new(),
        }
    }
}

impl CryptoTestConfig {
    /// Create a new config with the specified preferred algorithms
    pub fn with_preferred(preferred: crate::Preferred) -> Self {
        Self {
            preferred,
            ..Default::default()
        }
    }

    /// Create a new config with the specified cipher
    pub fn with_cipher(cipher: crate::cipher::Name) -> Self {
        let mut preferred = crate::Preferred::default();
        preferred.cipher = vec![cipher].into();
        Self {
            preferred,
            ..Default::default()
        }
    }

    /// Create a new config with the specified MAC algorithm
    pub fn with_mac(mac: crate::mac::Name) -> Self {
        let mut preferred = crate::Preferred::default();
        // Use AES-128-CTR as the cipher since it supports MACs
        preferred.cipher = vec![crate::cipher::AES_128_CTR].into();
        preferred.mac = vec![mac].into();
        Self {
            preferred,
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

/// Create a server config with specified preferred algorithms
pub fn server_config_with_preferred(preferred: crate::Preferred) -> Result<crate::server::Config, TestError> {
    let server_key =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .map_err(|e| TestError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    Ok(crate::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(10)),
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![server_key],
        preferred,
        ..Default::default()
    })
}

/// Create a client config with specified preferred algorithms
pub fn client_config_with_preferred(preferred: crate::Preferred) -> Result<crate::client::Config, TestError> {
    Ok(crate::client::Config {
        preferred,
        ..Default::default()
    })
}

/// Unified method to test crypto algorithms with configurable parameters
pub async fn test_crypto_with_config(config: CryptoTestConfig) -> Result<(), TestError> {
    let user = config.get_user().to_string();
    let additional_actions = config.additional_actions;
    let additional_expected_events = config.additional_expected_events;

    let server_config = server_config_with_preferred(config.preferred.clone())?;
    let client_config = client_config_with_preferred(config.preferred)?;

    let context = TestFramework::setup_with_configs(Some(server_config), Some(client_config)).await?;

    // Build the actions: basic auth and session + any additional actions
    let mut actions = vec![
        Action::ClientAuthenticate { user: user.clone() },
        Action::ClientOpenSession,
    ];
    actions.extend(additional_actions);

    // Build expected events: basic auth and session + any additional events
    let mut expected_events = vec![
        ExpectedEvent::ServerAuthPublickey { user: user.clone() },
        ExpectedEvent::ServerChannelOpenSession,
        ExpectedEvent::ClientCheckServerKey,
    ];
    expected_events.extend(additional_expected_events);

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
