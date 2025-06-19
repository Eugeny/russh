use super::test_framework::*;
use crate::kex::ALL_KEX_ALGORITHMS;
use crate::tests::test_init;

/// Configuration for kex algorithm testing
#[derive(Debug, Clone)]
pub(crate) struct KexTestConfig {
    /// The kex algorithm to test
    pub kex_algorithm: crate::kex::Name,
    /// The username to use for authentication (default: "testuser")
    pub user: Option<String>,
    /// Additional actions to perform after basic auth and session setup
    pub additional_actions: Vec<Action>,
    /// Additional expected events beyond the basic auth and session events
    pub additional_expected_events: Vec<ExpectedEvent>,
}

impl Default for KexTestConfig {
    fn default() -> Self {
        Self {
            kex_algorithm: crate::kex::CURVE25519,
            user: None,
            additional_actions: Vec::new(),
            additional_expected_events: Vec::new(),
        }
    }
}

impl KexTestConfig {
    /// Create a new config with the specified kex algorithm
    pub fn new(kex_algorithm: crate::kex::Name) -> Self {
        Self {
            kex_algorithm,
            ..Default::default()
        }
    }

    /// Get the username, defaulting to "testuser" if not specified
    pub fn get_user(&self) -> &str {
        self.user.as_deref().unwrap_or("testuser")
    }
}

#[tokio::test]
async fn test_all_kex_algorithms() -> Result<(), TestError> {
    test_init();

    for &algorithm in ALL_KEX_ALGORITHMS {
        if algorithm == &crate::kex::NONE {
            continue;
        }

        println!("- {}", algorithm.as_ref());

        // Test basic functionality
        test_kex_algorithm(*algorithm)
            .await
            .map_err(|e| TestError::Client(format!("Failed testing {}: {}", algorithm.as_ref(), e)))
            .unwrap();
    }

    Ok(())
}

/// Create a server config with a specific kex algorithm
pub fn server_config_with_kex(
    kex_algorithm: crate::kex::Name,
) -> Result<crate::server::Config, TestError> {
    let server_key =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .map_err(|e| TestError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    let mut preferred = crate::Preferred::default();
    preferred.kex = vec![kex_algorithm].into();

    Ok(crate::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(10)),
        auth_rejection_time: std::time::Duration::from_secs(1),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![server_key],
        preferred,
        ..Default::default()
    })
}

/// Create a client config with a specific kex algorithm
pub fn client_config_with_kex(
    kex_algorithm: crate::kex::Name,
) -> Result<crate::client::Config, TestError> {
    let mut preferred = crate::Preferred::default();
    preferred.kex = vec![kex_algorithm].into();

    Ok(crate::client::Config {
        preferred,
        ..Default::default()
    })
}

/// Unified method to test kex algorithms with configurable parameters
pub async fn test_kex_with_config(config: KexTestConfig) -> Result<(), TestError> {
    let server_config = server_config_with_kex(config.kex_algorithm)?;
    let client_config = client_config_with_kex(config.kex_algorithm)?;

    let context =
        TestFramework::setup_with_configs(Some(server_config), Some(client_config)).await?;

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

/// Test basic authentication and session setup with a specific kex algorithm
pub async fn test_kex_algorithm(kex_algorithm: crate::kex::Name) -> Result<(), TestError> {
    test_kex_with_config(KexTestConfig::new(kex_algorithm)).await
}
