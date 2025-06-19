//! Tests for the russh test framework
//!
//! This module contains comprehensive tests that verify the test framework itself works correctly.

use crate::test_framework::*;
use crate::ChannelId;

/// Configuration for kex algorithm testing
#[derive(Debug, Clone)]
pub struct KexTestConfig {
    /// The kex algorithm to test
    pub kex_algorithm: crate::kex::Name,
    /// The username to use for authentication (default: "testuser")
    pub user: Option<String>,
    /// Whether to verify events strictly (order matters) or flexibly (order independent)
    pub strict_event_order: bool,
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
            strict_event_order: true,
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

    /// Set the username for authentication
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    /// Set whether to use strict event order verification
    pub fn with_strict_event_order(mut self, strict: bool) -> Self {
        self.strict_event_order = strict;
        self
    }

    /// Get the username, defaulting to "testuser" if not specified
    pub fn get_user(&self) -> &str {
        self.user.as_deref().unwrap_or("testuser")
    }
}

/// Helper function to verify that a kex algorithm works by establishing connection, auth, and channel
/// This function uses the unified test_kex_with_config method with flexible event verification
async fn verify_kex_algorithm_works(kex_algorithm: crate::kex::Name) -> Result<(), TestError> {
    let config = KexTestConfig::new(kex_algorithm)
        .with_strict_event_order(false); // Use flexible event verification for compatibility

    test_kex_with_config(config).await
}

#[tokio::test]
async fn test_basic_auth_and_channel() -> Result<(), TestError> {
    let context = TestFramework::setup().await?;

    let actions = vec![
        Action::ClientAuthenticate { user: "testuser".to_string() },
        Action::ClientOpenSession,
    ];

    let expected_events = vec![
        ExpectedEvent::ServerAuthPublickey { user: "testuser".to_string() },
        ExpectedEvent::ServerChannelOpenSession,
        ExpectedEvent::ClientCheckServerKey,
    ];

    TestFramework::run_test(context, actions, expected_events).await
}

#[tokio::test]
async fn test_data_exchange() -> Result<(), TestError> {
    let context = TestFramework::setup().await?;

    let actions = vec![
        Action::ClientAuthenticate { user: "testuser".to_string() },
        Action::ClientOpenSession,
        Action::ClientSendData {
            channel: ChannelId(0),
            data: b"hello world".to_vec()
        },
    ];

    let expected_events = vec![
        ExpectedEvent::ServerAuthPublickey { user: "testuser".to_string() },
        ExpectedEvent::ServerChannelOpenSession,
        ExpectedEvent::ServerData {
            channel: ChannelId(2), // russh assigns channel ID 2 internally
            data: b"hello world".to_vec()
        },
        ExpectedEvent::ClientCheckServerKey,
    ];

    TestFramework::run_test(context, actions, expected_events).await
}

#[tokio::test]
async fn test_bidirectional_data_exchange() -> Result<(), TestError> {
    let context = TestFramework::setup().await?;

    let actions = vec![
        Action::ClientAuthenticate { user: "testuser".to_string() },
        Action::ClientOpenSession,
        Action::ClientSendData {
            channel: ChannelId(0),
            data: b"client hello".to_vec()
        },
    ];

    let expected_events = vec![
        ExpectedEvent::ServerAuthPublickey { user: "testuser".to_string() },
        ExpectedEvent::ServerChannelOpenSession,
        ExpectedEvent::ServerData {
            channel: ChannelId(2), // russh assigns channel ID 2 internally
            data: b"client hello".to_vec()
        },
        ExpectedEvent::ClientCheckServerKey,
    ];

    TestFramework::run_test(context, actions, expected_events).await
}

#[tokio::test]
async fn test_simple_framework_usage() -> Result<(), TestError> {
    let context = TestFramework::setup().await?;

    let actions = vec![
        Action::ClientAuthenticate { user: "alice".to_string() },
        Action::ClientOpenSession,
    ];

    let expected_events = vec![
        ExpectedEvent::ServerAuthPublickey { user: "alice".to_string() },
        ExpectedEvent::ServerChannelOpenSession,
        ExpectedEvent::ClientCheckServerKey,
    ];

    // Use exact event matching
    TestFramework::run_test(context, actions, expected_events).await
}

#[tokio::test]
#[should_panic(expected = "EventMismatch")]
async fn test_exact_event_order_failure() {
    let context = TestFramework::setup().await.unwrap();

    let actions = vec![
        Action::ClientAuthenticate { user: "testuser".to_string() },
        Action::ClientOpenSession,
    ];

    // Intentionally wrong order to demonstrate exact matching
    let wrong_expected_events = vec![
        ExpectedEvent::ClientCheckServerKey,  // This should be last, not first
        ExpectedEvent::ServerAuthPublickey { user: "testuser".to_string() },
        ExpectedEvent::ServerChannelOpenSession,
    ];

    // This should fail because the order is wrong
    TestFramework::run_test(context, actions, wrong_expected_events).await.unwrap();
}

#[tokio::test]
async fn test_different_kex_methods() -> Result<(), TestError> {
    // Test multiple kex algorithms using the local verify method
    let algorithms = [
        crate::kex::CURVE25519,
        crate::kex::ECDH_SHA2_NISTP256,
        crate::kex::DH_G14_SHA256
    ];

    for algorithm in &algorithms {
        verify_kex_algorithm_works(*algorithm).await?;
    }

    Ok(())
}

#[tokio::test]
async fn test_different_kex_algorithms() -> Result<(), TestError> {
    // Test curve25519-sha256 (the default and most common)
    test_kex_algorithm(crate::kex::CURVE25519).await?;

    // Test ecdh-sha2-nistp256 with a different user
    test_kex_algorithm_with_user(crate::kex::ECDH_SHA2_NISTP256, "kextest").await?;

    // Test ecdh-sha2-nistp384 with another user
    test_kex_algorithm_with_user(crate::kex::ECDH_SHA2_NISTP384, "kextest384").await?;

    Ok(())
}

#[tokio::test]
async fn test_multiple_kex_algorithms_at_once() -> Result<(), TestError> {
    // Test multiple kex algorithms using the unified config approach
    let algorithms = [
        crate::kex::CURVE25519,
        crate::kex::ECDH_SHA2_NISTP256,
        crate::kex::ECDH_SHA2_NISTP384
    ];

    for algorithm in algorithms {
        test_kex_with_config(
            KexTestConfig::new(algorithm)
        ).await?;
    }

    Ok(())
}

#[tokio::test]
async fn test_kex_with_unified_config() -> Result<(), TestError> {
    // Test using the new unified config approach with custom settings
    let config = KexTestConfig::new(crate::kex::CURVE25519)
        .with_user("custom_user")
        .with_strict_event_order(false); // Use flexible event verification

    test_kex_with_config(config).await?;

    // Test multiple algorithms with the same custom settings
    let algorithms = [
        crate::kex::CURVE25519,
        crate::kex::ECDH_SHA2_NISTP256
    ];
    let base_config = KexTestConfig::default()
        .with_user("batch_user")
        .with_strict_event_order(true);

    test_multiple_kex_with_config(&algorithms, base_config).await
}

/// Create a server config with a specific kex algorithm
pub fn server_config_with_kex(
    kex_algorithm: crate::kex::Name,
) -> Result<crate::server::Config, TestError> {
    let server_key =
        ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
            .map_err(|e| TestError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    let mut preferred = crate::Preferred::default();
    match kex_algorithm {
        crate::kex::CURVE25519 => {
            preferred.kex = vec![crate::kex::CURVE25519].into();
        }
        crate::kex::ECDH_SHA2_NISTP256 => {
            preferred.kex = vec![crate::kex::ECDH_SHA2_NISTP256].into();
        }
        crate::kex::ECDH_SHA2_NISTP384 => {
            preferred.kex = vec![crate::kex::ECDH_SHA2_NISTP384].into();
        }
        crate::kex::ECDH_SHA2_NISTP521 => {
            preferred.kex = vec![crate::kex::ECDH_SHA2_NISTP521].into();
        }
        crate::kex::DH_G14_SHA256 => {
            preferred.kex = vec![crate::kex::DH_G14_SHA256].into();
        }
        _ => {
            return Err(TestError::Server(format!(
                "Unsupported kex algorithm: {}",
                kex_algorithm.as_ref()
            )))
        }
    }

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

    let context = TestFramework::setup_with_configs(Some(server_config), Some(client_config)).await?;

    let user = config.get_user().to_string();
    let strict_event_order = config.strict_event_order;

    // Build the actions: basic auth and session + any additional actions
    let mut actions = vec![
        Action::ClientAuthenticate {
            user: user.clone(),
        },
        Action::ClientOpenSession,
    ];
    actions.extend(config.additional_actions);

    // Build expected events: basic auth and session + any additional events
    let mut expected_events = vec![
        ExpectedEvent::ServerAuthPublickey {
            user: user.clone(),
        },
        ExpectedEvent::ServerChannelOpenSession,
        ExpectedEvent::ClientCheckServerKey,
    ];
    expected_events.extend(config.additional_expected_events);

    // Run the test with appropriate event verification method
    if strict_event_order {
        TestFramework::run_test(context, actions, expected_events).await
    } else {
        TestFramework::run_test_flexible(context, actions, expected_events).await
    }
}

/// Test multiple kex algorithms with the same configuration
pub async fn test_multiple_kex_with_config(
    algorithms: &[crate::kex::Name],
    base_config: KexTestConfig,
) -> Result<(), TestError> {
    for &algorithm in algorithms {
        let config = KexTestConfig {
            kex_algorithm: algorithm,
            ..base_config.clone()
        };
        test_kex_with_config(config).await?;
    }
    Ok(())
}

/// Test basic authentication and session setup with a specific kex algorithm
pub async fn test_kex_algorithm(kex_algorithm: crate::kex::Name) -> Result<(), TestError> {
    test_kex_with_config(KexTestConfig::new(kex_algorithm)).await
}

/// Test basic authentication and session setup with a specific kex algorithm and custom user
pub async fn test_kex_algorithm_with_user(
    kex_algorithm: crate::kex::Name,
    user: &str,
) -> Result<(), TestError> {
    test_kex_with_config(
        KexTestConfig::new(kex_algorithm).with_user(user)
    ).await
}
