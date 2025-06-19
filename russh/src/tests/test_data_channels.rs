use super::test_framework::*;
use crate::ChannelId;

#[tokio::test]
async fn test_basic_auth_and_channel() -> Result<(), TestError> {
    let context = TestFramework::setup().await?;

    let actions = vec![
        Action::ClientAuthenticate {
            user: "testuser".to_string(),
        },
        Action::ClientOpenSession,
    ];

    let expected_events = vec![
        ExpectedEvent::ServerAuthPublickey {
            user: "testuser".to_string(),
        },
        ExpectedEvent::ServerChannelOpenSession,
        ExpectedEvent::ClientCheckServerKey,
    ];

    TestFramework::run_test(context, actions, expected_events).await
}

#[tokio::test]
async fn test_data_exchange() -> Result<(), TestError> {
    let context = TestFramework::setup().await?;

    let actions = vec![
        Action::ClientAuthenticate {
            user: "testuser".to_string(),
        },
        Action::ClientOpenSession,
        Action::ClientSendData {
            channel: ChannelId(0),
            data: b"hello world".to_vec(),
        },
    ];

    let expected_events = vec![
        ExpectedEvent::ServerAuthPublickey {
            user: "testuser".to_string(),
        },
        ExpectedEvent::ServerChannelOpenSession,
        ExpectedEvent::ServerData {
            channel: ChannelId(2), // russh assigns channel ID 2 internally
            data: b"hello world".to_vec(),
        },
        ExpectedEvent::ClientCheckServerKey,
    ];

    TestFramework::run_test(context, actions, expected_events).await
}

#[tokio::test]
async fn test_bidirectional_data_exchange() -> Result<(), TestError> {
    let context = TestFramework::setup().await?;

    let actions = vec![
        Action::ClientAuthenticate {
            user: "testuser".to_string(),
        },
        Action::ClientOpenSession,
        Action::ClientSendData {
            channel: ChannelId(0),
            data: b"client hello".to_vec(),
        },
    ];

    let expected_events = vec![
        ExpectedEvent::ServerAuthPublickey {
            user: "testuser".to_string(),
        },
        ExpectedEvent::ServerChannelOpenSession,
        ExpectedEvent::ServerData {
            channel: ChannelId(2), // russh assigns channel ID 2 internally
            data: b"client hello".to_vec(),
        },
        ExpectedEvent::ClientCheckServerKey,
    ];

    TestFramework::run_test(context, actions, expected_events).await
}

#[tokio::test]
#[should_panic(expected = "EventMismatch")]
async fn test_exact_event_order_failure() {
    let context = TestFramework::setup().await.unwrap();

    let actions = vec![
        Action::ClientAuthenticate {
            user: "testuser".to_string(),
        },
        Action::ClientOpenSession,
    ];

    // Intentionally wrong order to demonstrate exact matching
    let wrong_expected_events = vec![
        ExpectedEvent::ClientCheckServerKey, // This should be last, not first
        ExpectedEvent::ServerAuthPublickey {
            user: "testuser".to_string(),
        },
        ExpectedEvent::ServerChannelOpenSession,
    ];

    // This should fail because the order is wrong
    TestFramework::run_test(context, actions, wrong_expected_events)
        .await
        .unwrap();
}
