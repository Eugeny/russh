use super::test_framework::*;
use crate::tests::test_init;
use crate::ChannelId;

/// Test direct-tcpip channel opening and basic data transfer
#[tokio::test]
async fn test_direct_tcpip_channel() {
    test_init();

    let context = TestFramework::setup().await.unwrap();

    let actions = vec![
        Action::ClientAuthenticate {
            user: "testuser".to_string(),
        },
        Action::ClientOpenDirectTcpip {
            host_to_connect: "127.0.0.1".to_string(),
            port_to_connect: 8080,
            originator_address: "192.168.1.100".to_string(),
            originator_port: 12345,
        },
        Action::ClientSendData {
            channel: ChannelId(0),
            data: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        },
    ];

    let expected_events = vec![
        ExpectedEvent::ServerAuthPublickey {
            user: "testuser".to_string(),
        },
        ExpectedEvent::ServerChannelOpenDirectTcpip {
            host_to_connect: "127.0.0.1".to_string(),
            port_to_connect: 8080,
            originator_address: "192.168.1.100".to_string(),
            originator_port: 12345,
        },
        ExpectedEvent::ServerData {
            channel: ChannelId(2), // Channel IDs are assigned by russh internally
            data: b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
        },
        ExpectedEvent::ClientCheckServerKey,
    ];

    TestFramework::run_test(context, actions, expected_events)
        .await
        .unwrap();
}

/// Test direct-tcpip channel with bidirectional data transfer
#[tokio::test]
async fn test_direct_tcpip_bidirectional() {
    test_init();

    let context = TestFramework::setup().await.unwrap();

    let actions = vec![
        Action::ClientAuthenticate {
            user: "testuser".to_string(),
        },
        Action::ClientOpenDirectTcpip {
            host_to_connect: "example.com".to_string(),
            port_to_connect: 443,
            originator_address: "10.0.0.1".to_string(),
            originator_port: 54321,
        },
        Action::ClientSendData {
            channel: ChannelId(0),
            data: b"Hello from client".to_vec(),
        },
        // Server sends data back after receiving client data
        Action::ServerSendData {
            channel: ChannelId(2), // Use the actual channel ID that will be assigned
            data: b"Hello from server".to_vec(),
        },
    ];

    let expected_events = vec![
        ExpectedEvent::ServerAuthPublickey {
            user: "testuser".to_string(),
        },
        ExpectedEvent::ServerChannelOpenDirectTcpip {
            host_to_connect: "example.com".to_string(),
            port_to_connect: 443,
            originator_address: "10.0.0.1".to_string(),
            originator_port: 54321,
        },
        ExpectedEvent::ServerData {
            channel: ChannelId(2), // Channel IDs are assigned by russh internally
            data: b"Hello from client".to_vec(),
        },
        ExpectedEvent::ClientCheckServerKey,
        ExpectedEvent::ClientData {
            channel: ChannelId(2), // Channel IDs are assigned by russh internally
            data: b"Hello from server".to_vec(),
        },
    ];

    TestFramework::run_test(context, actions, expected_events)
        .await
        .unwrap();
}

/// Test direct-tcpip channel closure
#[tokio::test]
async fn test_direct_tcpip_channel_close() {
    test_init();

    let context = TestFramework::setup().await.unwrap();

    let actions = vec![
        Action::ClientAuthenticate {
            user: "testuser".to_string(),
        },
        Action::ClientOpenDirectTcpip {
            host_to_connect: "192.168.1.1".to_string(),
            port_to_connect: 22,
            originator_address: "172.16.0.1".to_string(),
            originator_port: 40000,
        },
        Action::ClientSendData {
            channel: ChannelId(0),
            data: b"test data".to_vec(),
        },
        Action::ClientCloseChannel {
            channel: ChannelId(0),
        },
    ];

    let expected_events = vec![
        ExpectedEvent::ServerAuthPublickey {
            user: "testuser".to_string(),
        },
        ExpectedEvent::ServerChannelOpenDirectTcpip {
            host_to_connect: "192.168.1.1".to_string(),
            port_to_connect: 22,
            originator_address: "172.16.0.1".to_string(),
            originator_port: 40000,
        },
        ExpectedEvent::ServerData {
            channel: ChannelId(2), // Channel IDs are assigned by russh internally
            data: b"test data".to_vec(),
        },
        ExpectedEvent::ServerChannelClose {
            channel: ChannelId(2), // Channel IDs are assigned by russh internally
        },
        ExpectedEvent::ClientCheckServerKey,
    ];

    TestFramework::run_test(context, actions, expected_events)
        .await
        .unwrap();
}

/// Test multiple concurrent direct-tcpip channels
#[tokio::test]
async fn test_multiple_direct_tcpip_channels() {
    test_init();

    let context = TestFramework::setup().await.unwrap();

    let actions = vec![
        Action::ClientAuthenticate {
            user: "testuser".to_string(),
        },
        // First channel
        Action::ClientOpenDirectTcpip {
            host_to_connect: "host1.example.com".to_string(),
            port_to_connect: 80,
            originator_address: "client.local".to_string(),
            originator_port: 50000,
        },
        // Second channel
        Action::ClientOpenDirectTcpip {
            host_to_connect: "host2.example.com".to_string(),
            port_to_connect: 443,
            originator_address: "client.local".to_string(),
            originator_port: 50001,
        },
        // Send data to both channels
        Action::ClientSendData {
            channel: ChannelId(0),
            data: b"data for channel 1".to_vec(),
        },
        Action::ClientSendData {
            channel: ChannelId(1),
            data: b"data for channel 2".to_vec(),
        },
    ];

    let expected_events = vec![
        ExpectedEvent::ServerAuthPublickey {
            user: "testuser".to_string(),
        },
        ExpectedEvent::ServerChannelOpenDirectTcpip {
            host_to_connect: "host1.example.com".to_string(),
            port_to_connect: 80,
            originator_address: "client.local".to_string(),
            originator_port: 50000,
        },
        ExpectedEvent::ServerChannelOpenDirectTcpip {
            host_to_connect: "host2.example.com".to_string(),
            port_to_connect: 443,
            originator_address: "client.local".to_string(),
            originator_port: 50001,
        },
        ExpectedEvent::ServerData {
            channel: ChannelId(2), // First channel
            data: b"data for channel 1".to_vec(),
        },
        ExpectedEvent::ServerData {
            channel: ChannelId(3), // Second channel
            data: b"data for channel 2".to_vec(),
        },
        ExpectedEvent::ClientCheckServerKey,
    ];

    TestFramework::run_test(context, actions, expected_events)
        .await
        .unwrap();
}

// Note: For forwarded-tcpip tests, we would need to extend the test framework
// to support server-initiated channel opening actions. The current framework
// focuses on client-initiated actions. Here's a placeholder test structure:

/// Test forwarded-tcpip channel (server-initiated)
#[tokio::test]
async fn test_forwarded_tcpip_channel() {
    test_init();

    let context = TestFramework::setup().await.unwrap();

    let actions = vec![
        Action::ClientAuthenticate {
            user: "testuser".to_string(),
        },
        // First establish a session channel to get the server session handle
        Action::ClientOpenSession,
        // Now the server can initiate a forwarded-tcpip channel
        Action::ServerOpenForwardedTcpip {
            connected_address: "127.0.0.1".to_string(),
            connected_port: 8080,
            originator_address: "remote.host".to_string(),
            originator_port: 12345,
        },
    ];

    let expected_events = vec![
        ExpectedEvent::ServerAuthPublickey {
            user: "testuser".to_string(),
        },
        ExpectedEvent::ServerChannelOpenSession,
        ExpectedEvent::ClientCheckServerKey,
        ExpectedEvent::ClientServerChannelOpenForwardedTcpip {
            connected_address: "127.0.0.1".to_string(),
            connected_port: 8080,
            originator_address: "remote.host".to_string(),
            originator_port: 12345,
        },
    ];

    TestFramework::run_test(context, actions, expected_events)
        .await
        .unwrap();
}
