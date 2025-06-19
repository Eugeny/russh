//! # Test Framework for russh
//!
//! This module provides a simple test framework for the russh crate that allows you to:
//!
//! - Set up a connected client and server pair using in-memory pipes (tokio::io::duplex)
//! - Define sequences of actions to perform on the client or server
//! - Define expected events that should occur in response
//! - Verify that the expected events actually happen
//!
//! The framework implementation is in this file, while tests for the framework itself
//! are located in `test_framework_tests.rs`.
//!
//! ## Example Usage
//!
//! ### Basic Usage with Framework Execution
//!
//! ```rust,no_run
//! # use russh::test_framework::*;
//! # tokio_test::block_on(async {
//! let context = TestFramework::setup().await?;
//!
//! let actions = vec![
//!     Action::ClientAuthenticate { user: "testuser".to_string() },
//!     Action::ClientOpenSession,
//!     Action::ClientSendData {
//!         channel: ChannelId(0),
//!         data: b"hello world".to_vec()
//!     },
//! ];
//!
//! let expected_events = vec![
//!     ExpectedEvent::ServerAuthPublickey { user: "testuser".to_string() },
//!     ExpectedEvent::ServerChannelOpenSession,
//!     ExpectedEvent::ClientCheckServerKey,
//! ];
//!
//! // Use exact event matching (order and content must match exactly)
//! TestFramework::run_test(context, actions, expected_events).await?;
//!
//! # Ok::<(), TestError>(())
//! # });
//! ```
//!
//! ### Advanced Usage with Manual Control
//!
//! ```rust,no_run
//! # use russh::test_framework::*;
//! # tokio_test::block_on(async {
//! let context = TestFramework::setup().await?;
//! let mut context = context;
//!
//! // Execute actions through the framework
//! TestFramework::execute_actions(&mut context, vec![
//!     Action::ClientAuthenticate { user: "testuser".to_string() },
//!     Action::ClientOpenSession,
//! ]).await?;
//!
//! // Custom event verification logic
//! tokio::time::sleep(std::time::Duration::from_millis(100)).await;
//! let events = /* gather events */;
//! // ... custom verification ...
//!
//! # Ok::<(), TestError>(())
//! # });
//! ```

//! ## Features
//!
//! - **In-memory connections**: Uses `tokio::io::duplex` for fast, deterministic testing
//! - **Event tracking**: Automatically records Handler method calls from both client and server
//! - **Action scripting**: Define sequences of client and server actions to execute
//! - **Event verification**: Verify that expected events occur in exact order and content
//! - **Exact matching**: Compare actual events against expected event arrays with precise order checking
//! - **Server-side actions**: Send data and close channels from the server side using commands
//!
//! ## Limitations
//!
//! - **Event ordering**: Event order is strictly enforced (use `run_test_flexible` for order-independent checking)
//! - **Channel IDs**: Channel IDs are assigned by russh internally and may differ from action parameters
//! - **Server-side actions**: Server-side actions use a command channel mechanism that may not reflect real usage
//!
//! ## API Methods
//!
//! - **`TestFramework::setup()`**: Creates a connected client/server pair
//! - **`TestFramework::execute_action(context, action)`**: Executes a single action
//! - **`TestFramework::execute_actions(context, actions)`**: Executes multiple actions
//! - **`TestFramework::run_test(context, actions, events)`**: Executes actions and verifies events (exact order and content match)
//! - **`TestFramework::run_test_flexible(context, actions, events)`**: Executes actions and verifies events (order-independent, for compatibility)
//!
//! ## Extending the Framework
//!
//! To add support for more SSH operations:
//!
//! 1. Add new variants to the `Action` enum
//! 2. Add corresponding variants to the `ExpectedEvent` enum
//! 3. Implement the action in `TestFramework::execute_action()`
//! 4. Add event recording in the appropriate handler methods
//!

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::channels::Channel;
use crate::client::{
    self, Handle as ClientHandle, Handler as ClientHandler, Session as ClientSession,
};
use crate::server::{
    self, Auth, Handler as ServerHandler, Msg as ServerMsg, Session as ServerSession,
};
use crate::{ChannelId, Error};

/// Commands that can be sent to the server handler
#[derive(Debug)]
pub enum ServerCommand {
    SendData {
        channel_id: ChannelId,
        data: Vec<u8>,
    },
    CloseChannel {
        channel_id: ChannelId,
    },
}

/// Represents an action that can be performed on the client or server
#[derive(Debug, Clone)]
pub enum Action {
    /// Client calls channel_open_session
    ClientOpenSession,
    /// Client sends data to a channel
    ClientSendData { channel: ChannelId, data: Vec<u8> },
    /// Client closes a channel
    ClientCloseChannel { channel: ChannelId },
    /// Server sends data to a channel
    ServerSendData { channel: ChannelId, data: Vec<u8> },
    /// Server closes a channel
    ServerCloseChannel { channel: ChannelId },
    /// Client authenticates with publickey
    ClientAuthenticate { user: String },
}

/// Represents an expected event (handler method call)
#[derive(Debug, Clone, PartialEq)]
pub enum ExpectedEvent {
    /// Server handler auth_publickey was called
    ServerAuthPublickey { user: String },
    /// Server handler channel_open_session was called
    ServerChannelOpenSession,
    /// Server handler data was called
    ServerData { channel: ChannelId, data: Vec<u8> },
    /// Server handler channel_close was called
    ServerChannelClose { channel: ChannelId },
    /// Client handler data was called
    ClientData { channel: ChannelId, data: Vec<u8> },
    /// Client handler channel_close was called
    ClientChannelClose { channel: ChannelId },
    /// Client handler check_server_key was called
    ClientCheckServerKey,
    /// Server key exchange algorithm was selected
    ServerKexAlgorithm { algorithm: String },
    /// Client key exchange algorithm was selected
    ClientKexAlgorithm { algorithm: String },
}

/// Test framework error
#[derive(Debug, thiserror::Error)]
pub enum TestError {
    #[error("Russh error: {0}")]
    Russh(#[from] Error),
    #[error("Server error: {0}")]
    Server(String),
    #[error("Client error: {0}")]
    Client(String),
    #[error("Expected event {expected:?} but got {actual:?}")]
    EventMismatch {
        expected: ExpectedEvent,
        actual: ExpectedEvent,
    },
    #[error("Expected {expected} events but got {actual}")]
    EventCountMismatch { expected: usize, actual: usize },
    #[error("Channel not found: {0}")]
    ChannelNotFound(ChannelId),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Handler that tracks events for testing
#[derive(Debug)]
struct TestServerHandler {
    events: Arc<tokio::sync::Mutex<VecDeque<ExpectedEvent>>>,
    channels: Arc<tokio::sync::Mutex<HashMap<ChannelId, Channel<ServerMsg>>>>,
    command_rx: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<ServerCommand>>>,
}

impl TestServerHandler {
    fn new(
        events: Arc<tokio::sync::Mutex<VecDeque<ExpectedEvent>>>,
        command_rx: mpsc::UnboundedReceiver<ServerCommand>,
    ) -> Self {
        Self {
            events,
            channels: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            command_rx: Arc::new(tokio::sync::Mutex::new(command_rx)),
        }
    }

    async fn record_event(&self, event: ExpectedEvent) {
        let mut events = self.events.lock().await;
        events.push_back(event);
    }

    async fn process_commands(&self) {
        let mut command_rx = self.command_rx.lock().await;
        while let Ok(command) = command_rx.try_recv() {
            match command {
                ServerCommand::SendData { channel_id, data } => {
                    let channels = self.channels.lock().await;
                    if let Some(channel) = channels.get(&channel_id) {
                        if let Err(e) = channel.data(&data[..]).await {
                            eprintln!("Failed to send data to channel {:?}: {:?}", channel_id, e);
                        }
                    }
                }
                ServerCommand::CloseChannel { channel_id } => {
                    let channels = self.channels.lock().await;
                    if let Some(channel) = channels.get(&channel_id) {
                        if let Err(e) = channel.close().await {
                            eprintln!("Failed to close channel {:?}: {:?}", channel_id, e);
                        }
                    }
                }
            }
        }
    }
}

#[cfg_attr(feature = "async-trait", async_trait::async_trait)]
impl ServerHandler for TestServerHandler {
    type Error = TestError;

    async fn auth_publickey(
        &mut self,
        user: &str,
        _public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.record_event(ExpectedEvent::ServerAuthPublickey {
            user: user.to_string(),
        })
        .await;
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<ServerMsg>,
        _session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        let channel_id = channel.id();
        self.record_event(ExpectedEvent::ServerChannelOpenSession)
            .await;

        // Store the channel for later use
        let mut channels = self.channels.lock().await;
        channels.insert(channel_id, channel);

        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.record_event(ExpectedEvent::ServerData {
            channel,
            data: data.to_vec(),
        })
        .await;

        // Process any pending commands
        self.process_commands().await;

        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.record_event(ExpectedEvent::ServerChannelClose { channel })
            .await;
        Ok(())
    }
}

/// Client handler that tracks events for testing
#[derive(Debug)]
struct TestClientHandler {
    events: Arc<tokio::sync::Mutex<VecDeque<ExpectedEvent>>>,
}

impl TestClientHandler {
    fn new(events: Arc<tokio::sync::Mutex<VecDeque<ExpectedEvent>>>) -> Self {
        Self { events }
    }

    async fn record_event(&self, event: ExpectedEvent) {
        let mut events = self.events.lock().await;
        events.push_back(event);
    }
}

#[cfg_attr(feature = "async-trait", async_trait::async_trait)]
impl ClientHandler for TestClientHandler {
    type Error = TestError;

    async fn check_server_key(
        &mut self,
        _server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        self.record_event(ExpectedEvent::ClientCheckServerKey).await;
        Ok(true)
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut ClientSession,
    ) -> Result<(), Self::Error> {
        self.record_event(ExpectedEvent::ClientData {
            channel,
            data: data.to_vec(),
        })
        .await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut ClientSession,
    ) -> Result<(), Self::Error> {
        self.record_event(ExpectedEvent::ClientChannelClose { channel })
            .await;
        Ok(())
    }
}

/// Test context that holds the client and server handles along with channels
pub struct TestContext {
    pub client: ClientHandle<TestClientHandler>,
    pub server_events: Arc<tokio::sync::Mutex<VecDeque<ExpectedEvent>>>,
    pub client_events: Arc<tokio::sync::Mutex<VecDeque<ExpectedEvent>>>,
    pub server_channels: Arc<tokio::sync::Mutex<HashMap<ChannelId, Channel<ServerMsg>>>>,
    pub server_command_tx: mpsc::UnboundedSender<ServerCommand>,
    pub client_channels: Vec<Channel<crate::client::Msg>>,
}

impl TestContext {
    /// Get a client channel by index
    pub fn get_client_channel(
        &self,
        index: usize,
    ) -> Result<&Channel<crate::client::Msg>, TestError> {
        self.client_channels
            .get(index)
            .ok_or_else(|| TestError::ChannelNotFound(ChannelId(index as u32)))
    }

    /// Get a server channel by index
    pub async fn get_server_channel(&self, index: usize) -> Result<bool, TestError> {
        let channels = self.server_channels.lock().await;
        Ok(channels.len() > index)
    }
}

/// Simple test framework for russh
pub struct TestFramework;

impl TestFramework {
    /// Set up a connected client and server pair using a pipe
    pub async fn setup() -> Result<TestContext, TestError> {
        Self::setup_with_configs(None, None).await
    }

    /// Set up a connected client and server pair with custom configurations
    pub async fn setup_with_configs(
        custom_server_config: Option<server::Config>,
        custom_client_config: Option<client::Config>,
    ) -> Result<TestContext, TestError> {
        // Create a bidirectional pipe
        let (client_stream, server_stream) = tokio::io::duplex(65536);

        // Create shared event storage
        let server_events = Arc::new(tokio::sync::Mutex::new(VecDeque::new()));
        let client_events = Arc::new(tokio::sync::Mutex::new(VecDeque::new()));

        // Create command channel for server
        let (server_command_tx, server_command_rx) = mpsc::unbounded_channel();

        // Create handlers
        let server_handler = TestServerHandler::new(server_events.clone(), server_command_rx);
        let server_channels = server_handler.channels.clone();
        let client_handler = TestClientHandler::new(client_events.clone());

        // Set up server config
        let server_config = if let Some(config) = custom_server_config {
            Arc::new(config)
        } else {
            let server_key =
                ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519)
                    .map_err(|e| {
                        TestError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
                    })?;

            Arc::new(server::Config {
                inactivity_timeout: Some(std::time::Duration::from_secs(10)),
                auth_rejection_time: std::time::Duration::from_secs(1),
                auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
                keys: vec![server_key],
                ..Default::default()
            })
        };

        // Set up client config
        let client_config = if let Some(config) = custom_client_config {
            Arc::new(config)
        } else {
            Arc::new(client::Config::default())
        };

        // Start server in background
        let _server_task = tokio::spawn(async move {
            if let Err(e) = server::run_stream(server_config, server_stream, server_handler).await {
                eprintln!("Server error: {:?}", e);
            }
        });

        // Connect client
        let client = client::connect_stream(client_config, client_stream, client_handler)
            .await
            .map_err(|e| TestError::Client(format!("{:?}", e)))?;

        Ok(TestContext {
            client,
            server_events,
            client_events,
            server_channels,
            server_command_tx,
            client_channels: Vec::new(),
        })
    }

    /// Execute a sequence of actions and verify the expected events occur
    pub async fn run_test(
        mut context: TestContext,
        actions: Vec<Action>,
        expected_events: Vec<ExpectedEvent>,
    ) -> Result<(), TestError> {
        // Execute actions
        for action in actions {
            Self::execute_action(&mut context, action).await?;
        }

        // Allow some time for events to propagate
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify events
        Self::verify_events(&context, expected_events).await
    }

    /// Execute a sequence of actions using the framework
    pub async fn execute_actions(
        context: &mut TestContext,
        actions: Vec<Action>,
    ) -> Result<(), TestError> {
        for action in actions {
            Self::execute_action(context, action).await?;
        }
        Ok(())
    }

    /// Execute actions and verify that expected events occurred (order-independent)
    pub async fn run_test_flexible(
        mut context: TestContext,
        actions: Vec<Action>,
        expected_events: Vec<ExpectedEvent>,
    ) -> Result<(), TestError> {
        // Execute actions
        Self::execute_actions(&mut context, actions).await?;

        // Allow some time for events to propagate
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Verify events occurred (order-independent)
        Self::verify_events_flexible(&context, expected_events).await
    }

    async fn execute_action(context: &mut TestContext, action: Action) -> Result<(), TestError> {
        match action {
            Action::ClientAuthenticate { user } => {
                // Generate a key for authentication
                let key = ssh_key::PrivateKey::random(
                    &mut rand::rngs::OsRng,
                    ssh_key::Algorithm::Ed25519,
                )
                .map_err(|e| TestError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

                let key_with_hash = crate::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);

                context
                    .client
                    .authenticate_publickey(user, key_with_hash)
                    .await
                    .map_err(|e| TestError::Client(format!("{:?}", e)))?;
            }
            Action::ClientOpenSession => {
                let channel = context
                    .client
                    .channel_open_session()
                    .await
                    .map_err(|e| TestError::Client(format!("{:?}", e)))?;
                context.client_channels.push(channel);
            }
            Action::ClientSendData { channel, data } => {
                let ch = context.get_client_channel(channel.0 as usize)?;
                ch.data(&data[..]).await.map_err(|e| {
                    TestError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
                })?;
            }
            Action::ClientCloseChannel { channel } => {
                let ch = context.get_client_channel(channel.0 as usize)?;
                ch.close().await.map_err(|e| {
                    TestError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
                })?;
            }
            Action::ServerSendData { channel, data } => {
                context
                    .server_command_tx
                    .send(ServerCommand::SendData {
                        channel_id: channel,
                        data,
                    })
                    .map_err(|_| {
                        TestError::Server("Failed to send command to server".to_string())
                    })?;

                // Give some time for the command to be processed
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Action::ServerCloseChannel { channel } => {
                context
                    .server_command_tx
                    .send(ServerCommand::CloseChannel {
                        channel_id: channel,
                    })
                    .map_err(|_| {
                        TestError::Server("Failed to send command to server".to_string())
                    })?;

                // Give some time for the command to be processed
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
        Ok(())
    }

    async fn verify_events(
        context: &TestContext,
        expected_events: Vec<ExpectedEvent>,
    ) -> Result<(), TestError> {
        // Collect all events from both client and server
        let server_events = context.server_events.lock().await;
        let client_events = context.client_events.lock().await;

        let mut all_events = Vec::new();
        all_events.extend(server_events.iter().cloned());
        all_events.extend(client_events.iter().cloned());

        // Check exact length match
        if all_events.len() != expected_events.len() {
            eprintln!(
                "Expected {} events, got {}",
                expected_events.len(),
                all_events.len()
            );
            eprintln!("Expected: {:?}", expected_events);
            eprintln!("Actual: {:?}", all_events);
            return Err(TestError::EventCountMismatch {
                expected: expected_events.len(),
                actual: all_events.len(),
            });
        }

        // Check exact order and content match
        for (i, (expected, actual)) in expected_events.iter().zip(all_events.iter()).enumerate() {
            if expected != actual {
                eprintln!("Event mismatch at position {}", i);
                eprintln!("Expected: {:?}", expected);
                eprintln!("Actual: {:?}", actual);
                eprintln!("Full expected sequence: {:?}", expected_events);
                eprintln!("Full actual sequence: {:?}", all_events);
                return Err(TestError::EventMismatch {
                    expected: expected.clone(),
                    actual: actual.clone(),
                });
            }
        }

        Ok(())
    }

    async fn verify_events_flexible(
        context: &TestContext,
        expected_events: Vec<ExpectedEvent>,
    ) -> Result<(), TestError> {
        let server_events = context.server_events.lock().await;
        let client_events = context.client_events.lock().await;

        let mut all_events = Vec::new();
        all_events.extend(server_events.iter().cloned());
        all_events.extend(client_events.iter().cloned());

        drop(server_events);
        drop(client_events);

        // Check that all expected events occurred (order-independent)
        for expected in &expected_events {
            if !all_events.contains(expected) {
                return Err(TestError::EventMismatch {
                    expected: expected.clone(),
                    actual: all_events
                        .first()
                        .cloned()
                        .unwrap_or(ExpectedEvent::ClientCheckServerKey),
                });
            }
        }

        Ok(())
    }
}
