use std::sync::Arc;

use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::Mutex;

use crate::{channels::WindowSize, ChannelMsg};

/// A handle to the [`super::Channel`]'s to be able to transmit messages
/// to it and update it's `window_size`.
#[derive(Debug)]
pub struct ChannelRef {
    pub(super) sender: UnboundedSender<ChannelMsg>,
    pub(super) window_size: Arc<Mutex<WindowSize>>,
}

impl ChannelRef {
    pub fn new(sender: UnboundedSender<ChannelMsg>) -> Self {
        Self {
            sender,
            window_size: Default::default(),
        }
    }

    pub(crate) fn window_size(&self) -> &Arc<Mutex<WindowSize>> {
        &self.window_size
    }
}

impl std::ops::Deref for ChannelRef {
    type Target = UnboundedSender<ChannelMsg>;

    fn deref(&self) -> &Self::Target {
        &self.sender
    }
}
