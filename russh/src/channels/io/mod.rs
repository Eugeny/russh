use super::{Channel, ChannelId, ChannelMsg};

mod rx;
pub use rx::ChannelRx;

mod tx;
pub use tx::ChannelTx;

/// An enum with the ability to hold either an owned [`Channel`]
/// or a `&mut` ref to it.
#[derive(Debug)]
pub enum ChannelAsMut<'i, S>
where
    S: From<(ChannelId, ChannelMsg)>,
{
    Owned(Channel<S>),
    RefMut(&'i mut Channel<S>),
}

impl<'i, S> AsMut<Channel<S>> for ChannelAsMut<'i, S>
where
    S: From<(ChannelId, ChannelMsg)>,
{
    fn as_mut(&mut self) -> &mut Channel<S> {
        match self {
            Self::Owned(channel) => channel,
            Self::RefMut(ref_mut) => ref_mut,
        }
    }
}

impl<S> From<Channel<S>> for ChannelAsMut<'static, S>
where
    S: From<(ChannelId, ChannelMsg)>,
{
    fn from(value: Channel<S>) -> Self {
        Self::Owned(value)
    }
}

impl<'i, S> From<&'i mut Channel<S>> for ChannelAsMut<'i, S>
where
    S: From<(ChannelId, ChannelMsg)>,
{
    fn from(value: &'i mut Channel<S>) -> Self {
        Self::RefMut(value)
    }
}
