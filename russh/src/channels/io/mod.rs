use super::{Channel, ChannelId, ChannelMsg, ChannelReadHalf};

mod rx;
pub use rx::ChannelRx;

mod tx;
pub use tx::ChannelTx;

/// An enum with the ability to hold either an owned [`Channel`]
/// or a `&mut` ref to it.
#[derive(Debug)]
pub enum ChannelRxAsMut<'i, S>
where
    S: From<(ChannelId, ChannelMsg)>,
{
    Owned(Channel<S>),
    RefMut(&'i mut ChannelReadHalf),
}

impl<'i, S> AsMut<ChannelReadHalf> for ChannelRxAsMut<'i, S>
where
    S: From<(ChannelId, ChannelMsg)>,
{
    fn as_mut(&mut self) -> &mut ChannelReadHalf {
        match self {
            Self::Owned(channel) => &mut channel.read_half,
            Self::RefMut(ref_mut) => ref_mut,
        }
    }
}

impl<S> From<Channel<S>> for ChannelRxAsMut<'static, S>
where
    S: From<(ChannelId, ChannelMsg)>,
{
    fn from(value: Channel<S>) -> Self {
        Self::Owned(value)
    }
}

impl<'i, S> From<&'i mut ChannelReadHalf> for ChannelRxAsMut<'i, S>
where
    S: From<(ChannelId, ChannelMsg)>,
{
    fn from(value: &'i mut ChannelReadHalf) -> Self {
        Self::RefMut(value)
    }
}
