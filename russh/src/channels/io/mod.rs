mod rx;
use std::borrow::{Borrow, BorrowMut};

pub use rx::ChannelRx;

mod tx;
pub use tx::ChannelTx;

use crate::{Channel, ChannelId, ChannelMsg, ChannelReadHalf};

pub struct ChannelCloseOnDrop<S: From<(ChannelId, ChannelMsg)>>(pub Channel<S>);
impl<S: From<(ChannelId, ChannelMsg)>> Borrow<ChannelReadHalf> for ChannelCloseOnDrop<S> {
    fn borrow(&self) -> &ChannelReadHalf {
        &self.0.read_half
    }
}
impl<S: From<(ChannelId, ChannelMsg)>> BorrowMut<ChannelReadHalf> for ChannelCloseOnDrop<S> {
    fn borrow_mut(&mut self) -> &mut ChannelReadHalf {
        &mut self.0.read_half
    }
}
impl<S: From<(ChannelId, ChannelMsg)>> Drop for ChannelCloseOnDrop<S> {
    fn drop(&mut self) {
        let Self(channel) = self;
        let _ = channel
            .write_half
            .sender
            .try_send((channel.write_half.id, ChannelMsg::Close).into());
    }
}
