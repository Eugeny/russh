mod rx;
use std::borrow::{Borrow, BorrowMut};

pub use rx::ChannelRx;

mod tx;
pub use tx::ChannelTx;

use crate::{Channel, ChannelId, ChannelMsg, ChannelReadHalf};

#[derive(Debug)]
pub struct ChannelCloseOnDrop<S: From<(ChannelId, ChannelMsg)> + Send + 'static>(pub Channel<S>);

impl<S: From<(ChannelId, ChannelMsg)> + Send + 'static> Borrow<ChannelReadHalf>
    for ChannelCloseOnDrop<S>
{
    fn borrow(&self) -> &ChannelReadHalf {
        &self.0.read_half
    }
}

impl<S: From<(ChannelId, ChannelMsg)> + Send + 'static> BorrowMut<ChannelReadHalf>
    for ChannelCloseOnDrop<S>
{
    fn borrow_mut(&mut self) -> &mut ChannelReadHalf {
        &mut self.0.read_half
    }
}

impl<S: From<(ChannelId, ChannelMsg)> + Send + 'static> Drop for ChannelCloseOnDrop<S> {
    fn drop(&mut self) {
        let id = self.0.write_half.id;
        let sender = self.0.write_half.sender.clone();
        tokio::spawn(async move {
            let _ = sender.send((id, ChannelMsg::Close).into()).await;
        });
    }
}
