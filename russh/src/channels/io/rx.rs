use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::AsyncRead;

use super::{ChannelAsMut, ChannelMsg};
use crate::ChannelId;

#[derive(Debug)]
pub struct ChannelRx<'i, S>
where
    S: From<(ChannelId, ChannelMsg)>,
{
    channel: ChannelAsMut<'i, S>,
    buffer: Option<(ChannelMsg, usize)>,

    ext: Option<u32>,
}

impl<'i, S> ChannelRx<'i, S>
where
    S: From<(ChannelId, ChannelMsg)>,
{
    pub fn new(channel: impl Into<ChannelAsMut<'i, S>>, ext: Option<u32>) -> Self {
        Self {
            channel: channel.into(),
            buffer: None,
            ext,
        }
    }
}

impl<'i, S> AsyncRead for ChannelRx<'i, S>
where
    S: From<(ChannelId, ChannelMsg)>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let (msg, mut idx) = match self.buffer.take() {
            Some(msg) => msg,
            None => match ready!(self.channel.as_mut().receiver.poll_recv(cx)) {
                Some(msg) => (msg, 0),
                None => return Poll::Ready(Ok(())),
            },
        };

        match (&msg, self.ext) {
            (ChannelMsg::Data { data }, None) => {
                let readable = buf.remaining().min(data.len() - idx);

                // Clamped to maximum `buf.remaining()` and `data.len() - idx` with `.min`
                #[allow(clippy::indexing_slicing)]
                buf.put_slice(&data[idx..idx + readable]);
                idx += readable;

                if idx != data.len() {
                    self.buffer = Some((msg, idx));
                }

                Poll::Ready(Ok(()))
            }
            (ChannelMsg::ExtendedData { data, ext }, Some(target)) if *ext == target => {
                let readable = buf.remaining().min(data.len() - idx);

                // Clamped to maximum `buf.remaining()` and `data.len() - idx` with `.min`
                #[allow(clippy::indexing_slicing)]
                buf.put_slice(&data[idx..idx + readable]);
                idx += readable;

                if idx != data.len() {
                    self.buffer = Some((msg, idx));
                }

                Poll::Ready(Ok(()))
            }
            (ChannelMsg::Eof, _) => {
                self.channel.as_mut().receiver.close();

                Poll::Ready(Ok(()))
            }
            _ => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
