use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::AsyncRead;
use tokio::sync::mpsc::error::TryRecvError;

use super::{ChannelAsMut, ChannelMsg};
use crate::ChannelId;

#[derive(Debug)]
pub struct ChannelRx<'i, S>
where
    S: From<(ChannelId, ChannelMsg)>,
{
    channel: ChannelAsMut<'i, S>,
    buffer: Option<ChannelMsg>,

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
        let msg = match self.buffer.take() {
            Some(msg) => msg,
            None => match self.channel.as_mut().receiver.try_recv() {
                Ok(msg) => msg,
                Err(TryRecvError::Empty) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(TryRecvError::Disconnected) => {
                    return Poll::Ready(Ok(()));
                }
            },
        };

        match (&msg, self.ext) {
            (ChannelMsg::Data { data }, None) => {
                if buf.remaining() >= data.len() {
                    buf.put_slice(data);

                    Poll::Ready(Ok(()))
                } else {
                    self.buffer = Some(msg);

                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            (ChannelMsg::ExtendedData { data, ext }, Some(target)) if *ext == target => {
                if buf.remaining() >= data.len() {
                    buf.put_slice(data);

                    Poll::Ready(Ok(()))
                } else {
                    self.buffer = Some(msg);

                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
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
