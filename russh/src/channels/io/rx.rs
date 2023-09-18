use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex, TryLockError},
    task::{Context, Poll},
};

use tokio::{io::AsyncRead, sync::mpsc::error::TryRecvError};

use super::ChannelMsg;
use crate::{Channel, ChannelId};

#[derive(Debug)]
pub struct ChannelRx<'i, S>
where
    S: From<(ChannelId, ChannelMsg)>,
{
    channel: &'i mut Channel<S>,
    buffer: Option<ChannelMsg>,

    window_size: Arc<Mutex<u32>>,
}

impl<'i, S> ChannelRx<'i, S>
where
    S: From<(ChannelId, ChannelMsg)>,
{
    pub fn new(channel: &'i mut Channel<S>, window_size: Arc<Mutex<u32>>) -> Self {
        Self {
            channel,
            buffer: None,
            window_size,
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
            None => match self.channel.receiver.try_recv() {
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

        match &msg {
            ChannelMsg::Data { data } => {
                if buf.remaining() >= data.len() {
                    buf.put_slice(data);

                    Poll::Ready(Ok(()))
                } else {
                    self.buffer = Some(msg);

                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            ChannelMsg::WindowAdjusted { new_size } => {
                let buffer = match self.window_size.try_lock() {
                    Ok(mut window_size) => {
                        *window_size = *new_size;

                        None
                    }
                    Err(TryLockError::WouldBlock) => Some(msg),
                    Err(TryLockError::Poisoned(err)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            err.to_string(),
                        )))
                    }
                };

                self.buffer = buffer;

                cx.waker().wake_by_ref();
                Poll::Pending
            }
            ChannelMsg::Eof => {
                self.channel.receiver.close();

                Poll::Ready(Ok(()))
            }
            _ => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
