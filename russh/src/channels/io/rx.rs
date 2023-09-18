use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex, TryLockError},
    task::{Context, Poll},
};

use tokio::{
    io::AsyncRead,
    sync::mpsc::{self, error::TryRecvError},
};

use super::ChannelMsg;

pub struct ChannelRx {
    receiver: mpsc::UnboundedReceiver<ChannelMsg>,
    buffer: Option<ChannelMsg>,

    window_size: Arc<Mutex<u32>>,
}

impl ChannelRx {
    pub fn new(
        receiver: mpsc::UnboundedReceiver<ChannelMsg>,
        window_size: Arc<Mutex<u32>>,
    ) -> Self {
        Self {
            receiver,
            buffer: None,
            window_size,
        }
    }
}

impl AsyncRead for ChannelRx {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let msg = match self.buffer.take() {
            Some(msg) => msg,
            None => match self.receiver.try_recv() {
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
                self.receiver.close();

                Poll::Ready(Ok(()))
            }
            _ => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
