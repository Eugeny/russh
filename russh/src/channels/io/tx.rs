use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::{
    io::AsyncWrite,
    sync::{
        mpsc::{self, error::TrySendError},
        Mutex,
    },
};

use russh_cryptovec::CryptoVec;

use super::ChannelMsg;
use crate::ChannelId;

pub struct ChannelTx<S> {
    sender: mpsc::Sender<S>,
    id: ChannelId,

    window_size: Arc<Mutex<u32>>,
    max_packet_size: u32,
    ext: Option<u32>,
}

impl<S> ChannelTx<S> {
    pub fn new(
        sender: mpsc::Sender<S>,
        id: ChannelId,
        window_size: Arc<Mutex<u32>>,
        max_packet_size: u32,
        ext: Option<u32>,
    ) -> Self {
        Self {
            sender,
            id,
            window_size,
            max_packet_size,
            ext,
        }
    }
}

impl<S> AsyncWrite for ChannelTx<S>
where
    S: From<(ChannelId, ChannelMsg)> + 'static,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut window_size = match self.window_size.try_lock() {
            Ok(window_size) => window_size,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        let writable = self.max_packet_size.min(*window_size).min(buf.len() as u32) as usize;
        if writable == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        let mut data = CryptoVec::new_zeroed(writable);
        #[allow(clippy::indexing_slicing)] // Clamped to maximum `buf.len()` with `.min`
        data.copy_from_slice(&buf[..writable]);
        data.resize(writable);

        *window_size -= writable as u32;
        drop(window_size);

        let msg = match self.ext {
            None => ChannelMsg::Data { data },
            Some(ext) => ChannelMsg::ExtendedData { data, ext },
        };

        match self.sender.try_send((self.id, msg).into()) {
            Ok(_) => Poll::Ready(Ok(writable)),
            Err(TrySendError::Closed(_)) => Poll::Ready(Ok(0)),
            Err(TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.poll_flush(cx)
    }
}
