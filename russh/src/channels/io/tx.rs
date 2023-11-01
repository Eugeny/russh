use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use futures::FutureExt;
use russh_cryptovec::CryptoVec;
use tokio::io::AsyncWrite;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::mpsc::{self, OwnedPermit};
use tokio::sync::{Mutex, OwnedMutexGuard};

use super::ChannelMsg;
use crate::ChannelId;

type BoxedThreadsafeFuture<T> = Pin<Box<dyn Sync + Send + std::future::Future<Output = T>>>;
type OwnedPermitFuture<S> =
    BoxedThreadsafeFuture<Result<(OwnedPermit<S>, ChannelMsg, usize), SendError<()>>>;

pub struct ChannelTx<S> {
    sender: mpsc::Sender<S>,
    send_fut: Option<OwnedPermitFuture<S>>,
    id: ChannelId,

    window_size_fut: Option<BoxedThreadsafeFuture<OwnedMutexGuard<u32>>>,
    window_size: Arc<Mutex<u32>>,
    max_packet_size: u32,
    ext: Option<u32>,
}

impl<S> ChannelTx<S>
where
    S: From<(ChannelId, ChannelMsg)> + 'static + Send,
{
    pub fn new(
        sender: mpsc::Sender<S>,
        id: ChannelId,
        window_size: Arc<Mutex<u32>>,
        max_packet_size: u32,
        ext: Option<u32>,
    ) -> Self {
        Self {
            sender,
            send_fut: None,
            id,
            window_size,
            window_size_fut: None,
            max_packet_size,
            ext,
        }
    }

    fn poll_mk_msg(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<(ChannelMsg, usize)> {
        let window_size = self.window_size.clone();
        let window_size_fut = self
            .window_size_fut
            .get_or_insert_with(|| Box::pin(window_size.lock_owned()));
        let mut window_size = ready!(window_size_fut.poll_unpin(cx));
        self.window_size_fut.take();

        let writable = (self.max_packet_size)
            .min(*window_size)
            .min(buf.len() as u32) as usize;
        if writable == 0 {
            // TODO fix this busywait
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

        Poll::Ready((msg, writable))
    }

    fn activate(&mut self, msg: ChannelMsg, writable: usize) -> &mut OwnedPermitFuture<S> {
        use futures::TryFutureExt;
        self.send_fut.insert(Box::pin(
            self.sender
                .clone()
                .reserve_owned()
                .map_ok(move |p| (p, msg, writable)),
        ))
    }

    fn handle_write_result(
        &mut self,
        r: Result<(OwnedPermit<S>, ChannelMsg, usize), SendError<()>>,
    ) -> Result<usize, io::Error> {
        self.send_fut = None;
        match r {
            Ok((permit, msg, writable)) => {
                permit.send((self.id, msg).into());
                Ok(writable)
            }
            Err(SendError(())) => Err(io::Error::new(io::ErrorKind::BrokenPipe, "channel closed")),
        }
    }
}

impl<S> AsyncWrite for ChannelTx<S>
where
    S: From<(ChannelId, ChannelMsg)> + 'static + Send,
{
    #[allow(clippy::too_many_lines)]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let send_fut = if let Some(x) = self.send_fut.as_mut() {
            x
        } else {
            let (msg, writable) = ready!(self.poll_mk_msg(cx, buf));
            self.activate(msg, writable)
        };
        let r = ready!(send_fut.as_mut().poll_unpin(cx));
        Poll::Ready(self.handle_write_result(r))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let send_fut = if let Some(x) = self.send_fut.as_mut() {
            x
        } else {
            self.activate(ChannelMsg::Eof, 0)
        };
        let r = ready!(send_fut.as_mut().poll_unpin(cx)).map(|(p, _, _)| (p, ChannelMsg::Eof, 0));
        Poll::Ready(self.handle_write_result(r).map(drop))
    }
}
