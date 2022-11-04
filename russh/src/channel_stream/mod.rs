// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
// Originally from microsoft/dev-tunnels

mod read_buffer;

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use russh_cryptovec::CryptoVec;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use self::read_buffer::ReadBuffer;

/// AsyncRead/AsyncWrite wrapper for SSH Channels
pub struct ChannelStream<H: crate::client::Handler> {
    id: crate::ChannelId,
    session: Arc<crate::client::Handle<H>>,
    incoming: mpsc::UnboundedReceiver<Vec<u8>>,

    readbuf: ReadBuffer,

    is_write_fut_valid: bool,
    write_fut: tokio_util::sync::ReusableBoxFuture<'static, Result<(), crate::CryptoVec>>,
}

impl<H: crate::client::Handler + 'static> ChannelStream<H> {
    pub fn new(
        id: crate::ChannelId,
        session: Arc<crate::client::Handle<H>>,
    ) -> (Self, mpsc::UnboundedSender<Vec<u8>>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            ChannelStream {
                id,
                session,
                incoming: rx,
                readbuf: ReadBuffer::default(),
                is_write_fut_valid: false,
                write_fut: tokio_util::sync::ReusableBoxFuture::new(make_client_write_fut::<H>(
                    None,
                )),
            },
            tx,
        )
    }
}

/// Makes a future that writes to the russh handle. This general approach was
/// taken from https://docs.rs/tokio-util/0.7.3/tokio_util/sync/struct.PollSender.html
/// This is just like make_server_write_fut, but for clients (they don't share a trait...)
async fn make_client_write_fut<H: crate::client::Handler>(
    data: Option<(Arc<crate::client::Handle<H>>, crate::ChannelId, Vec<u8>)>,
) -> Result<(), crate::CryptoVec> {
    match data {
        Some((client, id, data)) => client.data(id, CryptoVec::from(data)).await,
        None => unreachable!("this future should not be pollable in this state"),
    }
}

impl<H: crate::client::Handler + 'static> AsyncWrite for ChannelStream<H> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if !self.is_write_fut_valid {
            let session = self.session.clone();
            let id = self.id;
            self.write_fut
                .set(make_client_write_fut(Some((session, id, buf.to_vec()))));
            self.is_write_fut_valid = true;
        }

        self.poll_flush(cx).map(|r| r.map(|_| buf.len()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        if !self.is_write_fut_valid {
            return Poll::Ready(Ok(()));
        }

        match self.write_fut.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(_)) => {
                self.is_write_fut_valid = false;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(_)) => {
                self.is_write_fut_valid = false;
                Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "EOF")))
            }
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl<H: crate::client::Handler> AsyncRead for ChannelStream<H> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some((v, s)) = self.readbuf.take_data() {
            return self.readbuf.put_data(buf, v, s);
        }

        match self.incoming.poll_recv(cx) {
            Poll::Ready(Some(msg)) => self.readbuf.put_data(buf, msg, 0),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, "EOF"))),
            Poll::Pending => Poll::Pending,
        }
    }
}
