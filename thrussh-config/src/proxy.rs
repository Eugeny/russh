use futures::ready;
use futures::task::*;
use std;
use std::net::SocketAddr;
use std::pin::Pin;
use std::process::Stdio;
use tokio;
use tokio::io::ReadBuf;
use tokio::net::TcpStream;
use tokio::process::Command;

/// A type to implement either a TCP socket, or proxying through an external command.
pub enum Stream {
    #[allow(missing_docs)]
    Child(tokio::process::Child),
    #[allow(missing_docs)]
    Tcp(TcpStream),
}

impl Stream {
    /// Connect a direct TCP stream (as opposed to a proxied one).
    pub async fn tcp_connect(addr: &SocketAddr) -> Result<Stream, std::io::Error> {
        Ok(Stream::Tcp(tokio::net::TcpStream::connect(addr).await?))
    }
    /// Connect through a proxy command.
    pub async fn proxy_command(cmd: &str, args: &[&str]) -> Result<Stream, std::io::Error> {
        Ok(Stream::Child(
            Command::new(cmd)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .args(args)
                .spawn()
                .unwrap(),
        ))
    }
}

impl tokio::io::AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), std::io::Error>> {
        match *self {
            Stream::Child(ref mut c) => Pin::new(c.stdout.as_mut().unwrap()).poll_read(cx, buf),
            Stream::Tcp(ref mut t) => Pin::new(t).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match *self {
            Stream::Child(ref mut c) => Pin::new(c.stdin.as_mut().unwrap()).poll_write(cx, buf),
            Stream::Tcp(ref mut t) => Pin::new(t).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), std::io::Error>> {
        match *self {
            Stream::Child(ref mut c) => Pin::new(c.stdin.as_mut().unwrap()).poll_flush(cx),
            Stream::Tcp(ref mut t) => Pin::new(t).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<(), std::io::Error>> {
        match *self {
            Stream::Child(ref mut c) => {
                ready!(Pin::new(c.stdin.as_mut().unwrap()).poll_shutdown(cx))?;
                drop(c.stdin.take());
                Poll::Ready(Ok(()))
            }
            Stream::Tcp(ref mut t) => Pin::new(t).poll_shutdown(cx),
        }
    }
}
