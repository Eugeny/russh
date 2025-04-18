use std::pin::Pin;

use futures::task::*;
use log::trace;
use regex::Regex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::{CryptoVec, Error};

/// The buffer to read the identification string (first line in the
/// protocol).
struct ReadSshIdBuffer {
    pub buf: CryptoVec,
    pub total: usize,
    pub bytes_read: usize,
    pub sshid_len: usize,
}

impl ReadSshIdBuffer {
    pub fn id(&self) -> &[u8] {
        #[allow(clippy::indexing_slicing)] // length checked
        &self.buf[..self.sshid_len]
    }

    pub fn new() -> ReadSshIdBuffer {
        let mut buf = CryptoVec::new();
        buf.resize(256);
        ReadSshIdBuffer {
            buf,
            sshid_len: 0,
            bytes_read: 0,
            total: 0,
        }
    }
}

impl std::fmt::Debug for ReadSshIdBuffer {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(fmt, "ReadSshId {:?}", self.id())
    }
}

/// SshRead<R> is the same as R, plus a small buffer in the beginning to
/// read the identification string. After the first line in the
/// connection, the `id` parameter is never used again.
pub struct SshRead<R> {
    id: Option<ReadSshIdBuffer>,
    pub r: R,
}

impl<R: AsyncRead + AsyncWrite> SshRead<R> {
    pub fn split(self) -> (SshRead<tokio::io::ReadHalf<R>>, tokio::io::WriteHalf<R>) {
        let (r, w) = tokio::io::split(self.r);
        (SshRead { id: self.id, r }, w)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for SshRead<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), std::io::Error>> {
        if let Some(mut id) = self.id.take() {
            trace!("id {:?} {:?}", id.total, id.bytes_read);
            if id.total > id.bytes_read {
                let total = id.total.min(id.bytes_read + buf.remaining());
                #[allow(clippy::indexing_slicing)] // length checked
                buf.put_slice(&id.buf[id.bytes_read..total]);
                id.bytes_read += total - id.bytes_read;
                self.id = Some(id);
                return Poll::Ready(Ok(()));
            }
        }
        AsyncRead::poll_read(Pin::new(&mut self.get_mut().r), cx, buf)
    }
}

impl<R: std::io::Write> std::io::Write for SshRead<R> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.r.write(buf)
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.r.flush()
    }
}

impl<R: AsyncWrite + Unpin> AsyncWrite for SshRead<R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.r), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.r), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.r), cx)
    }
}

impl<R: AsyncRead + Unpin> SshRead<R> {
    pub fn new(r: R) -> Self {
        SshRead {
            id: Some(ReadSshIdBuffer::new()),
            r,
        }
    }

    #[allow(clippy::unwrap_used)]
    pub async fn read_ssh_id(&mut self) -> Result<&[u8], Error> {
        let ssh_id = self.id.as_mut().unwrap();
        loop {
            let mut i = 0;
            trace!("read_ssh_id: reading");

            #[allow(clippy::indexing_slicing)] // length checked
            let n = AsyncReadExt::read(&mut self.r, &mut ssh_id.buf[ssh_id.total..]).await?;
            trace!("read {:?}", n);

            ssh_id.total += n;
            #[allow(clippy::indexing_slicing)] // length checked
            {
                trace!("{:?}", std::str::from_utf8(&ssh_id.buf[..ssh_id.total]));
            }
            if n == 0 {
                return Err(Error::Disconnect);
            }
            #[allow(clippy::indexing_slicing)] // length checked
            loop {
                if i >= ssh_id.total - 1 {
                    break;
                }
                if ssh_id.buf[i] == b'\r' && ssh_id.buf[i + 1] == b'\n' {
                    ssh_id.bytes_read = i + 2;
                    break;
                } else if ssh_id.buf[i + 1] == b'\n' {
                    // This is really wrong, but OpenSSH 7.4 uses
                    // it.
                    ssh_id.bytes_read = i + 2;
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }

            // We have a full line, check if it is a valid SSH protocol
            // identifier. The SSH protocol identifier is defined in
            // https://datatracker.ietf.org/doc/html/rfc4253#section-5.1
            let ssh_version_regex = match Regex::new(r"^SSH-(1\.99|2\.0)-.*") {
                Ok(regex) => regex,
                Err(e) => return Err(Error::from(e)),
            };

            if ssh_id.bytes_read > 0 {
                // If we have a full line, handle it.
                if i >= 8 {
                    // Check if we have a valid SSH protocol identifier
                    #[allow(clippy::indexing_slicing)]
                    if let Ok(s) = std::str::from_utf8(&ssh_id.buf[..i]) {
                        if ssh_version_regex.is_match(s) {
                            ssh_id.sshid_len = i;
                            return Ok(ssh_id.id());
                        }
                    }
                }
                // Else, it is a "preliminary" (see
                // https://tools.ietf.org/html/rfc4253#section-4.2),
                // and we can discard it and read the next one.
                ssh_id.total = 0;
                ssh_id.bytes_read = 0;
            }
            trace!("bytes_read: {:?}", ssh_id.bytes_read);
        }
    }
}
