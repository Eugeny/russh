use std::pin::Pin;

use futures::task::*;
use log::trace;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::Error;

const SSH_ID_BUF_SIZE: usize = 256;

/// The buffer to read the identification string (first line in the
/// protocol).  Not sensitive data — just protocol version exchange.
struct ReadSshIdBuffer {
    pub buf: Box<[u8; SSH_ID_BUF_SIZE]>,
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
        ReadSshIdBuffer {
            buf: Box::new([0; SSH_ID_BUF_SIZE]),
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
            trace!("read {n:?}");

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

            if ssh_id.bytes_read > 0 {
                // If we have a full line, handle it.
                if i >= 8 {
                    // Check if we have a valid SSH protocol identifier
                    #[allow(clippy::indexing_slicing)]
                    if let Ok(s) = std::str::from_utf8(&ssh_id.buf[..i]) {
                        if s.starts_with("SSH-1.99-") || s.starts_with("SSH-2.0-") {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter;

    #[tokio::test]
    async fn test_ssh_id_openssh() {
        let data = "SSH-2.0-OpenSSH_10.2\r\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received, b"SSH-2.0-OpenSSH_10.2");
    }

    #[tokio::test]
    async fn test_ssh_id_openssh_7_4() {
        let data = "SSH-2.0-OpenSSH_7.4\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received, b"SSH-2.0-OpenSSH_7.4");
    }

    #[tokio::test]
    async fn test_ssh_id_too_long() {
        let data = String::from_iter(iter::once("SSH-2.0-").chain(
            iter::repeat("A").take(500)));
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await;
        assert!(matches!(received.err(), Some(Error::Disconnect)));
    }

    #[tokio::test]
    async fn test_ssh_id_empty() {
        let data = "";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await;
        assert!(matches!(received.err(), Some(Error::Disconnect)));
    }

    #[tokio::test]
    async fn test_ssh_id_almost_empty_cr_nl() {
        let data = "SSH-2.0-\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received, b"SSH-2.0-");
    }

    #[tokio::test]
    async fn test_ssh_id_almost_empty_nl() {
        let data = "SSH-2.0-\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received, b"SSH-2.0-");
    }

    #[tokio::test]
    async fn test_ssh_id_newline() {
        let data = "\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await;
        assert!(matches!(received.err(), Some(Error::Disconnect)));
    }

    #[tokio::test]
    async fn test_ssh_id_contains_cr() {
        // A \r that isn't followed by \n has no special meaning
        let data = "SSH-2.0-OpenSSH\r10.2\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received, b"SSH-2.0-OpenSSH\r10.2");
    }

    #[tokio::test]
    async fn test_ssh_id_trailing_cr() {
        // Verify this doesn't cause an out-of-bounds access when testing for \r\n
        let data = "SSH-2.0-OpenSSH_10.2\r";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await;
        assert!(matches!(received.err(), Some(Error::Disconnect)));
    }

    #[tokio::test]
    async fn test_ssh_id_nl_cr() {
        // Like \r\n but backwards
        let data = "SSH-2.0-OpenSSH_10.2\n\r";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received, b"SSH-2.0-OpenSSH_10.2");
    }

    #[tokio::test]
    async fn test_ssh_id_nl_cr_nl() {
        // Like \r\n but backwards, but also part of \r\n
        let data = "SSH-2.0-OpenSSH_10.2\n\r\n";
        let mut read = SshRead::new(data.as_bytes());

        let received = read.read_ssh_id().await.unwrap();
        assert_eq!(received, b"SSH-2.0-OpenSSH_10.2");
    }
}
