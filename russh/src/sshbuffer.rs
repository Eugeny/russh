// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use core::fmt;
use std::num::Wrapping;

use cipher::SealingKey;
use compression::Compress;
use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::*;

/// The SSH client/server identification string.
#[derive(Debug)]
pub enum SshId {
    /// When sending the id, append RFC standard `\r\n`. Example: `SshId::Standard("SSH-2.0-acme")`
    Standard(String),
    /// When sending the id, use this buffer as it is and do not append additional line terminators.
    Raw(String),
}

impl SshId {
    pub(crate) fn as_kex_hash_bytes(&self) -> &[u8] {
        match self {
            Self::Standard(s) => s.as_bytes(),
            Self::Raw(s) => s.trim_end_matches(['\n', '\r']).as_bytes(),
        }
    }

    pub(crate) fn write(&self, buffer: &mut CryptoVec) {
        match self {
            Self::Standard(s) => buffer.extend(format!("{s}\r\n").as_bytes()),
            Self::Raw(s) => buffer.extend(s.as_bytes()),
        }
    }
}

#[test]
fn test_ssh_id() {
    let mut buffer = CryptoVec::new();
    SshId::Standard("SSH-2.0-acme".to_string()).write(&mut buffer);
    assert_eq!(&buffer[..], b"SSH-2.0-acme\r\n");

    let mut buffer = CryptoVec::new();
    SshId::Raw("SSH-2.0-raw\n".to_string()).write(&mut buffer);
    assert_eq!(&buffer[..], b"SSH-2.0-raw\n");

    assert_eq!(
        SshId::Standard("SSH-2.0-acme".to_string()).as_kex_hash_bytes(),
        b"SSH-2.0-acme"
    );
    assert_eq!(
        SshId::Raw("SSH-2.0-raw\n".to_string()).as_kex_hash_bytes(),
        b"SSH-2.0-raw"
    );
}

#[derive(Debug, Default)]
pub struct SSHBuffer {
    pub buffer: CryptoVec,
    pub len: usize,   // next packet length.
    pub bytes: usize, // total bytes written since the last rekey
    // Sequence numbers are on 32 bits and wrap.
    // https://tools.ietf.org/html/rfc4253#section-6.4
    pub seqn: Wrapping<u32>,
}

impl SSHBuffer {
    pub fn new() -> Self {
        SSHBuffer {
            buffer: CryptoVec::new(),
            len: 0,
            bytes: 0,
            seqn: Wrapping(0),
        }
    }

    pub fn send_ssh_id(&mut self, id: &SshId) {
        id.write(&mut self.buffer);
    }
}

#[derive(Debug)]
pub(crate) struct IncomingSshPacket {
    pub buffer: CryptoVec,
    pub seqn: Wrapping<u32>,
}

pub(crate) struct PacketWriter {
    cipher: Box<dyn SealingKey + Send>,
    compress: Compress,
    compress_buffer: CryptoVec,
    write_buffer: SSHBuffer,
}

impl Debug for PacketWriter {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketWriter").finish()
    }
}

impl PacketWriter {
    pub fn clear() -> Self {
        Self::new(Box::new(cipher::clear::Key {}), Compress::None)
    }

    pub fn new(cipher: Box<dyn SealingKey + Send>, compress: Compress) -> Self {
        Self {
            cipher,
            compress,
            compress_buffer: CryptoVec::new(),
            write_buffer: SSHBuffer::new(),
        }
    }

    pub fn packet_raw(&mut self, buf: &[u8]) -> Result<(), Error> {
        if let Some(message_type) = buf.first() {
            debug!("> msg type {message_type:?}, len {}", buf.len());
            let packet = self.compress.compress(buf, &mut self.compress_buffer)?;
            self.cipher.write(packet, &mut self.write_buffer);
        }
        Ok(())
    }

    /// Sends and returns the packet contents
    pub fn packet<F: FnOnce(&mut CryptoVec) -> Result<(), Error>>(
        &mut self,
        f: F,
    ) -> Result<CryptoVec, Error> {
        let mut buf = CryptoVec::new();
        f(&mut buf)?;
        self.packet_raw(&buf)?;
        Ok(buf)
    }

    pub fn buffer(&mut self) -> &mut SSHBuffer {
        &mut self.write_buffer
    }

    pub fn compress(&mut self) -> &mut Compress {
        &mut self.compress
    }

    pub fn set_cipher(&mut self, cipher: Box<dyn SealingKey + Send>) {
        self.cipher = cipher;
    }

    pub fn reset_seqn(&mut self) {
        self.write_buffer.seqn = Wrapping(0);
    }

    pub async fn flush_into<W: AsyncWrite + Unpin>(&mut self, w: &mut W) -> std::io::Result<()> {
        if !self.write_buffer.buffer.is_empty() {
            w.write_all(&self.write_buffer.buffer).await?;
            w.flush().await?;
            self.write_buffer.buffer.clear();
        }
        Ok(())
    }
}
