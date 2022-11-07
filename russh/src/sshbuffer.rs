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

use std::num::Wrapping;

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
            Self::Raw(s) => s.trim_end_matches(|c| c == '\n' || c == '\r').as_bytes(),
        }
    }

    pub(crate) fn write(&self, buffer: &mut CryptoVec) {
        match self {
            Self::Standard(s) => buffer.extend(format!("{}\r\n", s).as_bytes()),
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
    pub len: usize, // next packet length.
    pub bytes: usize,
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
