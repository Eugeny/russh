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

use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::num::Wrapping;

use byteorder::{BigEndian, ByteOrder};
use log::{debug, trace};
use tokio::sync::oneshot;

use crate::cipher::SealingKey;
use crate::kex::KexAlgorithm;
use crate::keys::encoding::Encoding;
use crate::sshbuffer::SSHBuffer;
use crate::{
    auth, cipher, mac, msg, negotiation, ChannelId, ChannelParams, CryptoVec, Disconnect, Limits,
};

#[derive(Debug)]
pub(crate) struct Encrypted {
    pub state: EncryptedState,

    // It's always Some, except when we std::mem::replace it temporarily.
    pub exchange: Option<Exchange>,
    pub kex: Box<dyn KexAlgorithm + Send>,
    pub key: usize,
    pub client_mac: mac::Name,
    pub server_mac: mac::Name,
    pub session_id: CryptoVec,
    pub rekey: Option<Kex>,
    pub channels: HashMap<ChannelId, ChannelParams>,
    pub last_channel_id: Wrapping<u32>,
    pub write: CryptoVec,
    pub write_cursor: usize,
    pub last_rekey: std::time::Instant,
    pub server_compression: crate::compression::Compression,
    pub client_compression: crate::compression::Compression,
    pub compress: crate::compression::Compress,
    pub decompress: crate::compression::Decompress,
    pub compress_buffer: CryptoVec,
}

pub(crate) struct CommonSession<Config> {
    pub auth_user: String,
    pub remote_sshid: Vec<u8>,
    pub config: Config,
    pub encrypted: Option<Encrypted>,
    pub auth_method: Option<auth::Method>,
    pub(crate) auth_attempts: usize,
    pub write_buffer: SSHBuffer,
    pub kex: Option<Kex>,
    pub cipher: cipher::CipherPair,
    pub wants_reply: bool,
    pub disconnected: bool,
    pub buffer: CryptoVec,
    pub strict_kex: bool,
    pub alive_timeouts: usize,
    pub received_data: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ChannelFlushResult {
    Incomplete {
        wrote: usize,
    },
    Complete {
        wrote: usize,
        pending_eof: bool,
        pending_close: bool,
    },
}
impl ChannelFlushResult {
    pub(crate) fn wrote(&self) -> usize {
        match self {
            ChannelFlushResult::Incomplete { wrote } => *wrote,
            ChannelFlushResult::Complete { wrote, .. } => *wrote,
        }
    }
    pub(crate) fn complete(wrote: usize, channel: &ChannelParams) -> Self {
        ChannelFlushResult::Complete {
            wrote,
            pending_eof: channel.pending_eof,
            pending_close: channel.pending_close,
        }
    }
}

impl<C> CommonSession<C> {
    pub fn newkeys(&mut self, newkeys: NewKeys) {
        if let Some(ref mut enc) = self.encrypted {
            enc.exchange = Some(newkeys.exchange);
            enc.kex = newkeys.kex;
            enc.key = newkeys.key;
            enc.client_mac = newkeys.names.client_mac;
            enc.server_mac = newkeys.names.server_mac;
            self.cipher = newkeys.cipher;
            self.strict_kex = self.strict_kex || newkeys.names.strict_kex;
        }
    }

    pub fn encrypted(&mut self, state: EncryptedState, newkeys: NewKeys) {
        self.encrypted = Some(Encrypted {
            exchange: Some(newkeys.exchange),
            kex: newkeys.kex,
            key: newkeys.key,
            client_mac: newkeys.names.client_mac,
            server_mac: newkeys.names.server_mac,
            session_id: newkeys.session_id,
            state,
            rekey: None,
            channels: HashMap::new(),
            last_channel_id: Wrapping(1),
            write: CryptoVec::new(),
            write_cursor: 0,
            last_rekey: std::time::Instant::now(),
            server_compression: newkeys.names.server_compression,
            client_compression: newkeys.names.client_compression,
            compress: crate::compression::Compress::None,
            compress_buffer: CryptoVec::new(),
            decompress: crate::compression::Decompress::None,
        });
        self.cipher = newkeys.cipher;
        self.strict_kex = newkeys.names.strict_kex;
    }

    /// Send a disconnect message.
    pub fn disconnect(&mut self, reason: Disconnect, description: &str, language_tag: &str) {
        let disconnect = |buf: &mut CryptoVec| {
            push_packet!(buf, {
                buf.push(msg::DISCONNECT);
                buf.push_u32_be(reason as u32);
                buf.extend_ssh_string(description.as_bytes());
                buf.extend_ssh_string(language_tag.as_bytes());
            });
        };
        if !self.disconnected {
            self.disconnected = true;
            if let Some(ref mut enc) = self.encrypted {
                disconnect(&mut enc.write)
            } else {
                disconnect(&mut self.write_buffer.buffer)
            }
        }
    }

    /// Send a single byte message onto the channel.
    pub fn byte(&mut self, channel: ChannelId, msg: u8) {
        if let Some(ref mut enc) = self.encrypted {
            enc.byte(channel, msg)
        }
    }

    pub(crate) fn maybe_reset_seqn(&mut self) {
        if self.strict_kex {
            self.write_buffer.seqn = Wrapping(0);
        }
    }
}

impl Encrypted {
    pub fn byte(&mut self, channel: ChannelId, msg: u8) {
        if let Some(channel) = self.channels.get(&channel) {
            push_packet!(self.write, {
                self.write.push(msg);
                self.write.push_u32_be(channel.recipient_channel);
            });
        }
    }

    /*
    pub fn authenticated(&mut self) {
        self.server_compression.init_compress(&mut self.compress);
        self.state = EncryptedState::Authenticated;
    }
    */

    pub fn eof(&mut self, channel: ChannelId) {
        if let Some(channel) = self.has_pending_data_mut(channel) {
            channel.pending_eof = true;
        } else {
            self.byte(channel, msg::CHANNEL_EOF);
        }
    }

    pub fn close(&mut self, channel: ChannelId) {
        if let Some(channel) = self.has_pending_data_mut(channel) {
            channel.pending_close = true;
        } else {
            self.byte(channel, msg::CHANNEL_CLOSE);
            self.channels.remove(&channel);
        }
    }

    pub fn sender_window_size(&self, channel: ChannelId) -> usize {
        if let Some(channel) = self.channels.get(&channel) {
            channel.sender_window_size as usize
        } else {
            0
        }
    }

    pub fn adjust_window_size(&mut self, channel: ChannelId, data: &[u8], target: u32) -> bool {
        if let Some(channel) = self.channels.get_mut(&channel) {
            trace!(
                "adjust_window_size, channel = {}, size = {},",
                channel.sender_channel,
                target
            );
            // Ignore extra data.
            // https://tools.ietf.org/html/rfc4254#section-5.2
            if data.len() as u32 <= channel.sender_window_size {
                channel.sender_window_size -= data.len() as u32;
            }
            if channel.sender_window_size < target / 2 {
                debug!(
                    "sender_window_size {:?}, target {:?}",
                    channel.sender_window_size, target
                );
                push_packet!(self.write, {
                    self.write.push(msg::CHANNEL_WINDOW_ADJUST);
                    self.write.push_u32_be(channel.recipient_channel);
                    self.write.push_u32_be(target - channel.sender_window_size);
                });
                channel.sender_window_size = target;
                return true;
            }
        }
        false
    }

    fn flush_channel(write: &mut CryptoVec, channel: &mut ChannelParams) -> ChannelFlushResult {
        let mut pending_size = 0;
        while let Some((buf, a, from)) = channel.pending_data.pop_front() {
            let size = Self::data_noqueue(write, channel, &buf, a, from);
            pending_size += size;
            if from + size < buf.len() {
                channel.pending_data.push_front((buf, a, from + size));
                return ChannelFlushResult::Incomplete {
                    wrote: pending_size,
                };
            }
        }
        ChannelFlushResult::complete(pending_size, channel)
    }

    fn handle_flushed_channel(&mut self, channel: ChannelId, flush_result: ChannelFlushResult) {
        if let ChannelFlushResult::Complete {
            wrote: _,
            pending_eof,
            pending_close,
        } = flush_result
        {
            if pending_eof {
                self.eof(channel);
            }
            if pending_close {
                self.close(channel);
            }
        }
    }

    pub fn flush_pending(&mut self, channel: ChannelId) -> usize {
        let mut pending_size = 0;
        let mut maybe_flush_result = Option::<ChannelFlushResult>::None;

        if let Some(channel) = self.channels.get_mut(&channel) {
            let flush_result = Self::flush_channel(&mut self.write, channel);
            pending_size += flush_result.wrote();
            maybe_flush_result = Some(flush_result);
        }
        if let Some(flush_result) = maybe_flush_result {
            self.handle_flushed_channel(channel, flush_result)
        }
        pending_size
    }

    pub fn flush_all_pending(&mut self) {
        for channel in self.channels.values_mut() {
            Self::flush_channel(&mut self.write, channel);
        }
    }

    fn has_pending_data_mut(&mut self, channel: ChannelId) -> Option<&mut ChannelParams> {
        self.channels
            .get_mut(&channel)
            .filter(|c| !c.pending_data.is_empty())
    }

    pub fn has_pending_data(&self, channel: ChannelId) -> bool {
        if let Some(channel) = self.channels.get(&channel) {
            !channel.pending_data.is_empty()
        } else {
            false
        }
    }

    /// Push the largest amount of `&buf0[from..]` that can fit into
    /// the window, dividing it into packets if it is too large, and
    /// return the length that was written.
    fn data_noqueue(
        write: &mut CryptoVec,
        channel: &mut ChannelParams,
        buf0: &[u8],
        a: Option<u32>,
        from: usize,
    ) -> usize {
        if from >= buf0.len() {
            return 0;
        }
        let mut buf = if buf0.len() as u32 > from as u32 + channel.recipient_window_size {
            #[allow(clippy::indexing_slicing)] // length checked
            &buf0[from..from + channel.recipient_window_size as usize]
        } else {
            #[allow(clippy::indexing_slicing)] // length checked
            &buf0[from..]
        };
        let buf_len = buf.len();

        while !buf.is_empty() {
            // Compute the length we're allowed to send.
            let off = std::cmp::min(buf.len(), channel.recipient_maximum_packet_size as usize);
            match a {
                None => push_packet!(write, {
                    write.push(msg::CHANNEL_DATA);
                    write.push_u32_be(channel.recipient_channel);
                    #[allow(clippy::indexing_slicing)] // length checked
                    write.extend_ssh_string(&buf[..off]);
                }),
                Some(ext) => push_packet!(write, {
                    write.push(msg::CHANNEL_EXTENDED_DATA);
                    write.push_u32_be(channel.recipient_channel);
                    write.push_u32_be(ext);
                    #[allow(clippy::indexing_slicing)] // length checked
                    write.extend_ssh_string(&buf[..off]);
                }),
            }
            trace!(
                "buffer: {:?} {:?}",
                write.len(),
                channel.recipient_window_size
            );
            channel.recipient_window_size -= off as u32;
            #[allow(clippy::indexing_slicing)] // length checked
            {
                buf = &buf[off..]
            }
        }
        trace!("buf.len() = {:?}, buf_len = {:?}", buf.len(), buf_len);
        buf_len
    }

    pub fn data(&mut self, channel: ChannelId, buf0: CryptoVec) {
        if let Some(channel) = self.channels.get_mut(&channel) {
            assert!(channel.confirmed);
            if !channel.pending_data.is_empty() || self.rekey.is_some() {
                channel.pending_data.push_back((buf0, None, 0));
                return;
            }
            let buf_len = Self::data_noqueue(&mut self.write, channel, &buf0, None, 0);
            if buf_len < buf0.len() {
                channel.pending_data.push_back((buf0, None, buf_len))
            }
        } else {
            debug!("{:?} not saved for this session", channel);
        }
    }

    pub fn extended_data(&mut self, channel: ChannelId, ext: u32, buf0: CryptoVec) {
        if let Some(channel) = self.channels.get_mut(&channel) {
            assert!(channel.confirmed);
            if !channel.pending_data.is_empty() {
                channel.pending_data.push_back((buf0, Some(ext), 0));
                return;
            }
            let buf_len = Self::data_noqueue(&mut self.write, channel, &buf0, Some(ext), 0);
            if buf_len < buf0.len() {
                channel.pending_data.push_back((buf0, Some(ext), buf_len))
            }
        }
    }

    pub fn flush(
        &mut self,
        limits: &Limits,
        cipher: &mut dyn SealingKey,
        write_buffer: &mut SSHBuffer,
    ) -> Result<bool, crate::Error> {
        // If there are pending packets (and we've not started to rekey), flush them.
        {
            while self.write_cursor < self.write.len() {
                // Read a single packet, encrypt and send it.
                #[allow(clippy::indexing_slicing)] // length checked
                let len = BigEndian::read_u32(&self.write[self.write_cursor..]) as usize;
                #[allow(clippy::indexing_slicing)]
                let to_write = &self.write[(self.write_cursor + 4)..(self.write_cursor + 4 + len)];
                trace!("server_write_encrypted, buf = {:?}", to_write);
                #[allow(clippy::indexing_slicing)]
                let packet = self
                    .compress
                    .compress(to_write, &mut self.compress_buffer)?;
                cipher.write(packet, write_buffer);
                self.write_cursor += 4 + len
            }
        }
        if self.write_cursor >= self.write.len() {
            // If all packets have been written, clear.
            self.write_cursor = 0;
            self.write.clear();
        }

        if self.kex.skip_exchange() {
            return Ok(false);
        }

        let now = std::time::Instant::now();
        let dur = now.duration_since(self.last_rekey);
        Ok(write_buffer.bytes >= limits.rekey_write_limit || dur >= limits.rekey_time_limit)
    }
    pub fn new_channel_id(&mut self) -> ChannelId {
        self.last_channel_id += Wrapping(1);
        while self
            .channels
            .contains_key(&ChannelId(self.last_channel_id.0))
        {
            self.last_channel_id += Wrapping(1)
        }
        ChannelId(self.last_channel_id.0)
    }
    pub fn new_channel(&mut self, window_size: u32, maxpacket: u32) -> ChannelId {
        loop {
            self.last_channel_id += Wrapping(1);
            if let std::collections::hash_map::Entry::Vacant(vacant_entry) =
                self.channels.entry(ChannelId(self.last_channel_id.0))
            {
                vacant_entry.insert(ChannelParams {
                    recipient_channel: 0,
                    sender_channel: ChannelId(self.last_channel_id.0),
                    sender_window_size: window_size,
                    recipient_window_size: 0,
                    sender_maximum_packet_size: maxpacket,
                    recipient_maximum_packet_size: 0,
                    confirmed: false,
                    wants_reply: false,
                    pending_data: std::collections::VecDeque::new(),
                    pending_eof: false,
                    pending_close: false,
                });
                return ChannelId(self.last_channel_id.0);
            }
        }
    }
}

#[derive(Debug)]
pub enum EncryptedState {
    WaitingAuthServiceRequest { sent: bool, accepted: bool },
    WaitingAuthRequest(auth::AuthRequest),
    InitCompression,
    Authenticated,
}

#[derive(Debug, Default, Clone)]
pub struct Exchange {
    pub client_id: CryptoVec,
    pub server_id: CryptoVec,
    pub client_kex_init: CryptoVec,
    pub server_kex_init: CryptoVec,
    pub client_ephemeral: CryptoVec,
    pub server_ephemeral: CryptoVec,
}

impl Exchange {
    pub fn new() -> Self {
        Exchange {
            client_id: CryptoVec::new(),
            server_id: CryptoVec::new(),
            client_kex_init: CryptoVec::new(),
            server_kex_init: CryptoVec::new(),
            client_ephemeral: CryptoVec::new(),
            server_ephemeral: CryptoVec::new(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum Kex {
    /// Version number sent. `algo` and `sent` tell wether kexinit has
    /// been received, and sent, respectively.
    Init(KexInit),

    /// Algorithms have been determined, the DH algorithm should run.
    Dh(KexDh),

    /// The kex has run.
    DhDone(KexDhDone),

    /// The DH is over, we've sent the NEWKEYS packet, and are waiting
    /// the NEWKEYS from the other side.
    Keys(NewKeys),
}

#[derive(Debug)]
pub(crate) struct KexInit {
    pub algo: Option<negotiation::Names>,
    pub exchange: Exchange,
    pub session_id: Option<CryptoVec>,
    pub sent: bool,
}

impl KexInit {
    pub fn received_rekey(ex: Exchange, algo: negotiation::Names, session_id: &CryptoVec) -> Self {
        let mut kexinit = KexInit {
            exchange: ex,
            algo: Some(algo),
            sent: false,
            session_id: Some(session_id.clone()),
        };
        kexinit.exchange.client_kex_init.clear();
        kexinit.exchange.server_kex_init.clear();
        kexinit.exchange.client_ephemeral.clear();
        kexinit.exchange.server_ephemeral.clear();
        kexinit
    }

    pub fn initiate_rekey(ex: Exchange, session_id: &CryptoVec) -> Self {
        let mut kexinit = KexInit {
            exchange: ex,
            algo: None,
            sent: true,
            session_id: Some(session_id.clone()),
        };
        kexinit.exchange.client_kex_init.clear();
        kexinit.exchange.server_kex_init.clear();
        kexinit.exchange.client_ephemeral.clear();
        kexinit.exchange.server_ephemeral.clear();
        kexinit
    }
}

#[derive(Debug)]
pub(crate) struct KexDh {
    pub exchange: Exchange,
    pub names: negotiation::Names,
    pub key: usize,
    pub session_id: Option<CryptoVec>,
}

pub(crate) struct KexDhDone {
    pub exchange: Exchange,
    pub kex: Box<dyn KexAlgorithm + Send>,
    pub key: usize,
    pub session_id: Option<CryptoVec>,
    pub names: negotiation::Names,
}

impl Debug for KexDhDone {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "KexDhDone")
    }
}

impl KexDhDone {
    pub fn compute_keys(self, hash: CryptoVec, is_server: bool) -> Result<NewKeys, crate::Error> {
        let session_id = if let Some(session_id) = self.session_id {
            session_id
        } else {
            hash.clone()
        };
        // Now computing keys.
        let c = self.kex.compute_keys(
            &session_id,
            &hash,
            self.names.cipher,
            if is_server {
                self.names.client_mac
            } else {
                self.names.server_mac
            },
            if is_server {
                self.names.server_mac
            } else {
                self.names.client_mac
            },
            is_server,
        )?;
        Ok(NewKeys {
            exchange: self.exchange,
            names: self.names,
            kex: self.kex,
            key: self.key,
            cipher: c,
            session_id,
            sent: false,
        })
    }
}

#[derive(Debug)]
pub(crate) struct NewKeys {
    pub exchange: Exchange,
    pub names: negotiation::Names,
    pub kex: Box<dyn KexAlgorithm + Send>,
    pub key: usize,
    pub cipher: cipher::CipherPair,
    pub session_id: CryptoVec,
    pub sent: bool,
}

pub(crate) enum GlobalRequestResponse {
    /// request was for Keepalive, ignore result
    Keepalive,
    /// request was for TcpIpForward, sends Some(port) for success or None for failure
    TcpIpForward(oneshot::Sender<Option<u32>>),
    /// request was for CancelTcpIpForward, sends true for success or false for failure
    CancelTcpIpForward(oneshot::Sender<bool>),
    /// request was for StreamLocalForward, sends true for success or false for failure
    StreamLocalForward(oneshot::Sender<bool>),
    CancelStreamLocalForward(oneshot::Sender<bool>),
}
