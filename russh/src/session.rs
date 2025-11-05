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
use std::mem::replace;
use std::num::Wrapping;

use byteorder::{BigEndian, ByteOrder};
use log::{debug, trace};
use ssh_encoding::Encode;
use tokio::sync::oneshot;

use crate::cipher::OpeningKey;
use crate::client::GexParams;
use crate::kex::dh::groups::DhGroup;
use crate::kex::{KexAlgorithm, KexAlgorithmImplementor};
use crate::sshbuffer::PacketWriter;
use crate::{
    ChannelId, ChannelParams, CryptoVec, Disconnect, Limits, auth, cipher, mac, msg, negotiation,
};

#[derive(Debug)]
pub(crate) struct Encrypted {
    pub state: EncryptedState,

    // It's always Some, except when we std::mem::replace it temporarily.
    pub exchange: Option<Exchange>,
    pub kex: KexAlgorithm,
    pub key: usize,
    pub client_mac: mac::Name,
    pub server_mac: mac::Name,
    pub session_id: CryptoVec,
    pub channels: HashMap<ChannelId, ChannelParams>,
    pub last_channel_id: Wrapping<u32>,
    pub write: CryptoVec,
    pub write_cursor: usize,
    pub last_rekey: russh_util::time::Instant,
    pub server_compression: crate::compression::Compression,
    pub client_compression: crate::compression::Compression,
    pub decompress: crate::compression::Decompress,
    pub rekey_wanted: bool,
    pub received_extensions: Vec<String>,
    pub extension_info_awaiters: HashMap<String, Vec<oneshot::Sender<()>>>,
}

pub(crate) struct CommonSession<Config> {
    pub auth_user: String,
    pub remote_sshid: Vec<u8>,
    pub config: Config,
    pub encrypted: Option<Encrypted>,
    pub auth_method: Option<auth::Method>,
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub(crate) auth_attempts: usize,
    pub packet_writer: PacketWriter,
    pub remote_to_local: Box<dyn OpeningKey + Send>,
    pub wants_reply: bool,
    pub disconnected: bool,
    pub buffer: CryptoVec,
    pub strict_kex: bool,
    pub alive_timeouts: usize,
    pub received_data: bool,
}

impl<C> Debug for CommonSession<C> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommonSession")
            .field("auth_user", &self.auth_user)
            .field("remote_sshid", &self.remote_sshid)
            .field("encrypted", &self.encrypted)
            .field("auth_method", &self.auth_method)
            .field("auth_attempts", &self.auth_attempts)
            .field("packet_writer", &self.packet_writer)
            .field("wants_reply", &self.wants_reply)
            .field("disconnected", &self.disconnected)
            .field("buffer", &self.buffer)
            .field("strict_kex", &self.strict_kex)
            .field("alive_timeouts", &self.alive_timeouts)
            .field("received_data", &self.received_data)
            .finish()
    }
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
            self.remote_to_local = newkeys.cipher.remote_to_local;
            self.packet_writer
                .set_cipher(newkeys.cipher.local_to_remote);
            self.strict_kex = self.strict_kex || newkeys.names.strict_kex();

            // Reset compression state
            enc.client_compression
                .init_compress(self.packet_writer.compress());
            enc.server_compression.init_decompress(&mut enc.decompress);
        }
    }

    pub fn encrypted(&mut self, state: EncryptedState, newkeys: NewKeys) {
        let strict_kex = newkeys.names.strict_kex();
        self.encrypted = Some(Encrypted {
            exchange: Some(newkeys.exchange),
            kex: newkeys.kex,
            key: newkeys.key,
            client_mac: newkeys.names.client_mac,
            server_mac: newkeys.names.server_mac,
            session_id: newkeys.session_id,
            state,
            channels: HashMap::new(),
            last_channel_id: Wrapping(1),
            write: CryptoVec::new(),
            write_cursor: 0,
            last_rekey: russh_util::time::Instant::now(),
            server_compression: newkeys.names.server_compression,
            client_compression: newkeys.names.client_compression,
            decompress: crate::compression::Decompress::None,
            rekey_wanted: false,
            received_extensions: Vec::new(),
            extension_info_awaiters: HashMap::new(),
        });
        self.remote_to_local = newkeys.cipher.remote_to_local;
        self.packet_writer
            .set_cipher(newkeys.cipher.local_to_remote);
        self.strict_kex = strict_kex;
    }

    /// Send a disconnect message.
    pub fn disconnect(
        &mut self,
        reason: Disconnect,
        description: &str,
        language_tag: &str,
    ) -> Result<(), crate::Error> {
        let disconnect = |buf: &mut CryptoVec| {
            push_packet!(buf, {
                msg::DISCONNECT.encode(buf)?;
                (reason as u32).encode(buf)?;
                description.encode(buf)?;
                language_tag.encode(buf)?;
            });
            Ok(())
        };
        if !self.disconnected {
            self.disconnected = true;
            return if let Some(ref mut enc) = self.encrypted {
                disconnect(&mut enc.write)
            } else {
                disconnect(&mut self.packet_writer.buffer().buffer)
            };
        }
        Ok(())
    }

    /// Send a debug message.
    pub fn debug(
        &mut self,
        always_display: bool,
        message: &str,
        language_tag: &str,
    ) -> Result<(), crate::Error> {
        let debug = |buf: &mut CryptoVec| {
            push_packet!(buf, {
                msg::DEBUG.encode(buf)?;
                (always_display as u8).encode(buf)?;
                message.encode(buf)?;
                language_tag.encode(buf)?;
            });
            Ok(())
        };
        if let Some(ref mut enc) = self.encrypted {
            debug(&mut enc.write)
        } else {
            debug(&mut self.packet_writer.buffer().buffer)
        }
    }

    pub(crate) fn reset_seqn(&mut self) {
        self.packet_writer.reset_seqn();
    }
}

impl Encrypted {
    pub fn byte(&mut self, channel: ChannelId, msg: u8) -> Result<(), crate::Error> {
        if let Some(channel) = self.channels.get(&channel) {
            push_packet!(self.write, {
                self.write.push(msg);
                channel.recipient_channel.encode(&mut self.write)?;
            });
        }
        Ok(())
    }

    pub fn eof(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        if let Some(channel) = self.has_pending_data_mut(channel) {
            channel.pending_eof = true;
        } else {
            self.byte(channel, msg::CHANNEL_EOF)?;
        }
        Ok(())
    }

    pub fn close(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        if let Some(channel) = self.has_pending_data_mut(channel) {
            channel.pending_close = true;
        } else {
            self.byte(channel, msg::CHANNEL_CLOSE)?;
            self.channels.remove(&channel);
        }
        Ok(())
    }

    pub fn sender_window_size(&self, channel: ChannelId) -> usize {
        if let Some(channel) = self.channels.get(&channel) {
            channel.sender_window_size as usize
        } else {
            0
        }
    }

    pub fn adjust_window_size(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        target: u32,
    ) -> Result<bool, crate::Error> {
        if let Some(channel) = self.channels.get_mut(&channel) {
            trace!(
                "adjust_window_size, channel = {}, size = {},",
                channel.sender_channel, target
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
                    channel.recipient_channel.encode(&mut self.write)?;
                    (target - channel.sender_window_size).encode(&mut self.write)?;
                });
                channel.sender_window_size = target;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn flush_channel(
        write: &mut CryptoVec,
        channel: &mut ChannelParams,
    ) -> Result<ChannelFlushResult, crate::Error> {
        let mut pending_size = 0;
        while let Some((buf, a, from)) = channel.pending_data.pop_front() {
            let size = Self::data_noqueue(write, channel, &buf, a, from)?;
            pending_size += size;
            if from + size < buf.len() {
                channel.pending_data.push_front((buf, a, from + size));
                return Ok(ChannelFlushResult::Incomplete {
                    wrote: pending_size,
                });
            }
        }
        Ok(ChannelFlushResult::complete(pending_size, channel))
    }

    fn handle_flushed_channel(
        &mut self,
        channel: ChannelId,
        flush_result: ChannelFlushResult,
    ) -> Result<(), crate::Error> {
        if let ChannelFlushResult::Complete {
            wrote: _,
            pending_eof,
            pending_close,
        } = flush_result
        {
            if pending_eof {
                self.eof(channel)?;
            }
            if pending_close {
                self.close(channel)?;
            }
        }
        Ok(())
    }

    pub fn flush_pending(&mut self, channel: ChannelId) -> Result<usize, crate::Error> {
        let mut pending_size = 0;
        let mut maybe_flush_result = Option::<ChannelFlushResult>::None;

        if let Some(channel) = self.channels.get_mut(&channel) {
            let flush_result = Self::flush_channel(&mut self.write, channel)?;
            pending_size += flush_result.wrote();
            maybe_flush_result = Some(flush_result);
        }
        if let Some(flush_result) = maybe_flush_result {
            self.handle_flushed_channel(channel, flush_result)?
        }
        Ok(pending_size)
    }

    pub fn flush_all_pending(&mut self) -> Result<(), crate::Error> {
        for channel in self.channels.values_mut() {
            Self::flush_channel(&mut self.write, channel)?;
        }
        Ok(())
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
    ) -> Result<usize, crate::Error> {
        if from >= buf0.len() {
            return Ok(0);
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
                    channel.recipient_channel.encode(write)?;
                    #[allow(clippy::indexing_slicing)] // length checked
                    buf[..off].encode(write)?;
                }),
                Some(ext) => push_packet!(write, {
                    write.push(msg::CHANNEL_EXTENDED_DATA);
                    channel.recipient_channel.encode(write)?;
                    ext.encode(write)?;
                    #[allow(clippy::indexing_slicing)] // length checked
                    buf[..off].encode(write)?;
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
        Ok(buf_len)
    }

    pub fn data(
        &mut self,
        channel: ChannelId,
        buf0: CryptoVec,
        is_rekeying: bool,
    ) -> Result<(), crate::Error> {
        if let Some(channel) = self.channels.get_mut(&channel) {
            assert!(channel.confirmed);
            if !channel.pending_data.is_empty() && is_rekeying {
                channel.pending_data.push_back((buf0, None, 0));
                return Ok(());
            }
            let buf_len = Self::data_noqueue(&mut self.write, channel, &buf0, None, 0)?;
            if buf_len < buf0.len() {
                channel.pending_data.push_back((buf0, None, buf_len))
            }
        } else {
            debug!("{channel:?} not saved for this session");
        }
        Ok(())
    }

    pub fn extended_data(
        &mut self,
        channel: ChannelId,
        ext: u32,
        buf0: CryptoVec,
        is_rekeying: bool,
    ) -> Result<(), crate::Error> {
        if let Some(channel) = self.channels.get_mut(&channel) {
            assert!(channel.confirmed);
            if !channel.pending_data.is_empty() && is_rekeying {
                channel.pending_data.push_back((buf0, Some(ext), 0));
                return Ok(());
            }
            let buf_len = Self::data_noqueue(&mut self.write, channel, &buf0, Some(ext), 0)?;
            if buf_len < buf0.len() {
                channel.pending_data.push_back((buf0, Some(ext), buf_len))
            }
        }
        Ok(())
    }

    pub fn flush(
        &mut self,
        limits: &Limits,
        writer: &mut PacketWriter,
    ) -> Result<bool, crate::Error> {
        // If there are pending packets (and we've not started to rekey), flush them.
        {
            while self.write_cursor < self.write.len() {
                // Read a single packet, encrypt and send it.
                #[allow(clippy::indexing_slicing)] // length checked
                let len = BigEndian::read_u32(&self.write[self.write_cursor..]) as usize;
                #[allow(clippy::indexing_slicing)]
                let to_write = &self.write[(self.write_cursor + 4)..(self.write_cursor + 4 + len)];
                trace!("session_write_encrypted, buf = {to_write:?}");

                writer.packet_raw(to_write)?;
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

        let now = russh_util::time::Instant::now();
        let dur = now.duration_since(self.last_rekey);
        Ok(replace(&mut self.rekey_wanted, false)
            || writer.buffer().bytes >= limits.rekey_write_limit
            || dur >= limits.rekey_time_limit)
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
    pub gex: Option<(GexParams, DhGroup)>,
}

impl Exchange {
    pub fn new(client_id: &[u8], server_id: &[u8]) -> Self {
        Exchange {
            client_id: client_id.into(),
            server_id: server_id.into(),
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub(crate) struct NewKeys {
    pub exchange: Exchange,
    pub names: negotiation::Names,
    pub kex: KexAlgorithm,
    pub key: usize,
    pub cipher: cipher::CipherPair,
    pub session_id: CryptoVec,
}

#[derive(Debug)]
pub(crate) enum GlobalRequestResponse {
    /// request was for Keepalive, ignore result
    Keepalive,
    /// request was for Keepalive but with notification of the result
    Ping(oneshot::Sender<()>),
    /// request was for NoMoreSessions, disallow additional sessions
    NoMoreSessions,
    /// request was for TcpIpForward, sends Some(port) for success or None for failure
    TcpIpForward(oneshot::Sender<Option<u32>>),
    /// request was for CancelTcpIpForward, sends true for success or false for failure
    CancelTcpIpForward(oneshot::Sender<bool>),
    /// request was for StreamLocalForward, sends true for success or false for failure
    StreamLocalForward(oneshot::Sender<bool>),
    CancelStreamLocalForward(oneshot::Sender<bool>),
}
