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
use std::cell::RefCell;
use std::convert::TryInto;
use std::num::Wrapping;

use log::{debug, error, info, trace, warn};
use russh_cryptovec::CryptoVec;
use russh_keys::encoding::{Encoding, Reader};
use russh_keys::key::parse_public_key;

use crate::client::{Handler, Msg, Prompt, Reply, Session};
use crate::key::PubKey;
use crate::negotiation::{Named, Select};
use crate::parsing::{ChannelOpenConfirmation, ChannelType, OpenChannelMessage};
use crate::session::{Encrypted, EncryptedState, GlobalRequestResponse, Kex, KexInit};
use crate::{
    auth, msg, negotiation, strict_kex_violation, Channel, ChannelId, ChannelMsg,
    ChannelOpenFailure, ChannelParams, Sig,
};

thread_local! {
    static SIGNATURE_BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

impl Session {
    pub(crate) async fn client_read_encrypted<H: Handler>(
        &mut self,
        client: &mut H,
        seqn: &mut Wrapping<u32>,
        buf: &[u8],
    ) -> Result<(), H::Error> {
        #[allow(clippy::indexing_slicing)] // length checked
        {
            trace!(
                "client_read_encrypted, buf = {:?}",
                &buf[..buf.len().min(20)]
            );
        }
        // Either this packet is a KEXINIT, in which case we start a key re-exchange.
        if buf.first() == Some(&msg::KEXINIT) {
            debug!("Received KEXINIT");
            // Now, if we're encrypted:
            if let Some(ref mut enc) = self.common.encrypted {
                // If we're not currently re-keying, but buf is a rekey request
                let kexinit = if let Some(Kex::Init(kexinit)) = enc.rekey.take() {
                    Some(kexinit)
                } else if let Some(exchange) = enc.exchange.take() {
                    Some(KexInit::received_rekey(
                        exchange,
                        negotiation::Client::read_kex(
                            buf,
                            &self.common.config.as_ref().preferred,
                            None,
                        )?,
                        &enc.session_id,
                    ))
                } else {
                    None
                };

                if let Some(kexinit) = kexinit {
                    if let Some(ref algo) = kexinit.algo {
                        if self.common.strict_kex && !algo.strict_kex {
                            return Err(strict_kex_violation(msg::KEXINIT, 0).into());
                        }
                    }

                    let dhdone = kexinit.client_parse(
                        self.common.config.as_ref(),
                        &mut *self.common.cipher.local_to_remote,
                        buf,
                        &mut self.common.write_buffer,
                    )?;

                    if !enc.kex.skip_exchange() {
                        enc.rekey = Some(Kex::DhDone(dhdone));
                    }
                }
            } else {
                unreachable!()
            }
            self.flush()?;
            return Ok(());
        }

        if let Some(ref mut enc) = self.common.encrypted {
            match enc.rekey.take() {
                Some(Kex::DhDone(mut kexdhdone)) => {
                    return if kexdhdone.names.ignore_guessed {
                        kexdhdone.names.ignore_guessed = false;
                        enc.rekey = Some(Kex::DhDone(kexdhdone));
                        Ok(())
                    } else if buf.first() == Some(&msg::KEX_ECDH_REPLY) {
                        // We've sent ECDH_INIT, waiting for ECDH_REPLY
                        let kex = kexdhdone.server_key_check(true, client, buf).await?;
                        enc.rekey = Some(Kex::Keys(kex));
                        self.common
                            .cipher
                            .local_to_remote
                            .write(&[msg::NEWKEYS], &mut self.common.write_buffer);
                        self.flush()?;
                        self.common.maybe_reset_seqn();
                        Ok(())
                    } else {
                        error!("Wrong packet received");
                        Err(crate::Error::Inconsistent.into())
                    };
                }
                Some(Kex::Keys(newkeys)) => {
                    if buf.first() != Some(&msg::NEWKEYS) {
                        return Err(crate::Error::Kex.into());
                    }
                    self.common.write_buffer.bytes = 0;
                    enc.last_rekey = std::time::Instant::now();

                    // Ok, NEWKEYS received, now encrypted.
                    enc.flush_all_pending();
                    let mut pending = std::mem::take(&mut self.pending_reads);
                    for p in pending.drain(..) {
                        self.process_packet(client, &p).await?;
                    }
                    self.pending_reads = pending;
                    self.pending_len = 0;
                    self.common.newkeys(newkeys);
                    self.flush()?;

                    if self.common.strict_kex {
                        *seqn = Wrapping(0);
                    }

                    return Ok(());
                }
                Some(Kex::Init(k)) => {
                    enc.rekey = Some(Kex::Init(k));
                    self.pending_len += buf.len() as u32;
                    if self.pending_len > 2 * self.target_window_size {
                        return Err(crate::Error::Pending.into());
                    }
                    self.pending_reads.push(CryptoVec::from_slice(buf));
                    return Ok(());
                }
                rek => enc.rekey = rek,
            }
        }
        self.process_packet(client, buf).await
    }

    async fn process_packet<H: Handler>(
        &mut self,
        client: &mut H,
        buf: &[u8],
    ) -> Result<(), H::Error> {
        // If we've successfully read a packet.
        trace!("process_packet buf = {:?} bytes", buf.len());
        trace!("buf = {:?}", buf);
        let mut is_authenticated = false;
        if let Some(ref mut enc) = self.common.encrypted {
            match enc.state {
                EncryptedState::WaitingAuthServiceRequest {
                    ref mut accepted, ..
                } => {
                    debug!(
                        "waiting service request, {:?} {:?}",
                        buf.first(),
                        msg::SERVICE_ACCEPT
                    );
                    if buf.first() == Some(&msg::SERVICE_ACCEPT) {
                        let mut r = buf.reader(1);
                        if r.read_string().map_err(crate::Error::from)? == b"ssh-userauth" {
                            *accepted = true;
                            if let Some(ref meth) = self.common.auth_method {
                                let auth_request = match meth {
                                    crate::auth::Method::KeyboardInteractive { submethods } => {
                                        auth::AuthRequest {
                                            methods: auth::MethodSet::all(),
                                            partial_success: false,
                                            current: Some(
                                                auth::CurrentRequest::KeyboardInteractive {
                                                    submethods: submethods.to_string(),
                                                },
                                            ),
                                            rejection_count: 0,
                                        }
                                    }
                                    _ => auth::AuthRequest {
                                        methods: auth::MethodSet::all(),
                                        partial_success: false,
                                        current: None,
                                        rejection_count: 0,
                                    },
                                };
                                let len = enc.write.len();
                                #[allow(clippy::indexing_slicing)] // length checked
                                if enc.write_auth_request(&self.common.auth_user, meth) {
                                    debug!("enc: {:?}", &enc.write[len..]);
                                    enc.state = EncryptedState::WaitingAuthRequest(auth_request)
                                }
                            } else {
                                debug!("no auth method")
                            }
                        }
                    } else if buf.first() == Some(&msg::EXT_INFO) {
                        return self.handle_ext_info(client, buf);
                    } else {
                        debug!("unknown message: {:?}", buf);
                        return Err(crate::Error::Inconsistent.into());
                    }
                }
                EncryptedState::WaitingAuthRequest(ref mut auth_request) => {
                    if buf.first() == Some(&msg::USERAUTH_SUCCESS) {
                        debug!("userauth_success");
                        self.sender
                            .send(Reply::AuthSuccess)
                            .map_err(|_| crate::Error::SendError)?;
                        enc.state = EncryptedState::InitCompression;
                        enc.server_compression.init_decompress(&mut enc.decompress);
                        return Ok(());
                    } else if buf.first() == Some(&msg::USERAUTH_BANNER) {
                        let mut r = buf.reader(1);
                        let banner = r.read_string().map_err(crate::Error::from)?;
                        return if let Ok(banner) = std::str::from_utf8(banner) {
                            client.auth_banner(banner, self).await
                        } else {
                            Ok(())
                        };
                    } else if buf.first() == Some(&msg::USERAUTH_FAILURE) {
                        debug!("userauth_failure");

                        let mut r = buf.reader(1);
                        let remaining_methods = r.read_string().map_err(crate::Error::from)?;
                        debug!(
                            "remaining methods {:?}",
                            std::str::from_utf8(remaining_methods)
                        );
                        auth_request.methods = auth::MethodSet::empty();
                        for method in remaining_methods.split(|&c| c == b',') {
                            if let Some(m) = auth::MethodSet::from_bytes(method) {
                                auth_request.methods |= m
                            }
                        }
                        let no_more_methods = auth_request.methods.is_empty();
                        self.common.auth_method = None;
                        self.sender
                            .send(Reply::AuthFailure)
                            .map_err(|_| crate::Error::SendError)?;

                        // If no other authentication method is allowed by the server, give up.
                        if no_more_methods {
                            return Err(crate::Error::NoAuthMethod.into());
                        }
                    } else if buf.first() == Some(&msg::USERAUTH_INFO_REQUEST_OR_USERAUTH_PK_OK) {
                        if let Some(auth::CurrentRequest::PublicKey {
                            ref mut sent_pk_ok, ..
                        }) = auth_request.current
                        {
                            debug!("userauth_pk_ok");
                            *sent_pk_ok = true;
                        } else if let Some(auth::CurrentRequest::KeyboardInteractive { .. }) =
                            auth_request.current
                        {
                            debug!("keyboard_interactive");
                            let mut r = buf.reader(1);

                            // read fields
                            let name = String::from_utf8_lossy(
                                r.read_string().map_err(crate::Error::from)?,
                            )
                            .to_string();

                            let instructions = String::from_utf8_lossy(
                                r.read_string().map_err(crate::Error::from)?,
                            )
                            .to_string();

                            let _lang = r.read_string().map_err(crate::Error::from)?;
                            let n_prompts = r.read_u32().map_err(crate::Error::from)?;

                            // read prompts
                            let mut prompts = Vec::with_capacity(n_prompts.try_into().unwrap_or(0));
                            for _i in 0..n_prompts {
                                let prompt = String::from_utf8_lossy(
                                    r.read_string().map_err(crate::Error::from)?,
                                );

                                let echo = r.read_byte().map_err(crate::Error::from)? != 0;
                                prompts.push(Prompt {
                                    prompt: prompt.to_string(),
                                    echo,
                                });
                            }

                            // send challenges to caller
                            self.sender
                                .send(Reply::AuthInfoRequest {
                                    name,
                                    instructions,
                                    prompts,
                                })
                                .map_err(|_| crate::Error::SendError)?;

                            // wait for response from handler
                            let responses = loop {
                                match self.receiver.recv().await {
                                    Some(Msg::AuthInfoResponse { responses }) => break responses,
                                    _ => {}
                                }
                            };
                            // write responses
                            enc.client_send_auth_response(&responses)?;
                            return Ok(());
                        }

                        // continue with userauth_pk_ok
                        match self.common.auth_method.take() {
                            Some(auth_method @ auth::Method::PublicKey { .. }) => {
                                self.common.buffer.clear();
                                enc.client_send_signature(
                                    &self.common.auth_user,
                                    &auth_method,
                                    &mut self.common.buffer,
                                )?
                            }
                            Some(auth_method @ auth::Method::OpenSSHCertificate { .. }) => {
                                self.common.buffer.clear();
                                enc.client_send_signature(
                                    &self.common.auth_user,
                                    &auth_method,
                                    &mut self.common.buffer,
                                )?
                            }
                            Some(auth::Method::FuturePublicKey { key }) => {
                                debug!("public key");
                                self.common.buffer.clear();
                                let i = enc.client_make_to_sign(
                                    &self.common.auth_user,
                                    &key,
                                    &mut self.common.buffer,
                                );
                                let len = self.common.buffer.len();
                                let buf =
                                    std::mem::replace(&mut self.common.buffer, CryptoVec::new());

                                self.sender
                                    .send(Reply::SignRequest { key, data: buf })
                                    .map_err(|_| crate::Error::SendError)?;
                                self.common.buffer = loop {
                                    match self.receiver.recv().await {
                                        Some(Msg::Signed { data }) => break data,
                                        _ => {}
                                    }
                                };
                                if self.common.buffer.len() != len {
                                    // The buffer was modified.
                                    push_packet!(enc.write, {
                                        #[allow(clippy::indexing_slicing)] // length checked
                                        enc.write.extend(&self.common.buffer[i..]);
                                    })
                                }
                            }
                            _ => {}
                        }
                    } else if buf.first() == Some(&msg::EXT_INFO) {
                        return self.handle_ext_info(client, buf);
                    } else {
                        debug!("unknown message: {:?}", buf);
                        return Err(crate::Error::Inconsistent.into());
                    }
                }
                EncryptedState::InitCompression => unreachable!(),
                EncryptedState::Authenticated => is_authenticated = true,
            }
        }
        if is_authenticated {
            self.client_read_authenticated(client, buf).await
        } else {
            Ok(())
        }
    }

    fn handle_ext_info<H: Handler>(&mut self, _client: &mut H, buf: &[u8]) -> Result<(), H::Error> {
        debug!("Received EXT_INFO: {:?}", buf);
        Ok(())
    }

    async fn client_read_authenticated<H: Handler>(
        &mut self,
        client: &mut H,
        buf: &[u8],
    ) -> Result<(), H::Error> {
        match buf.first() {
            Some(&msg::CHANNEL_OPEN_CONFIRMATION) => {
                debug!("channel_open_confirmation");
                let mut reader = buf.reader(1);
                let msg = ChannelOpenConfirmation::parse(&mut reader)?;
                let local_id = ChannelId(msg.recipient_channel);

                if let Some(ref mut enc) = self.common.encrypted {
                    if let Some(parameters) = enc.channels.get_mut(&local_id) {
                        parameters.confirm(&msg);
                    } else {
                        // We've not requested this channel, close connection.
                        return Err(crate::Error::Inconsistent.into());
                    }
                } else {
                    return Err(crate::Error::Inconsistent.into());
                };

                if let Some(channel) = self.channels.get(&local_id) {
                    channel
                        .send(ChannelMsg::Open {
                            id: local_id,
                            max_packet_size: msg.maximum_packet_size,
                            window_size: msg.initial_window_size,
                        })
                        .unwrap_or(());
                } else {
                    error!("no channel for id {local_id:?}");
                }

                client
                    .channel_open_confirmation(
                        local_id,
                        msg.maximum_packet_size,
                        msg.initial_window_size,
                        self,
                    )
                    .await
            }
            Some(&msg::CHANNEL_CLOSE) => {
                debug!("channel_close");
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                if let Some(ref mut enc) = self.common.encrypted {
                    // The CHANNEL_CLOSE message must be sent to the server at this point or the session
                    // will not be released.
                    enc.close(channel_num);
                }
                self.channels.remove(&channel_num);
                client.channel_close(channel_num, self).await
            }
            Some(&msg::CHANNEL_EOF) => {
                debug!("channel_eof");
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan.send(ChannelMsg::Eof);
                }
                client.channel_eof(channel_num, self).await
            }
            Some(&msg::CHANNEL_OPEN_FAILURE) => {
                debug!("channel_open_failure");
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                let reason_code =
                    ChannelOpenFailure::from_u32(r.read_u32().map_err(crate::Error::from)?)
                        .unwrap_or(ChannelOpenFailure::Unknown);
                let descr = std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                    .map_err(crate::Error::from)?;
                let language = std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                    .map_err(crate::Error::from)?;
                if let Some(ref mut enc) = self.common.encrypted {
                    enc.channels.remove(&channel_num);
                }

                if let Some(sender) = self.channels.remove(&channel_num) {
                    let _ = sender.send(ChannelMsg::OpenFailure(reason_code));
                }

                let _ = self.sender.send(Reply::ChannelOpenFailure);

                client
                    .channel_open_failure(channel_num, reason_code, descr, language, self)
                    .await
            }
            Some(&msg::CHANNEL_DATA) => {
                trace!("channel_data");
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                let data = r.read_string().map_err(crate::Error::from)?;
                let target = self.common.config.window_size;
                if let Some(ref mut enc) = self.common.encrypted {
                    if enc.adjust_window_size(channel_num, data, target) {
                        let next_window =
                            client.adjust_window(channel_num, self.target_window_size);
                        if next_window > 0 {
                            self.target_window_size = next_window
                        }
                    }
                }

                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan.send(ChannelMsg::Data {
                        data: CryptoVec::from_slice(data),
                    });
                }

                client.data(channel_num, data, self).await
            }
            Some(&msg::CHANNEL_EXTENDED_DATA) => {
                debug!("channel_extended_data");
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                let extended_code = r.read_u32().map_err(crate::Error::from)?;
                let data = r.read_string().map_err(crate::Error::from)?;
                let target = self.common.config.window_size;
                if let Some(ref mut enc) = self.common.encrypted {
                    if enc.adjust_window_size(channel_num, data, target) {
                        let next_window =
                            client.adjust_window(channel_num, self.target_window_size);
                        if next_window > 0 {
                            self.target_window_size = next_window
                        }
                    }
                }

                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan.send(ChannelMsg::ExtendedData {
                        ext: extended_code,
                        data: CryptoVec::from_slice(data),
                    });
                }

                client
                    .extended_data(channel_num, extended_code, data, self)
                    .await
            }
            Some(&msg::CHANNEL_REQUEST) => {
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                let req = r.read_string().map_err(crate::Error::from)?;
                debug!(
                    "channel_request: {:?} {:?}",
                    channel_num,
                    std::str::from_utf8(req)
                );
                match req {
                    b"xon-xoff" => {
                        r.read_byte().map_err(crate::Error::from)?; // should be 0.
                        let client_can_do = r.read_byte().map_err(crate::Error::from)? != 0;
                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan.send(ChannelMsg::XonXoff { client_can_do });
                        }
                        client.xon_xoff(channel_num, client_can_do, self).await
                    }
                    b"exit-status" => {
                        r.read_byte().map_err(crate::Error::from)?; // should be 0.
                        let exit_status = r.read_u32().map_err(crate::Error::from)?;
                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan.send(ChannelMsg::ExitStatus { exit_status });
                        }
                        client.exit_status(channel_num, exit_status, self).await
                    }
                    b"exit-signal" => {
                        r.read_byte().map_err(crate::Error::from)?; // should be 0.
                        let signal_name =
                            Sig::from_name(r.read_string().map_err(crate::Error::from)?)?;
                        let core_dumped = r.read_byte().map_err(crate::Error::from)? != 0;
                        let error_message =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        let lang_tag =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan.send(ChannelMsg::ExitSignal {
                                signal_name: signal_name.clone(),
                                core_dumped,
                                error_message: error_message.to_string(),
                                lang_tag: lang_tag.to_string(),
                            });
                        }
                        client
                            .exit_signal(
                                channel_num,
                                signal_name,
                                core_dumped,
                                error_message,
                                lang_tag,
                                self,
                            )
                            .await
                    }
                    b"keepalive@openssh.com" => {
                        let wants_reply = r.read_byte().map_err(crate::Error::from)?;
                        if wants_reply == 1 {
                            if let Some(ref mut enc) = self.common.encrypted {
                                trace!(
                                    "Received channel keep alive message: {:?}",
                                    std::str::from_utf8(req),
                                );
                                self.common.wants_reply = false;
                                push_packet!(enc.write, {
                                    enc.write.push(msg::CHANNEL_SUCCESS);
                                    enc.write.push_u32_be(channel_num.0)
                                });
                            }
                        } else {
                            warn!("Received keepalive without reply request!");
                        }
                        Ok(())
                    }
                    _ => {
                        let wants_reply = r.read_byte().map_err(crate::Error::from)?;
                        if wants_reply == 1 {
                            if let Some(ref mut enc) = self.common.encrypted {
                                self.common.wants_reply = false;
                                push_packet!(enc.write, {
                                    enc.write.push(msg::CHANNEL_FAILURE);
                                    enc.write.push_u32_be(channel_num.0)
                                })
                            }
                        }
                        info!(
                            "Unknown channel request {:?} {:?}",
                            std::str::from_utf8(req),
                            wants_reply
                        );
                        Ok(())
                    }
                }
            }
            Some(&msg::CHANNEL_WINDOW_ADJUST) => {
                debug!("channel_window_adjust");
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                let amount = r.read_u32().map_err(crate::Error::from)?;
                let mut new_size = 0;
                debug!("amount: {:?}", amount);
                if let Some(ref mut enc) = self.common.encrypted {
                    if let Some(ref mut channel) = enc.channels.get_mut(&channel_num) {
                        channel.recipient_window_size += amount;
                        new_size = channel.recipient_window_size;
                    } else {
                        return Err(crate::Error::WrongChannel.into());
                    }
                }

                if let Some(ref mut enc) = self.common.encrypted {
                    new_size -= enc.flush_pending(channel_num) as u32;
                }
                if let Some(chan) = self.channels.get(&channel_num) {
                    *chan.window_size().lock().await = new_size;

                    let _ = chan.send(ChannelMsg::WindowAdjusted { new_size });
                }
                client.window_adjusted(channel_num, new_size, self).await
            }
            Some(&msg::GLOBAL_REQUEST) => {
                let mut r = buf.reader(1);
                let req = r.read_string().map_err(crate::Error::from)?;
                let wants_reply = r.read_byte().map_err(crate::Error::from)?;
                if let Some(ref mut enc) = self.common.encrypted {
                    if req.starts_with(b"keepalive") {
                        if wants_reply == 1 {
                            trace!(
                                "Received keep alive message: {:?}",
                                std::str::from_utf8(req),
                            );
                            self.common.wants_reply = false;
                            push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS));
                        } else {
                            warn!("Received keepalive without reply request!");
                        }
                    } else if req == b"hostkeys-00@openssh.com" {
                        let mut keys = vec![];
                        loop {
                            match r.read_string() {
                                Ok(key) => {
                                    let key2 = <&[u8]>::clone(&key);
                                    let key =
                                        parse_public_key(key, None).map_err(crate::Error::from);
                                    match key {
                                        Ok(key) => keys.push(key),
                                        Err(err) => {
                                            debug!(
                                                "failed to parse announced host key {:?}: {:?}",
                                                key2, err
                                            )
                                        }
                                    }
                                }
                                Err(russh_keys::Error::IndexOutOfBounds) => break,
                                x => {
                                    x.map_err(crate::Error::from)?;
                                }
                            }
                        }
                        return client.openssh_ext_host_keys_announced(keys, self).await;
                    } else {
                        warn!(
                            "Unhandled global request: {:?} {:?}",
                            std::str::from_utf8(req),
                            wants_reply
                        );
                        self.common.wants_reply = false;
                        push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
                    }
                }
                self.common.received_data = false;
                Ok(())
            }
            Some(&msg::CHANNEL_SUCCESS) => {
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan.send(ChannelMsg::Success);
                }
                client.channel_success(channel_num, self).await
            }
            Some(&msg::CHANNEL_FAILURE) => {
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan.send(ChannelMsg::Failure);
                }
                client.channel_failure(channel_num, self).await
            }
            Some(&msg::CHANNEL_OPEN) => {
                let mut r = buf.reader(1);
                let msg = OpenChannelMessage::parse(&mut r)?;

                if let Some(ref mut enc) = self.common.encrypted {
                    let id = enc.new_channel_id();
                    let channel = ChannelParams {
                        recipient_channel: msg.recipient_channel,
                        sender_channel: id,
                        recipient_window_size: msg.recipient_window_size,
                        sender_window_size: self.common.config.window_size,
                        recipient_maximum_packet_size: msg.recipient_maximum_packet_size,
                        sender_maximum_packet_size: self.common.config.maximum_packet_size,
                        confirmed: true,
                        wants_reply: false,
                        pending_data: std::collections::VecDeque::new(),
                        pending_eof: false,
                        pending_close: false,
                    };

                    let confirm = || {
                        debug!("confirming channel: {:?}", msg);
                        msg.confirm(
                            &mut enc.write,
                            id.0,
                            channel.sender_window_size,
                            channel.sender_maximum_packet_size,
                        );
                        enc.channels.insert(id, channel);
                    };

                    match &msg.typ {
                        ChannelType::Session => {
                            confirm();
                            client.server_channel_open_session(id, self).await?
                        }
                        ChannelType::DirectTcpip(d) => {
                            confirm();
                            client
                                .server_channel_open_direct_tcpip(
                                    id,
                                    &d.host_to_connect,
                                    d.port_to_connect,
                                    &d.originator_address,
                                    d.originator_port,
                                    self,
                                )
                                .await?
                        }
                        ChannelType::X11 {
                            originator_address,
                            originator_port,
                        } => {
                            confirm();
                            let channel = self.accept_server_initiated_channel(id, &msg);
                            client
                                .server_channel_open_x11(
                                    channel,
                                    originator_address,
                                    *originator_port,
                                    self,
                                )
                                .await?
                        }
                        ChannelType::ForwardedTcpIp(d) => {
                            confirm();
                            let channel = self.accept_server_initiated_channel(id, &msg);
                            client
                                .server_channel_open_forwarded_tcpip(
                                    channel,
                                    &d.host_to_connect,
                                    d.port_to_connect,
                                    &d.originator_address,
                                    d.originator_port,
                                    self,
                                )
                                .await?
                        }
                        ChannelType::AgentForward => {
                            confirm();
                            client.server_channel_open_agent_forward(id, self).await?
                        }
                        ChannelType::Unknown { typ } => {
                            if client.server_channel_handle_unknown(id, typ) {
                                confirm();
                            } else {
                                debug!("unknown channel type: {}", String::from_utf8_lossy(typ));
                                msg.unknown_type(&mut enc.write);
                            }
                        }
                    };
                    Ok(())
                } else {
                    Err(crate::Error::Inconsistent.into())
                }
            }
            Some(&msg::REQUEST_SUCCESS) => {
                trace!("Global Request Success");
                match self.open_global_requests.pop_front() {
                    Some(GlobalRequestResponse::Keepalive) => {
                        // ignore keepalives
                    }
                    Some(GlobalRequestResponse::TcpIpForward(return_channel)) => {
                        let result = if buf.len() == 1 {
                            // If a specific port was requested, the reply has no data
                            Some(0)
                        } else {
                            let mut r = buf.reader(1);
                            match r.read_u32() {
                                Ok(port) => Some(port),
                                Err(e) => {
                                    error!("Error parsing port for TcpIpForward request: {e:?}");
                                    None
                                }
                            }
                        };
                        let _ = return_channel.send(result);
                    }
                    Some(GlobalRequestResponse::CancelTcpIpForward(return_channel)) => {
                        let _ = return_channel.send(true);
                    }
                    None => {
                        error!("Received global request failure for unknown request!")
                    }
                }
                Ok(())
            }
            Some(&msg::REQUEST_FAILURE) => {
                trace!("global request failure");
                match self.open_global_requests.pop_front() {
                    Some(GlobalRequestResponse::Keepalive) => {
                        // ignore keepalives
                    }
                    Some(GlobalRequestResponse::TcpIpForward(return_channel)) => {
                        let _ = return_channel.send(None);
                    }
                    Some(GlobalRequestResponse::CancelTcpIpForward(return_channel)) => {
                        let _ = return_channel.send(false);
                    }
                    None => {
                        error!("Received global request failure for unknown request!")
                    }
                }
                Ok(())
            }
            m => {
                debug!("unknown message received: {:?}", m);
                Ok(())
            }
        }
    }

    fn accept_server_initiated_channel(
        &mut self,
        id: ChannelId,
        msg: &OpenChannelMessage,
    ) -> Channel<Msg> {
        let (channel, channel_ref) = Channel::new(
            id,
            self.inbound_channel_sender.clone(),
            msg.recipient_maximum_packet_size,
            msg.recipient_window_size,
        );

        self.channels.insert(id, channel_ref);

        channel
    }

    pub(crate) fn write_auth_request_if_needed(&mut self, user: &str, meth: auth::Method) -> bool {
        let mut is_waiting = false;
        if let Some(ref mut enc) = self.common.encrypted {
            is_waiting = match enc.state {
                EncryptedState::WaitingAuthRequest(_) => true,
                EncryptedState::WaitingAuthServiceRequest {
                    accepted,
                    ref mut sent,
                } => {
                    debug!("sending ssh-userauth service requset");
                    if !*sent {
                        let p = b"\x05\0\0\0\x0Cssh-userauth";
                        self.common
                            .cipher
                            .local_to_remote
                            .write(p, &mut self.common.write_buffer);
                        *sent = true
                    }
                    accepted
                }
                EncryptedState::InitCompression | EncryptedState::Authenticated => false,
            };
            debug!(
                "write_auth_request_if_needed: is_waiting = {:?}",
                is_waiting
            );
            if is_waiting {
                enc.write_auth_request(user, &meth);
            }
        }
        self.common.auth_user.clear();
        self.common.auth_user.push_str(user);
        self.common.auth_method = Some(meth);
        is_waiting
    }
}

impl Encrypted {
    fn write_auth_request(&mut self, user: &str, auth_method: &auth::Method) -> bool {
        // The server is waiting for our USERAUTH_REQUEST.
        push_packet!(self.write, {
            self.write.push(msg::USERAUTH_REQUEST);

            match *auth_method {
                auth::Method::None => {
                    self.write.extend_ssh_string(user.as_bytes());
                    self.write.extend_ssh_string(b"ssh-connection");
                    self.write.extend_ssh_string(b"none");
                    true
                }
                auth::Method::Password { ref password } => {
                    self.write.extend_ssh_string(user.as_bytes());
                    self.write.extend_ssh_string(b"ssh-connection");
                    self.write.extend_ssh_string(b"password");
                    self.write.push(0);
                    self.write.extend_ssh_string(password.as_bytes());
                    true
                }
                auth::Method::PublicKey { ref key } => {
                    self.write.extend_ssh_string(user.as_bytes());
                    self.write.extend_ssh_string(b"ssh-connection");
                    self.write.extend_ssh_string(b"publickey");
                    self.write.push(0); // This is a probe

                    debug!("write_auth_request: key - {:?}", key.name());
                    self.write.extend_ssh_string(key.name().as_bytes());
                    key.push_to(&mut self.write);
                    true
                }
                auth::Method::OpenSSHCertificate { ref cert, .. } => {
                    self.write.extend_ssh_string(user.as_bytes());
                    self.write.extend_ssh_string(b"ssh-connection");
                    self.write.extend_ssh_string(b"publickey");
                    self.write.push(0); // This is a probe

                    debug!("write_auth_request: cert - {:?}", cert.name());
                    self.write.extend_ssh_string(cert.name().as_bytes());
                    cert.push_to(&mut self.write);
                    true
                }
                auth::Method::FuturePublicKey { ref key, .. } => {
                    self.write.extend_ssh_string(user.as_bytes());
                    self.write.extend_ssh_string(b"ssh-connection");
                    self.write.extend_ssh_string(b"publickey");
                    self.write.push(0); // This is a probe

                    self.write.extend_ssh_string(key.name().as_bytes());
                    key.push_to(&mut self.write);
                    true
                }
                auth::Method::KeyboardInteractive { ref submethods } => {
                    debug!("Keyboard Iinteractive");
                    self.write.extend_ssh_string(user.as_bytes());
                    self.write.extend_ssh_string(b"ssh-connection");
                    self.write.extend_ssh_string(b"keyboard-interactive");
                    self.write.extend_ssh_string(b""); // lang tag is deprecated. Should be empty
                    self.write.extend_ssh_string(submethods.as_bytes());
                    true
                }
            }
        })
    }

    fn client_make_to_sign<Key: Named + PubKey>(
        &mut self,
        user: &str,
        key: &Key,
        buffer: &mut CryptoVec,
    ) -> usize {
        buffer.clear();
        buffer.extend_ssh_string(self.session_id.as_ref());

        let i0 = buffer.len();
        buffer.push(msg::USERAUTH_REQUEST);
        buffer.extend_ssh_string(user.as_bytes());
        buffer.extend_ssh_string(b"ssh-connection");
        buffer.extend_ssh_string(b"publickey");
        buffer.push(1);
        buffer.extend_ssh_string(key.name().as_bytes()); // TODO
        key.push_to(buffer);
        i0
    }

    fn client_send_signature(
        &mut self,
        user: &str,
        method: &auth::Method,
        buffer: &mut CryptoVec,
    ) -> Result<(), crate::Error> {
        match method {
            auth::Method::PublicKey { ref key, ..  } => {
                let i0 = self.client_make_to_sign(user, key.as_ref(), buffer);
                // Extend with self-signature.
                key.add_self_signature(buffer)?;
                push_packet!(self.write, {
                    #[allow(clippy::indexing_slicing)] // length checked
                    self.write.extend(&buffer[i0..]);
                })
            }
            auth::Method::OpenSSHCertificate { ref key, ref cert  } => {
                let i0 = self.client_make_to_sign(user, cert, buffer);
                // Extend with self-signature.
                key.add_self_signature(buffer)?;
                push_packet!(self.write, {
                    #[allow(clippy::indexing_slicing)] // length checked
                    self.write.extend(&buffer[i0..]);
                })
            }
            _ => {}
        }
        Ok(())
    }

    fn client_send_auth_response(&mut self, responses: &[String]) -> Result<(), crate::Error> {
        push_packet!(self.write, {
            self.write.push(msg::USERAUTH_INFO_RESPONSE);
            self.write
                .push_u32_be(responses.len().try_into().unwrap_or(0)); // number of responses

            for r in responses {
                self.write.extend_ssh_string(r.as_bytes()); // write the reponses
            }
        });
        Ok(())
    }
}
