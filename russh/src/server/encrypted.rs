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

use auth::*;
use byteorder::{BigEndian, ByteOrder};
use log::{debug, error, info, trace, warn};
use negotiation::Select;
use russh_keys::encoding::{Encoding, Position, Reader};
use russh_keys::key;
use russh_keys::key::Verify;
use tokio::sync::mpsc::unbounded_channel;
use tokio::time::Instant;
use {msg, negotiation};

use super::super::*;
use super::*;
use crate::msg::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED;
use crate::parsing::{ChannelOpenConfirmation, ChannelType, OpenChannelMessage};

impl Session {
    /// Returns false iff a request was rejected.
    pub(crate) async fn server_read_encrypted<H: Handler + Send>(
        mut self,
        mut handler: H,
        buf: &[u8],
    ) -> Result<(H, Self), H::Error> {
        #[allow(clippy::indexing_slicing)] // length checked
        {
            trace!(
                "server_read_encrypted, buf = {:?}",
                &buf[..buf.len().min(20)]
            );
        }
        // Either this packet is a KEXINIT, in which case we start a key re-exchange.

        #[allow(clippy::unwrap_used)]
        let mut enc = self.common.encrypted.as_mut().unwrap();
        if buf.first() == Some(&msg::KEXINIT) {
            debug!("Received rekeying request");
            // If we're not currently rekeying, but `buf` is a rekey request
            if let Some(Kex::Init(kexinit)) = enc.rekey.take() {
                enc.rekey = Some(kexinit.server_parse(
                    self.common.config.as_ref(),
                    &mut *self.common.cipher.local_to_remote,
                    buf,
                    &mut self.common.write_buffer,
                )?);
            } else if let Some(exchange) = enc.exchange.take() {
                let kexinit = KexInit::received_rekey(
                    exchange,
                    negotiation::Server::read_kex(buf, &self.common.config.as_ref().preferred)?,
                    &enc.session_id,
                );
                enc.rekey = Some(kexinit.server_parse(
                    self.common.config.as_ref(),
                    &mut *self.common.cipher.local_to_remote,
                    buf,
                    &mut self.common.write_buffer,
                )?);
            }
            self.flush()?;
            return Ok((handler, self));
        }

        match enc.rekey.take() {
            Some(Kex::Dh(kexdh)) => {
                enc.rekey = Some(kexdh.parse(
                    self.common.config.as_ref(),
                    &mut *self.common.cipher.local_to_remote,
                    buf,
                    &mut self.common.write_buffer,
                )?);
                self.flush()?;
                return Ok((handler, self));
            }
            Some(Kex::Keys(newkeys)) => {
                if buf.first() != Some(&msg::NEWKEYS) {
                    return Err(Error::Kex.into());
                }
                self.common.write_buffer.bytes = 0;
                enc.last_rekey = std::time::Instant::now();

                // Ok, NEWKEYS received, now encrypted.
                enc.flush_all_pending();
                let mut pending = std::mem::take(&mut self.pending_reads);
                for p in pending.drain(..) {
                    let (h, s) = self.process_packet(handler, &p).await?;
                    handler = h;
                    self = s;
                }
                self.pending_reads = pending;
                self.pending_len = 0;
                self.common.newkeys(newkeys);
                self.flush()?;
                return Ok((handler, self));
            }
            Some(Kex::Init(k)) => {
                enc.rekey = Some(Kex::Init(k));
                self.pending_len += buf.len() as u32;
                if self.pending_len > 2 * self.target_window_size {
                    return Err(Error::Pending.into());
                }
                self.pending_reads.push(CryptoVec::from_slice(buf));
                return Ok((handler, self));
            }
            rek => {
                trace!("rek = {:?}", rek);
                enc.rekey = rek
            }
        }
        self.process_packet(handler, buf).await
    }

    async fn process_packet<H: Handler + Send>(
        mut self,
        mut handler: H,
        buf: &[u8],
    ) -> Result<(H, Self), H::Error> {
        let rejection_wait_until =
            tokio::time::Instant::now() + self.common.config.auth_rejection_time;
        let initial_none_rejection_wait_until = if self.common.auth_attempts == 0 {
            tokio::time::Instant::now()
                + self
                    .common
                    .config
                    .auth_rejection_time_initial
                    .unwrap_or(self.common.config.auth_rejection_time)
        } else {
            rejection_wait_until
        };

        #[allow(clippy::unwrap_used)]
        let mut enc = self.common.encrypted.as_mut().unwrap();
        // If we've successfully read a packet.
        match enc.state {
            EncryptedState::WaitingAuthServiceRequest {
                ref mut accepted, ..
            } if buf.first() == Some(&msg::SERVICE_REQUEST) => {
                let mut r = buf.reader(1);
                let request = r.read_string().map_err(crate::Error::from)?;
                debug!("request: {:?}", std::str::from_utf8(request));
                if request == b"ssh-userauth" {
                    let auth_request = server_accept_service(
                        self.common.config.as_ref().auth_banner,
                        self.common.config.as_ref().methods,
                        &mut enc.write,
                    );
                    *accepted = true;
                    enc.state = EncryptedState::WaitingAuthRequest(auth_request);
                }
                Ok((handler, self))
            }
            EncryptedState::WaitingAuthRequest(_)
                if buf.first() == Some(&msg::USERAUTH_REQUEST) =>
            {
                handler = enc
                    .server_read_auth_request(
                        rejection_wait_until,
                        initial_none_rejection_wait_until,
                        handler,
                        buf,
                        &mut self.common.auth_user,
                    )
                    .await?;
                self.common.auth_attempts += 1;
                if let EncryptedState::InitCompression = enc.state {
                    enc.client_compression.init_decompress(&mut enc.decompress);
                    handler.auth_succeeded(self).await
                } else {
                    Ok((handler, self))
                }
            }
            EncryptedState::WaitingAuthRequest(ref mut auth)
                if buf.first() == Some(&msg::USERAUTH_INFO_RESPONSE) =>
            {
                let (h, resp) = read_userauth_info_response(
                    rejection_wait_until,
                    handler,
                    &mut enc.write,
                    auth,
                    &mut self.common.auth_user,
                    buf,
                )
                .await?;
                handler = h;
                if resp {
                    enc.state = EncryptedState::InitCompression;
                    enc.client_compression.init_decompress(&mut enc.decompress);
                    handler.auth_succeeded(self).await
                } else {
                    Ok((handler, self))
                }
            }
            EncryptedState::InitCompression => {
                enc.server_compression.init_compress(&mut enc.compress);
                enc.state = EncryptedState::Authenticated;
                self.server_read_authenticated(handler, buf).await
            }
            EncryptedState::Authenticated => self.server_read_authenticated(handler, buf).await,
            _ => Ok((handler, self)),
        }
    }
}

fn server_accept_service(
    banner: Option<&str>,
    methods: MethodSet,
    buffer: &mut CryptoVec,
) -> AuthRequest {
    push_packet!(buffer, {
        buffer.push(msg::SERVICE_ACCEPT);
        buffer.extend_ssh_string(b"ssh-userauth");
    });

    if let Some(banner) = banner {
        push_packet!(buffer, {
            buffer.push(msg::USERAUTH_BANNER);
            buffer.extend_ssh_string(banner.as_bytes());
            buffer.extend_ssh_string(b"");
        })
    }

    AuthRequest {
        methods,
        partial_success: false, // not used immediately anway.
        current: None,
        rejection_count: 0,
    }
}

impl Encrypted {
    /// Returns false iff the request was rejected.
    async fn server_read_auth_request<H: Handler + Send>(
        &mut self,
        mut until: Instant,
        initial_auth_until: Instant,
        mut handler: H,
        buf: &[u8],
        auth_user: &mut String,
    ) -> Result<H, H::Error> {
        // https://tools.ietf.org/html/rfc4252#section-5
        let mut r = buf.reader(1);
        let user = r.read_string().map_err(crate::Error::from)?;
        let user = std::str::from_utf8(user).map_err(crate::Error::from)?;
        let service_name = r.read_string().map_err(crate::Error::from)?;
        let method = r.read_string().map_err(crate::Error::from)?;
        debug!(
            "name: {:?} {:?} {:?}",
            user,
            std::str::from_utf8(service_name),
            std::str::from_utf8(method)
        );

        if service_name == b"ssh-connection" {
            if method == b"password" {
                let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state
                {
                    a
                } else {
                    unreachable!()
                };
                auth_user.clear();
                auth_user.push_str(user);
                r.read_byte().map_err(crate::Error::from)?;
                let password = r.read_string().map_err(crate::Error::from)?;
                let password = std::str::from_utf8(password).map_err(crate::Error::from)?;
                let (handler, auth) = handler.auth_password(user, password).await?;
                if let Auth::Accept = auth {
                    server_auth_request_success(&mut self.write);
                    self.state = EncryptedState::InitCompression;
                } else {
                    auth_user.clear();
                    auth_request.methods -= MethodSet::PASSWORD;
                    auth_request.partial_success = false;
                    reject_auth_request(until, &mut self.write, auth_request).await;
                }
                Ok(handler)
            } else if method == b"publickey" {
                self.server_read_auth_request_pk(until, handler, buf, auth_user, user, r)
                    .await
            } else if method == b"none" {
                let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state
                {
                    a
                } else {
                    unreachable!()
                };

                if method == b"none" {
                    until = initial_auth_until
                }

                let (handler, auth) = handler.auth_none(user).await?;
                if let Auth::Accept = auth {
                    server_auth_request_success(&mut self.write);
                    self.state = EncryptedState::InitCompression;
                } else {
                    auth_user.clear();
                    auth_request.methods -= MethodSet::NONE;
                    auth_request.partial_success = false;
                    reject_auth_request(until, &mut self.write, auth_request).await;
                }
                Ok(handler)
            } else if method == b"keyboard-interactive" {
                let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state
                {
                    a
                } else {
                    unreachable!()
                };
                auth_user.clear();
                auth_user.push_str(user);
                let _ = r.read_string().map_err(crate::Error::from)?; // language_tag, deprecated.
                let submethods = std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                    .map_err(crate::Error::from)?;
                debug!("{:?}", submethods);
                auth_request.current = Some(CurrentRequest::KeyboardInteractive {
                    submethods: submethods.to_string(),
                });
                let (h, auth) = handler
                    .auth_keyboard_interactive(user, submethods, None)
                    .await?;
                handler = h;
                if reply_userauth_info_response(until, auth_request, &mut self.write, auth).await? {
                    self.state = EncryptedState::InitCompression
                }
                Ok(handler)
            } else {
                // Other methods of the base specification are insecure or optional.
                let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state
                {
                    a
                } else {
                    unreachable!()
                };
                reject_auth_request(until, &mut self.write, auth_request).await;
                Ok(handler)
            }
        } else {
            // Unknown service
            Err(Error::Inconsistent.into())
        }
    }
}

thread_local! {
    static SIGNATURE_BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

impl Encrypted {
    async fn server_read_auth_request_pk<H: Handler + Send>(
        &mut self,
        until: Instant,
        mut handler: H,
        buf: &[u8],
        auth_user: &mut String,
        user: &str,
        mut r: Position<'_>,
    ) -> Result<H, H::Error> {
        let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state {
            a
        } else {
            unreachable!()
        };
        let is_real = r.read_byte().map_err(crate::Error::from)?;
        let pubkey_algo = r.read_string().map_err(crate::Error::from)?;
        let pubkey_key = r.read_string().map_err(crate::Error::from)?;
        debug!("algo: {:?}, key: {:?}", pubkey_algo, pubkey_key);
        match key::PublicKey::parse(pubkey_algo, pubkey_key) {
            Ok(mut pubkey) => {
                debug!("is_real = {:?}", is_real);

                if is_real != 0 {
                    let pos0 = r.position;
                    let sent_pk_ok = if let Some(CurrentRequest::PublicKey { sent_pk_ok, .. }) =
                        auth_request.current
                    {
                        sent_pk_ok
                    } else {
                        false
                    };

                    let signature = r.read_string().map_err(crate::Error::from)?;
                    debug!("signature = {:?}", signature);
                    let mut s = signature.reader(0);
                    let algo_ = s.read_string().map_err(crate::Error::from)?;
                    pubkey.set_algorithm(algo_);
                    debug!("algo_: {:?}", algo_);
                    let sig = s.read_string().map_err(crate::Error::from)?;
                    #[allow(clippy::indexing_slicing)] // length checked
                    let init = &buf[0..pos0];

                    let is_valid = if sent_pk_ok && user == auth_user {
                        true
                    } else if auth_user.is_empty() {
                        auth_user.clear();
                        auth_user.push_str(user);
                        let (h, auth) = handler.auth_publickey(user, &pubkey).await?;
                        handler = h;
                        auth == Auth::Accept
                    } else {
                        false
                    };
                    if is_valid {
                        let session_id = self.session_id.as_ref();
                        #[allow(clippy::blocks_in_if_conditions)] // length checked
                        if SIGNATURE_BUFFER.with(|buf| {
                            let mut buf = buf.borrow_mut();
                            buf.clear();
                            buf.extend_ssh_string(session_id);
                            buf.extend(init);
                            // Verify signature.
                            pubkey.verify_client_auth(&buf, sig)
                        }) {
                            debug!("signature verified");
                            server_auth_request_success(&mut self.write);
                            self.state = EncryptedState::InitCompression;
                        } else {
                            debug!("signature wrong");
                            reject_auth_request(until, &mut self.write, auth_request).await;
                        }
                    } else {
                        reject_auth_request(until, &mut self.write, auth_request).await;
                    }
                    Ok(handler)
                } else {
                    auth_user.clear();
                    auth_user.push_str(user);
                    let (h, auth) = handler.auth_publickey(user, &pubkey).await?;
                    handler = h;
                    match auth {
                        Auth::Accept => {
                            let mut public_key = CryptoVec::new();
                            public_key.extend(pubkey_key);

                            let mut algo = CryptoVec::new();
                            algo.extend(pubkey_algo);
                            debug!("pubkey_key: {:?}", pubkey_key);
                            push_packet!(self.write, {
                                self.write.push(msg::USERAUTH_PK_OK);
                                self.write.extend_ssh_string(pubkey_algo);
                                self.write.extend_ssh_string(pubkey_key);
                            });

                            auth_request.current = Some(CurrentRequest::PublicKey {
                                key: public_key,
                                algo,
                                sent_pk_ok: true,
                            });
                        }
                        auth => {
                            if let Auth::Reject {
                                proceed_with_methods: Some(proceed_with_methods),
                            } = auth
                            {
                                auth_request.methods = proceed_with_methods;
                            }
                            auth_request.partial_success = false;
                            auth_user.clear();
                            reject_auth_request(until, &mut self.write, auth_request).await;
                        }
                    }
                    Ok(handler)
                }
            }
            Err(e) => {
                if let russh_keys::Error::CouldNotReadKey = e {
                    reject_auth_request(until, &mut self.write, auth_request).await;
                    Ok(handler)
                } else {
                    Err(crate::Error::from(e).into())
                }
            }
        }
    }
}

async fn reject_auth_request(
    until: Instant,
    write: &mut CryptoVec,
    auth_request: &mut AuthRequest,
) {
    debug!("rejecting {:?}", auth_request);
    push_packet!(write, {
        write.push(msg::USERAUTH_FAILURE);
        write.extend_list(auth_request.methods);
        write.push(auth_request.partial_success as u8);
    });
    auth_request.current = None;
    auth_request.rejection_count += 1;
    debug!("packet pushed");
    tokio::time::sleep_until(until).await
}

fn server_auth_request_success(buffer: &mut CryptoVec) {
    push_packet!(buffer, {
        buffer.push(msg::USERAUTH_SUCCESS);
    })
}

async fn read_userauth_info_response<H: Handler + Send>(
    until: Instant,
    mut handler: H,
    write: &mut CryptoVec,
    auth_request: &mut AuthRequest,
    user: &mut str,
    b: &[u8],
) -> Result<(H, bool), H::Error> {
    if let Some(CurrentRequest::KeyboardInteractive { ref submethods }) = auth_request.current {
        let mut r = b.reader(1);
        let n = r.read_u32().map_err(crate::Error::from)?;
        let response = Response { pos: r, n };
        let (h, auth) = handler
            .auth_keyboard_interactive(user, submethods, Some(response))
            .await?;
        handler = h;
        let resp = reply_userauth_info_response(until, auth_request, write, auth)
            .await
            .map_err(H::Error::from)?;
        Ok((handler, resp))
    } else {
        reject_auth_request(until, write, auth_request).await;
        Ok((handler, false))
    }
}

async fn reply_userauth_info_response(
    until: Instant,
    auth_request: &mut AuthRequest,
    write: &mut CryptoVec,
    auth: Auth,
) -> Result<bool, Error> {
    match auth {
        Auth::Accept => {
            server_auth_request_success(write);
            Ok(true)
        }
        Auth::Reject {
            proceed_with_methods,
        } => {
            if let Some(proceed_with_methods) = proceed_with_methods {
                auth_request.methods = proceed_with_methods;
            }
            auth_request.partial_success = false;
            reject_auth_request(until, write, auth_request).await;
            Ok(false)
        }
        Auth::Partial {
            name,
            instructions,
            prompts,
        } => {
            push_packet!(write, {
                write.push(msg::USERAUTH_INFO_REQUEST);
                write.extend_ssh_string(name.as_bytes());
                write.extend_ssh_string(instructions.as_bytes());
                write.extend_ssh_string(b""); // lang, should be empty
                write.push_u32_be(prompts.len() as u32);
                for &(ref a, b) in prompts.iter() {
                    write.extend_ssh_string(a.as_bytes());
                    write.push(b as u8);
                }
            });
            Ok(false)
        }
        Auth::UnsupportedMethod => unreachable!(),
    }
}

impl Session {
    async fn server_read_authenticated<H: Handler + Send>(
        mut self,
        mut handler: H,
        buf: &[u8],
    ) -> Result<(H, Self), H::Error> {
        #[allow(clippy::indexing_slicing)] // length checked
        {
            trace!(
                "authenticated buf = {:?}",
                &buf[..std::cmp::min(buf.len(), 100)]
            );
        }
        match buf.first() {
            Some(&msg::CHANNEL_OPEN) => self
                .server_handle_channel_open(handler, buf)
                .await
                .map(|(h, _, s)| (h, s)),
            Some(&msg::CHANNEL_CLOSE) => {
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                if let Some(ref mut enc) = self.common.encrypted {
                    enc.channels.remove(&channel_num);
                }
                self.channels.remove(&channel_num);
                debug!("handler.channel_close {:?}", channel_num);
                handler.channel_close(channel_num, self).await
            }
            Some(&msg::CHANNEL_EOF) => {
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                debug!("handler.channel_eof {:?}", channel_num);
                handler.channel_eof(channel_num, self).await
            }
            Some(&msg::CHANNEL_EXTENDED_DATA) | Some(&msg::CHANNEL_DATA) => {
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);

                let ext = if buf.first() == Some(&msg::CHANNEL_DATA) {
                    None
                } else {
                    Some(r.read_u32().map_err(crate::Error::from)?)
                };
                trace!("handler.data {:?} {:?}", ext, channel_num);
                let data = r.read_string().map_err(crate::Error::from)?;
                let target = self.target_window_size;

                if let Some(ref mut enc) = self.common.encrypted {
                    if enc.adjust_window_size(channel_num, data, target) {
                        let window = handler.adjust_window(channel_num, self.target_window_size);
                        if window > 0 {
                            self.target_window_size = window
                        }
                    }
                }
                self.flush()?;
                if let Some(ext) = ext {
                    handler.extended_data(channel_num, ext, data, self).await
                } else {
                    handler.data(channel_num, data, self).await
                }
            }

            Some(&msg::CHANNEL_WINDOW_ADJUST) => {
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                let amount = r.read_u32().map_err(crate::Error::from)?;
                let mut new_value = 0;
                if let Some(ref mut enc) = self.common.encrypted {
                    if let Some(channel) = enc.channels.get_mut(&channel_num) {
                        channel.recipient_window_size += amount;
                        new_value = channel.recipient_window_size;
                    } else {
                        return Err(Error::WrongChannel.into());
                    }
                }
                debug!("handler.window_adjusted {:?}", channel_num);
                handler.window_adjusted(channel_num, new_value, self).await
            }

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
                        return Err(Error::Inconsistent.into());
                    }
                } else {
                    return Err(Error::Inconsistent.into());
                };

                handler
                    .channel_open_confirmation(
                        local_id,
                        msg.maximum_packet_size,
                        msg.initial_window_size,
                        self,
                    )
                    .await
            }

            Some(&msg::CHANNEL_REQUEST) => {
                let mut r = buf.reader(1);
                let channel_num = ChannelId(r.read_u32().map_err(crate::Error::from)?);
                let req_type = r.read_string().map_err(crate::Error::from)?;
                let wants_reply = r.read_byte().map_err(crate::Error::from)?;
                if let Some(ref mut enc) = self.common.encrypted {
                    if let Some(channel) = enc.channels.get_mut(&channel_num) {
                        channel.wants_reply = wants_reply != 0;
                    }
                }
                match req_type {
                    b"pty-req" => {
                        let term =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        let col_width = r.read_u32().map_err(crate::Error::from)?;
                        let row_height = r.read_u32().map_err(crate::Error::from)?;
                        let pix_width = r.read_u32().map_err(crate::Error::from)?;
                        let pix_height = r.read_u32().map_err(crate::Error::from)?;
                        let mut modes = [(Pty::TTY_OP_END, 0); 130];
                        let mut i = 0;
                        {
                            let mode_string = r.read_string().map_err(crate::Error::from)?;
                            while 5 * i < mode_string.len() {
                                #[allow(clippy::indexing_slicing)] // length checked
                                let code = mode_string[5 * i];
                                if code == 0 {
                                    break;
                                }
                                #[allow(clippy::indexing_slicing)] // length checked
                                let num = BigEndian::read_u32(&mode_string[5 * i + 1..]);
                                debug!("code = {:?}", code);
                                if let Some(code) = Pty::from_u8(code) {
                                    #[allow(clippy::indexing_slicing)] // length checked
                                    if i < 130 {
                                        modes[i] = (code, num);
                                    } else {
                                        error!("pty-req: too many pty codes");
                                    }
                                } else {
                                    info!("pty-req: unknown pty code {:?}", code);
                                }
                                i += 1
                            }
                        }
                        debug!("handler.pty_request {:?}", channel_num);
                        #[allow(clippy::indexing_slicing)] // `modes` length checked
                        handler
                            .pty_request(
                                channel_num,
                                term,
                                col_width,
                                row_height,
                                pix_width,
                                pix_height,
                                &modes[0..i],
                                self,
                            )
                            .await
                    }
                    b"x11-req" => {
                        let single_connection = r.read_byte().map_err(crate::Error::from)? != 0;
                        let x11_auth_protocol =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        let x11_auth_cookie =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        let x11_screen_number = r.read_u32().map_err(crate::Error::from)?;
                        debug!("handler.x11_request {:?}", channel_num);
                        handler
                            .x11_request(
                                channel_num,
                                single_connection,
                                x11_auth_protocol,
                                x11_auth_cookie,
                                x11_screen_number,
                                self,
                            )
                            .await
                    }
                    b"env" => {
                        let env_variable =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        let env_value =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        debug!("handler.env_request {:?}", channel_num);
                        handler
                            .env_request(channel_num, env_variable, env_value, self)
                            .await
                    }
                    b"shell" => {
                        debug!("handler.shell_request {:?}", channel_num);
                        handler.shell_request(channel_num, self).await
                    }
                    b"auth-agent-req@openssh.com" => {
                        debug!("handler.agent_request {:?}", channel_num);
                        let response;
                        (handler, response, self) =
                            handler.agent_request(channel_num, self).await?;
                        if response {
                            self.request_success()
                        } else {
                            self.request_failure()
                        }
                        Ok((handler, self))
                    }
                    b"exec" => {
                        let req = r.read_string().map_err(crate::Error::from)?;
                        debug!("handler.exec_request {:?}", channel_num);
                        handler.exec_request(channel_num, req, self).await
                    }
                    b"subsystem" => {
                        let name =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        debug!("handler.subsystem_request {:?}", channel_num);
                        handler.subsystem_request(channel_num, name, self).await
                    }
                    b"window-change" => {
                        let col_width = r.read_u32().map_err(crate::Error::from)?;
                        let row_height = r.read_u32().map_err(crate::Error::from)?;
                        let pix_width = r.read_u32().map_err(crate::Error::from)?;
                        let pix_height = r.read_u32().map_err(crate::Error::from)?;
                        debug!("handler.window_change {:?}", channel_num);
                        handler
                            .window_change_request(
                                channel_num,
                                col_width,
                                row_height,
                                pix_width,
                                pix_height,
                                self,
                            )
                            .await
                    }
                    b"signal" => {
                        let signal_name =
                            Sig::from_name(r.read_string().map_err(crate::Error::from)?)?;
                        debug!("handler.signal {:?} {:?}", channel_num, signal_name);
                        handler.signal(channel_num, signal_name, self).await
                    }
                    x => {
                        warn!("unknown channel request {}", String::from_utf8_lossy(x));
                        self.channel_failure(channel_num);
                        Ok((handler, self))
                    }
                }
            }
            Some(&msg::GLOBAL_REQUEST) => {
                let mut r = buf.reader(1);
                let req_type = r.read_string().map_err(crate::Error::from)?;
                self.common.wants_reply = r.read_byte().map_err(crate::Error::from)? != 0;
                match req_type {
                    b"tcpip-forward" => {
                        let address =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        let port = r.read_u32().map_err(crate::Error::from)?;
                        debug!("handler.tcpip_forward {:?} {:?}", address, port);
                        let mut returned_port = port;
                        let (h, result, mut s) = handler
                            .tcpip_forward(address, &mut returned_port, self)
                            .await?;
                        if let Some(ref mut enc) = s.common.encrypted {
                            if result {
                                push_packet!(enc.write, {
                                    enc.write.push(msg::REQUEST_SUCCESS);
                                    if s.common.wants_reply && port == 0 && returned_port != 0 {
                                        enc.write.push_u32_be(returned_port);
                                    }
                                })
                            } else {
                                push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
                            }
                        }
                        Ok((h, s))
                    }
                    b"cancel-tcpip-forward" => {
                        let address =
                            std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                                .map_err(crate::Error::from)?;
                        let port = r.read_u32().map_err(crate::Error::from)?;
                        debug!("handler.cancel_tcpip_forward {:?} {:?}", address, port);
                        let (h, result, mut s) =
                            handler.cancel_tcpip_forward(address, port, self).await?;
                        if let Some(ref mut enc) = s.common.encrypted {
                            if result {
                                push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS))
                            } else {
                                push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
                            }
                        }
                        Ok((h, s))
                    }
                    _ => {
                        if let Some(ref mut enc) = self.common.encrypted {
                            push_packet!(enc.write, {
                                enc.write.push(msg::REQUEST_FAILURE);
                            });
                        }
                        Ok((handler, self))
                    }
                }
            }
            Some(&msg::CHANNEL_OPEN_FAILURE) => {
                debug!("channel_open_failure");
                let mut buf_pos = buf.reader(1);
                let channel_num = ChannelId(buf_pos.read_u32().map_err(crate::Error::from)?);
                let reason =
                    ChannelOpenFailure::from_u32(buf_pos.read_u32().map_err(crate::Error::from)?)
                        .unwrap_or(ChannelOpenFailure::Unknown);
                let description =
                    std::str::from_utf8(buf_pos.read_string().map_err(crate::Error::from)?)
                        .map_err(crate::Error::from)?;
                let language_tag =
                    std::str::from_utf8(buf_pos.read_string().map_err(crate::Error::from)?)
                        .map_err(crate::Error::from)?;

                trace!("Channel open failure description: {description}");
                trace!("Channel open failure language tag: {language_tag}");

                if let Some(ref mut enc) = self.common.encrypted {
                    enc.channels.remove(&channel_num);
                }

                if let Some(channel_sender) = self.channels.remove(&channel_num) {
                    channel_sender
                        .send(ChannelMsg::OpenFailure(reason))
                        .map_err(|_| crate::Error::SendError)?;
                }

                Ok((handler, self))
            }
            m => {
                debug!("unknown message received: {:?}", m);
                Ok((handler, self))
            }
        }
    }

    async fn server_handle_channel_open<H: Handler + Send>(
        mut self,
        handler: H,
        buf: &[u8],
    ) -> Result<(H, bool, Self), H::Error> {
        let mut r = buf.reader(1);
        let msg = OpenChannelMessage::parse(&mut r)?;

        let sender_channel = if let Some(ref mut enc) = self.common.encrypted {
            enc.new_channel_id()
        } else {
            unreachable!()
        };
        let channel_params = ChannelParams {
            recipient_channel: msg.recipient_channel,

            // "sender" is the local end, i.e. we're the sender, the remote is the recipient.
            sender_channel,

            recipient_window_size: msg.recipient_window_size,
            sender_window_size: self.common.config.window_size,
            recipient_maximum_packet_size: msg.recipient_maximum_packet_size,
            sender_maximum_packet_size: self.common.config.maximum_packet_size,
            confirmed: true,
            wants_reply: false,
            pending_data: std::collections::VecDeque::new(),
        };

        let (sender, receiver) = unbounded_channel();
        let channel = Channel {
            id: sender_channel,
            sender: self.sender.sender.clone(),
            receiver,
            max_packet_size: channel_params.recipient_maximum_packet_size,
            window_size: channel_params.recipient_window_size,
        };

        match &msg.typ {
            ChannelType::Session => {
                let mut result = handler.channel_open_session(channel, self).await;
                if let Ok((_, allowed, s)) = &mut result {
                    s.channels.insert(sender_channel, sender);
                    s.finalize_channel_open(&msg, channel_params, *allowed);
                }
                result
            }
            ChannelType::X11 {
                originator_address,
                originator_port,
            } => {
                let mut result = handler
                    .channel_open_x11(channel, originator_address, *originator_port, self)
                    .await;
                if let Ok((_, allowed, s)) = &mut result {
                    s.channels.insert(sender_channel, sender);
                    s.finalize_channel_open(&msg, channel_params, *allowed);
                }
                result
            }
            ChannelType::DirectTcpip(d) => {
                let mut result = handler
                    .channel_open_direct_tcpip(
                        channel,
                        &d.host_to_connect,
                        d.port_to_connect,
                        &d.originator_address,
                        d.originator_port,
                        self,
                    )
                    .await;
                if let Ok((_, allowed, s)) = &mut result {
                    s.channels.insert(sender_channel, sender);
                    s.finalize_channel_open(&msg, channel_params, *allowed);
                }
                result
            }
            ChannelType::ForwardedTcpIp(d) => {
                let mut result = handler
                    .channel_open_forwarded_tcpip(
                        channel,
                        &d.host_to_connect,
                        d.port_to_connect,
                        &d.originator_address,
                        d.originator_port,
                        self,
                    )
                    .await;
                if let Ok((_, allowed, s)) = &mut result {
                    s.channels.insert(sender_channel, sender);
                    s.finalize_channel_open(&msg, channel_params, *allowed);
                }
                result
            }
            ChannelType::AgentForward => {
                if let Some(ref mut enc) = self.common.encrypted {
                    msg.fail(
                        &mut enc.write,
                        msg::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        b"Unsupported channel type",
                    );
                }
                Ok((handler, false, self))
            }
            ChannelType::Unknown { typ } => {
                debug!("unknown channel type: {}", String::from_utf8_lossy(typ));
                if let Some(ref mut enc) = self.common.encrypted {
                    msg.unknown_type(&mut enc.write);
                }
                Ok((handler, false, self))
            }
        }
    }

    fn finalize_channel_open(
        &mut self,
        open: &OpenChannelMessage,
        channel: ChannelParams,
        allowed: bool,
    ) {
        if let Some(ref mut enc) = self.common.encrypted {
            if allowed {
                open.confirm(
                    &mut enc.write,
                    channel.sender_channel.0,
                    channel.sender_window_size,
                    channel.sender_maximum_packet_size,
                );
                enc.channels.insert(channel.sender_channel, channel);
            } else {
                open.fail(
                    &mut enc.write,
                    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                    b"Rejected",
                );
            }
        }
    }
}
