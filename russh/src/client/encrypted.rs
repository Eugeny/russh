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
use std::ops::Deref;
use std::str::FromStr;

use bytes::Bytes;
use log::{debug, error, info, trace, warn};
use ssh_encoding::{Decode, Encode, Reader};
use ssh_key::Algorithm;

use super::IncomingSshPacket;
use crate::auth::AuthRequest;
use crate::cert::PublicKeyOrCertificate;
use crate::client::{Handler, Msg, Prompt, Reply, Session};
use crate::helpers::{sign_with_hash_alg, AlgorithmExt, EncodedExt, NameList};
use crate::keys::key::parse_public_key;
use crate::parsing::{ChannelOpenConfirmation, ChannelType, OpenChannelMessage};
use crate::session::{Encrypted, EncryptedState, GlobalRequestResponse};
use crate::{
    auth, map_err, msg, Channel, ChannelId, ChannelMsg, ChannelOpenFailure, ChannelParams, CryptoVec, Error,
    MethodSet, Sig,
};

thread_local! {
    static SIGNATURE_BUFFER: RefCell<CryptoVec> = RefCell::new(CryptoVec::new());
}

impl Session {
    pub(crate) async fn client_read_encrypted<H: Handler>(
        &mut self,
        client: &mut H,
        pkt: &mut IncomingSshPacket,
    ) -> Result<(), H::Error> {
        #[allow(clippy::indexing_slicing)] // length checked
        {
            trace!(
                "client_read_encrypted, buf = {:?}",
                &pkt.buffer[..pkt.buffer.len().min(20)]
            );
        }

        self.process_packet(client, &pkt.buffer).await
    }

    pub(crate) async fn process_packet<H: Handler>(
        &mut self,
        client: &mut H,
        buf: &[u8],
    ) -> Result<(), H::Error> {
        // If we've successfully read a packet.
        trace!("process_packet buf = {:?} bytes", buf.len());
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
                    match buf.split_first() {
                        Some((&msg::SERVICE_ACCEPT, mut r)) => {
                            if map_err!(Bytes::decode(&mut r))?.as_ref() == b"ssh-userauth" {
                                *accepted = true;
                                if let Some(ref meth) = self.common.auth_method {
                                    let len = enc.write.len();
                                    let auth_request = AuthRequest::new(meth);
                                    #[allow(clippy::indexing_slicing)] // length checked
                                    if enc.write_auth_request(&self.common.auth_user, meth)? {
                                        debug!("enc: {:?}", &enc.write[len..]);
                                        enc.state = EncryptedState::WaitingAuthRequest(auth_request)
                                    }
                                } else {
                                    debug!("no auth method")
                                }
                            }
                        }
                        Some((&msg::EXT_INFO, mut r)) => {
                            return self.handle_ext_info(&mut r).map_err(Into::into);
                        }
                        other => {
                            debug!("unknown message: {other:?}");
                            return Err(crate::Error::Inconsistent.into());
                        }
                    }
                }
                EncryptedState::WaitingAuthRequest(ref mut auth_request) => {
                    trace!("waiting auth request, {:?}", buf.first(),);
                    match buf.split_first() {
                        Some((&msg::USERAUTH_SUCCESS, _)) => {
                            debug!("userauth_success");
                            self.sender
                                .send(Reply::AuthSuccess)
                                .map_err(|_| crate::Error::SendError)?;
                            enc.state = EncryptedState::InitCompression;
                            enc.server_compression.init_decompress(&mut enc.decompress);
                            return Ok(());
                        }
                        Some((&msg::USERAUTH_BANNER, mut r)) => {
                            let banner = map_err!(String::decode(&mut r))?;
                            client.auth_banner(&banner, self).await?;
                            return Ok(());
                        }
                        Some((&msg::USERAUTH_FAILURE, mut r)) => {
                            debug!("userauth_failure");

                            let remaining_methods: MethodSet =
                                (&map_err!(NameList::decode(&mut r))?).into();
                            let partial_success = map_err!(u8::decode(&mut r))? != 0;
                            debug!("remaining methods {remaining_methods:?}, partial success {partial_success:?}");
                            auth_request.methods = remaining_methods.clone();

                            let no_more_methods = auth_request.methods.is_empty();
                            self.common.auth_method = None;
                            self.sender
                                .send(Reply::AuthFailure {
                                    proceed_with_methods: remaining_methods,
                                    partial_success,
                                })
                                .map_err(|_| crate::Error::SendError)?;

                            // If no other authentication method is allowed by the server, give up.
                            if no_more_methods {
                                return Err(crate::Error::NoAuthMethod.into());
                            }
                        }
                        Some((&msg::USERAUTH_INFO_REQUEST_OR_USERAUTH_PK_OK, mut r)) => {
                            if let Some(auth::CurrentRequest::PublicKey {
                                ref mut sent_pk_ok,
                                ..
                            }) = auth_request.current
                            {
                                debug!("userauth_pk_ok");
                                *sent_pk_ok = true;
                            } else if let Some(auth::CurrentRequest::KeyboardInteractive {
                                ..
                            }) = auth_request.current
                            {
                                debug!("keyboard_interactive");

                                // read fields
                                let name = map_err!(String::decode(&mut r))?;

                                let instructions = map_err!(String::decode(&mut r))?;

                                let _lang = map_err!(String::decode(&mut r))?;
                                let n_prompts = map_err!(u32::decode(&mut r))?;

                                // read prompts
                                let mut prompts =
                                    Vec::with_capacity(n_prompts.try_into().unwrap_or(0));
                                for _i in 0..n_prompts {
                                    let prompt = map_err!(String::decode(&mut r))?;

                                    let echo = map_err!(u8::decode(&mut r))? != 0;
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
                                        Some(Msg::AuthInfoResponse { responses }) => {
                                            break responses
                                        }
                                        None => return Err(crate::Error::RecvError.into()),
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
                                Some(auth_method @ auth::Method::OpenSshCertificate { .. }) => {
                                    self.common.buffer.clear();
                                    enc.client_send_signature(
                                        &self.common.auth_user,
                                        &auth_method,
                                        &mut self.common.buffer,
                                    )?
                                }
                                Some(auth::Method::FuturePublicKey { key, hash_alg }) => {
                                    debug!("public key");
                                    self.common.buffer.clear();
                                    let i = enc.client_make_to_sign(
                                        &self.common.auth_user,
                                        &PublicKeyOrCertificate::PublicKey {
                                            key: key.clone(),
                                            hash_alg,
                                        },
                                        &mut self.common.buffer,
                                    )?;
                                    let len = self.common.buffer.len();
                                    let buf = std::mem::replace(
                                        &mut self.common.buffer,
                                        CryptoVec::new(),
                                    );

                                    self.sender
                                        .send(Reply::SignRequest { key, data: buf })
                                        .map_err(|_| crate::Error::SendError)?;
                                    self.common.buffer = loop {
                                        match self.receiver.recv().await {
                                            Some(Msg::Signed { data }) => break data,
                                            None => return Err(crate::Error::RecvError.into()),
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
                        }
                        Some((&msg::EXT_INFO, mut r)) => {
                            return self.handle_ext_info(&mut r).map_err(Into::into);
                        }
                        other => {
                            debug!("unknown message: {other:?}");
                            return Err(crate::Error::Inconsistent.into());
                        }
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

    fn handle_ext_info(&mut self, r: &mut impl Reader) -> Result<(), Error> {
        let n_extensions = u32::decode(r)? as usize;
        debug!("Received EXT_INFO, {n_extensions:?} extensions");
        for _ in 0..n_extensions {
            let name = String::decode(r)?;
            if name == "server-sig-algs" {
                self.handle_server_sig_algs_ext(r)?;
            } else {
                let data = Vec::<u8>::decode(r)?;
                debug!("* {name:?} (unknown, data: {data:?})");
            }
            if let Some(ref mut enc) = self.common.encrypted {
                enc.received_extensions.push(name.clone());
                if let Some(mut senders) = enc.extension_info_awaiters.remove(&name) {
                    senders.drain(..).for_each(|w| {
                        let _ = w.send(());
                    });
                }
            }
        }
        Ok(())
    }

    fn handle_server_sig_algs_ext(&mut self, r: &mut impl Reader) -> Result<(), Error> {
        let algs = NameList::decode(r)?;
        debug!("* server-sig-algs");
        self.server_sig_algs = Some(
            algs.0
                .iter()
                .filter_map(|x| Algorithm::from_str(x).ok())
                .inspect(|x| {
                    debug!("  * {x:?}");
                })
                .collect::<Vec<_>>(),
        );
        Ok(())
    }

    async fn client_read_authenticated<H: Handler>(
        &mut self,
        client: &mut H,
        buf: &[u8],
    ) -> Result<(), H::Error> {
        match buf.split_first() {
            Some((&msg::CHANNEL_OPEN_CONFIRMATION, mut reader)) => {
                debug!("channel_open_confirmation");
                let msg = map_err!(ChannelOpenConfirmation::decode(&mut reader))?;
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
                        .await
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
            Some((&msg::CHANNEL_CLOSE, mut r)) => {
                debug!("channel_close");
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                if let Some(ref mut enc) = self.common.encrypted {
                    // The CHANNEL_CLOSE message must be sent to the server at this point or the session
                    // will not be released.
                    enc.close(channel_num)?;
                }
                self.channels.remove(&channel_num);
                client.channel_close(channel_num, self).await
            }
            Some((&msg::CHANNEL_EOF, mut r)) => {
                debug!("channel_eof");
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan.send(ChannelMsg::Eof).await;
                }
                client.channel_eof(channel_num, self).await
            }
            Some((&msg::CHANNEL_OPEN_FAILURE, mut r)) => {
                debug!("channel_open_failure");
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                let reason_code = ChannelOpenFailure::from_u32(map_err!(u32::decode(&mut r))?)
                    .unwrap_or(ChannelOpenFailure::Unknown);
                let descr = map_err!(String::decode(&mut r))?;
                let language = map_err!(String::decode(&mut r))?;
                if let Some(ref mut enc) = self.common.encrypted {
                    enc.channels.remove(&channel_num);
                }

                if let Some(sender) = self.channels.remove(&channel_num) {
                    let _ = sender.send(ChannelMsg::OpenFailure(reason_code)).await;
                }

                let _ = self.sender.send(Reply::ChannelOpenFailure);

                client
                    .channel_open_failure(channel_num, reason_code, &descr, &language, self)
                    .await
            }
            Some((&msg::CHANNEL_DATA, mut r)) => {
                trace!("channel_data");
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                let data = map_err!(Bytes::decode(&mut r))?;
                let target = self.common.config.window_size;
                if let Some(ref mut enc) = self.common.encrypted {
                    if enc.adjust_window_size(channel_num, &data, target)? {
                        let next_window =
                            client.adjust_window(channel_num, self.target_window_size);
                        if next_window > 0 {
                            self.target_window_size = next_window
                        }
                    }
                }

                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan
                        .send(ChannelMsg::Data {
                            data: CryptoVec::from_slice(&data),
                        })
                        .await;
                }

                client.data(channel_num, &data, self).await
            }
            Some((&msg::CHANNEL_EXTENDED_DATA, mut r)) => {
                debug!("channel_extended_data");
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                let extended_code = map_err!(u32::decode(&mut r))?;
                let data = map_err!(Bytes::decode(&mut r))?;
                let target = self.common.config.window_size;
                if let Some(ref mut enc) = self.common.encrypted {
                    if enc.adjust_window_size(channel_num, &data, target)? {
                        let next_window =
                            client.adjust_window(channel_num, self.target_window_size);
                        if next_window > 0 {
                            self.target_window_size = next_window
                        }
                    }
                }

                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan
                        .send(ChannelMsg::ExtendedData {
                            ext: extended_code,
                            data: CryptoVec::from_slice(&data),
                        })
                        .await;
                }

                client
                    .extended_data(channel_num, extended_code, &data, self)
                    .await
            }
            Some((&msg::CHANNEL_REQUEST, mut r)) => {
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                let req = map_err!(String::decode(&mut r))?;
                debug!("channel_request: {channel_num:?} {req:?}",);
                match req.as_str() {
                    "xon-xoff" => {
                        map_err!(u8::decode(&mut r))?; // should be 0.
                        let client_can_do = map_err!(u8::decode(&mut r))? != 0;
                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan.send(ChannelMsg::XonXoff { client_can_do }).await;
                        }
                        client.xon_xoff(channel_num, client_can_do, self).await
                    }
                    "exit-status" => {
                        map_err!(u8::decode(&mut r))?; // should be 0.
                        let exit_status = map_err!(u32::decode(&mut r))?;
                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan.send(ChannelMsg::ExitStatus { exit_status }).await;
                        }
                        client.exit_status(channel_num, exit_status, self).await
                    }
                    "exit-signal" => {
                        map_err!(u8::decode(&mut r))?; // should be 0.
                        let signal_name =
                            Sig::from_name(map_err!(String::decode(&mut r))?.as_str());
                        let core_dumped = map_err!(u8::decode(&mut r))? != 0;
                        let error_message = map_err!(String::decode(&mut r))?;
                        let lang_tag = map_err!(String::decode(&mut r))?;
                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan
                                .send(ChannelMsg::ExitSignal {
                                    signal_name: signal_name.clone(),
                                    core_dumped,
                                    error_message: error_message.to_string(),
                                    lang_tag: lang_tag.to_string(),
                                })
                                .await;
                        }
                        client
                            .exit_signal(
                                channel_num,
                                signal_name,
                                core_dumped,
                                &error_message,
                                &lang_tag,
                                self,
                            )
                            .await
                    }
                    "keepalive@openssh.com" => {
                        let wants_reply = map_err!(u8::decode(&mut r))?;
                        if wants_reply == 1 {
                            if let Some(ref mut enc) = self.common.encrypted {
                                trace!("Received channel keep alive message: {req:?}",);
                                self.common.wants_reply = false;
                                push_packet!(enc.write, {
                                    map_err!(msg::CHANNEL_SUCCESS.encode(&mut enc.write))?;
                                    map_err!(channel_num.encode(&mut enc.write))?;
                                });
                            }
                        } else {
                            warn!("Received keepalive without reply request!");
                        }
                        Ok(())
                    }
                    _ => {
                        let wants_reply = map_err!(u8::decode(&mut r))?;
                        if wants_reply == 1 {
                            if let Some(ref mut enc) = self.common.encrypted {
                                self.common.wants_reply = false;
                                push_packet!(enc.write, {
                                    map_err!(msg::CHANNEL_FAILURE.encode(&mut enc.write))?;
                                    map_err!(channel_num.encode(&mut enc.write))?;
                                })
                            }
                        }
                        info!("Unknown channel request {req:?} {wants_reply:?}",);
                        Ok(())
                    }
                }
            }
            Some((&msg::CHANNEL_WINDOW_ADJUST, mut r)) => {
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                let amount = map_err!(u32::decode(&mut r))?;
                let mut new_size = 0;
                debug!("channel_window_adjust amount: {amount:?}");
                if let Some(ref mut enc) = self.common.encrypted {
                    if let Some(ref mut channel) = enc.channels.get_mut(&channel_num) {
                        new_size = channel.recipient_window_size.saturating_add(amount);
                        channel.recipient_window_size = new_size;
                    } else {
                        return Ok(());
                    }
                }

                if let Some(ref mut enc) = self.common.encrypted {
                    new_size -= enc.flush_pending(channel_num)? as u32;
                }
                if let Some(chan) = self.channels.get(&channel_num) {
                    chan.window_size().update(new_size).await;

                    let _ = chan.send(ChannelMsg::WindowAdjusted { new_size }).await;
                }
                client.window_adjusted(channel_num, new_size, self).await
            }
            Some((&msg::GLOBAL_REQUEST, mut r)) => {
                let req = map_err!(String::decode(&mut r))?;
                let wants_reply = map_err!(u8::decode(&mut r))?;
                if let Some(ref mut enc) = self.common.encrypted {
                    if req.starts_with("keepalive") {
                        if wants_reply == 1 {
                            trace!("Received keep alive message: {req:?}",);
                            self.common.wants_reply = false;
                            push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS));
                        } else {
                            warn!("Received keepalive without reply request!");
                        }
                    } else if req == "hostkeys-00@openssh.com" {
                        let mut keys = vec![];
                        loop {
                            match Bytes::decode(&mut r) {
                                Ok(key) => {
                                    let key = map_err!(parse_public_key(&key));
                                    match key {
                                        Ok(key) => keys.push(key),
                                        Err(ref err) => {
                                            debug!(
                                                "failed to parse announced host key {key:?}: {err:?}",
                                            )
                                        }
                                    }
                                }
                                Err(ssh_encoding::Error::Length) => break,
                                x => {
                                    map_err!(x)?;
                                }
                            }
                        }
                        return client.openssh_ext_host_keys_announced(keys, self).await;
                    } else {
                        warn!("Unhandled global request: {req:?} {wants_reply:?}",);
                        self.common.wants_reply = false;
                        push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
                    }
                }
                self.common.received_data = false;
                Ok(())
            }
            Some((&msg::CHANNEL_SUCCESS, mut r)) => {
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan.send(ChannelMsg::Success).await;
                }
                client.channel_success(channel_num, self).await
            }
            Some((&msg::CHANNEL_FAILURE, mut r)) => {
                let channel_num = map_err!(ChannelId::decode(&mut r))?;
                if let Some(chan) = self.channels.get(&channel_num) {
                    let _ = chan.send(ChannelMsg::Failure).await;
                }
                client.channel_failure(channel_num, self).await
            }
            Some((&msg::CHANNEL_OPEN, mut r)) => {
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
                        debug!("confirming channel: {msg:?}");
                        map_err!(msg.confirm(
                            &mut enc.write,
                            id.0,
                            channel.sender_window_size,
                            channel.sender_maximum_packet_size,
                        ))?;
                        enc.channels.insert(id, channel);
                        Ok(())
                    };

                    match &msg.typ {
                        ChannelType::Session => {
                            confirm()?;
                            let channel = self.accept_server_initiated_channel(id, &msg);
                            client.server_channel_open_session(channel, self).await?
                        }
                        ChannelType::DirectTcpip(d) => {
                            confirm()?;
                            let channel = self.accept_server_initiated_channel(id, &msg);
                            client
                                .server_channel_open_direct_tcpip(
                                    channel,
                                    &d.host_to_connect,
                                    d.port_to_connect,
                                    &d.originator_address,
                                    d.originator_port,
                                    self,
                                )
                                .await?
                        }
                        ChannelType::DirectStreamLocal(d) => {
                            confirm()?;
                            let channel = self.accept_server_initiated_channel(id, &msg);
                            client
                                .server_channel_open_direct_streamlocal(
                                    channel,
                                    &d.socket_path,
                                    self,
                                )
                                .await?
                        }
                        ChannelType::X11 {
                            originator_address,
                            originator_port,
                        } => {
                            confirm()?;
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
                            confirm()?;
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
                        ChannelType::ForwardedStreamLocal(d) => {
                            confirm()?;
                            let channel = self.accept_server_initiated_channel(id, &msg);
                            client
                                .server_channel_open_forwarded_streamlocal(
                                    channel,
                                    &d.socket_path,
                                    self,
                                )
                                .await?;
                        }
                        ChannelType::AgentForward => {
                            confirm()?;
                            let channel = self.accept_server_initiated_channel(id, &msg);
                            client
                                .server_channel_open_agent_forward(channel, self)
                                .await?
                        }
                        ChannelType::Unknown { typ } => {
                            if client.should_accept_unknown_server_channel(id, typ).await {
                                confirm()?;
                                let channel = self.accept_server_initiated_channel(id, &msg);
                                client.server_channel_open_unknown(channel, self).await?;
                            } else {
                                debug!("unknown channel type: {typ}");
                                msg.unknown_type(&mut enc.write)?;
                            }
                        }
                    };
                    Ok(())
                } else {
                    Err(crate::Error::Inconsistent.into())
                }
            }
            Some((&msg::REQUEST_SUCCESS, mut r)) => {
                trace!("Global Request Success");
                match self.open_global_requests.pop_front() {
                    Some(GlobalRequestResponse::Keepalive) => {
                        // ignore keepalives
                    }
                    Some(GlobalRequestResponse::Ping(return_channel)) => {
                        let _ = return_channel.send(());
                    }
                    Some(GlobalRequestResponse::NoMoreSessions) => {
                        debug!("no-more-sessions@openssh.com requests success");
                    }
                    Some(GlobalRequestResponse::TcpIpForward(return_channel)) => {
                        let result = if r.is_empty() {
                            // If a specific port was requested, the reply has no data
                            Some(0)
                        } else {
                            match u32::decode(&mut r) {
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
                    Some(GlobalRequestResponse::StreamLocalForward(return_channel)) => {
                        let _ = return_channel.send(true);
                    }
                    Some(GlobalRequestResponse::CancelStreamLocalForward(return_channel)) => {
                        let _ = return_channel.send(true);
                    }
                    None => {
                        error!("Received global request failure for unknown request!")
                    }
                }
                Ok(())
            }
            Some((&msg::REQUEST_FAILURE, _)) => {
                trace!("global request failure");
                match self.open_global_requests.pop_front() {
                    Some(GlobalRequestResponse::Keepalive) => {
                        // ignore keepalives
                    }
                    Some(GlobalRequestResponse::Ping(return_channel)) => {
                        let _ = return_channel.send(());
                    }
                    Some(GlobalRequestResponse::NoMoreSessions) => {
                        warn!("no-more-sessions@openssh.com requests failure");
                    }
                    Some(GlobalRequestResponse::TcpIpForward(return_channel)) => {
                        let _ = return_channel.send(None);
                    }
                    Some(GlobalRequestResponse::CancelTcpIpForward(return_channel)) => {
                        let _ = return_channel.send(false);
                    }
                    Some(GlobalRequestResponse::StreamLocalForward(return_channel)) => {
                        let _ = return_channel.send(false);
                    }
                    Some(GlobalRequestResponse::CancelStreamLocalForward(return_channel)) => {
                        let _ = return_channel.send(false);
                    }
                    None => {
                        error!("Received global request failure for unknown request!")
                    }
                }
                Ok(())
            }
            m => {
                debug!("unknown message received: {m:?}");
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
            self.common.config.channel_buffer_size,
        );

        self.channels.insert(id, channel_ref);

        channel
    }

    pub(crate) fn write_auth_request_if_needed(
        &mut self,
        user: &str,
        meth: auth::Method,
    ) -> Result<bool, crate::Error> {
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
                        self.common.packet_writer.packet(|w| {
                            msg::SERVICE_REQUEST.encode(w)?;
                            "ssh-userauth".encode(w)?;
                            Ok(())
                        })?;
                        *sent = true
                    }
                    accepted
                }
                EncryptedState::InitCompression | EncryptedState::Authenticated => false,
            };
            debug!(
                "write_auth_request_if_needed: is_waiting = {is_waiting:?}"
            );
            if is_waiting {
                enc.write_auth_request(user, &meth)?;
                let auth_request = AuthRequest::new(&meth);
                enc.state = EncryptedState::WaitingAuthRequest(auth_request);
            }
        }
        self.common.auth_user.clear();
        self.common.auth_user.push_str(user);
        self.common.auth_method = Some(meth);
        Ok(is_waiting)
    }
}

impl Encrypted {
    fn write_auth_request(
        &mut self,
        user: &str,
        auth_method: &auth::Method,
    ) -> Result<bool, crate::Error> {
        // The server is waiting for our USERAUTH_REQUEST.
        Ok(push_packet!(self.write, {
            self.write.push(msg::USERAUTH_REQUEST);

            match *auth_method {
                auth::Method::None => {
                    user.encode(&mut self.write)?;
                    "ssh-connection".encode(&mut self.write)?;
                    "none".encode(&mut self.write)?;
                    true
                }
                auth::Method::Password { ref password } => {
                    user.encode(&mut self.write)?;
                    "ssh-connection".encode(&mut self.write)?;
                    "password".encode(&mut self.write)?;
                    0u8.encode(&mut self.write)?;
                    password.encode(&mut self.write)?;
                    true
                }
                auth::Method::PublicKey { ref key } => {
                    user.encode(&mut self.write)?;
                    "ssh-connection".encode(&mut self.write)?;
                    "publickey".encode(&mut self.write)?;
                    self.write.push(0); // This is a probe

                    debug!("write_auth_request: key - {:?}", key.algorithm());
                    key.algorithm().as_str().encode(&mut self.write)?;
                    key.public_key().to_bytes()?.encode(&mut self.write)?;
                    true
                }
                auth::Method::OpenSshCertificate { ref cert, .. } => {
                    user.as_bytes().encode(&mut self.write)?;
                    "ssh-connection".encode(&mut self.write)?;
                    "publickey".encode(&mut self.write)?;
                    self.write.push(0); // This is a probe

                    debug!("write_auth_request: cert - {:?}", cert.algorithm());
                    cert.algorithm()
                        .to_certificate_type()
                        .encode(&mut self.write)?;
                    cert.to_bytes()?.as_slice().encode(&mut self.write)?;
                    true
                }
                auth::Method::FuturePublicKey { ref key, hash_alg } => {
                    user.as_bytes().encode(&mut self.write)?;
                    "ssh-connection".encode(&mut self.write)?;
                    "publickey".encode(&mut self.write)?;
                    self.write.push(0); // This is a probe

                    key.algorithm()
                        .with_hash_alg(hash_alg)
                        .as_str()
                        .encode(&mut self.write)?;

                    key.to_bytes()?.as_slice().encode(&mut self.write)?;
                    true
                }
                auth::Method::KeyboardInteractive { ref submethods } => {
                    debug!("Keyboard interactive");
                    user.as_bytes().encode(&mut self.write)?;
                    "ssh-connection".encode(&mut self.write)?;
                    "keyboard-interactive".encode(&mut self.write)?;
                    "".encode(&mut self.write)?; // lang tag is deprecated. Should be empty
                    submethods.as_bytes().encode(&mut self.write)?;
                    true
                }
            }
        }))
    }

    fn client_make_to_sign(
        &mut self,
        user: &str,
        key: &PublicKeyOrCertificate,
        buffer: &mut CryptoVec,
    ) -> Result<usize, crate::Error> {
        buffer.clear();
        self.session_id.as_ref().encode(buffer)?;

        let i0 = buffer.len();
        buffer.push(msg::USERAUTH_REQUEST);
        user.encode(buffer)?;
        "ssh-connection".encode(buffer)?;
        "publickey".encode(buffer)?;
        1u8.encode(buffer)?;

        match key {
            PublicKeyOrCertificate::Certificate(cert) => {
                cert.algorithm().to_certificate_type().encode(buffer)?;
                cert.to_bytes()?.encode(buffer)?;
            }
            PublicKeyOrCertificate::PublicKey { key, hash_alg } => {
                key.algorithm().with_hash_alg(*hash_alg).encode(buffer)?;
                key.to_bytes()?.encode(buffer)?;
            }
        }
        Ok(i0)
    }

    fn client_send_signature(
        &mut self,
        user: &str,
        method: &auth::Method,
        buffer: &mut CryptoVec,
    ) -> Result<(), crate::Error> {
        match method {
            auth::Method::PublicKey { key } => {
                let i0 =
                    self.client_make_to_sign(user, &PublicKeyOrCertificate::from(key), buffer)?;

                // Extend with self-signature.
                sign_with_hash_alg(key, buffer)?.encode(&mut *buffer)?;

                push_packet!(self.write, {
                    #[allow(clippy::indexing_slicing)] // length checked
                    self.write.extend(&buffer[i0..]);
                })
            }
            auth::Method::OpenSshCertificate { key, cert } => {
                let i0 = self.client_make_to_sign(
                    user,
                    &PublicKeyOrCertificate::Certificate(cert.clone()),
                    buffer,
                )?;

                // Extend with self-signature.
                signature::Signer::try_sign(key.deref(), buffer)?
                    .encoded()?
                    .encode(&mut *buffer)?;

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
            msg::USERAUTH_INFO_RESPONSE.encode(&mut self.write)?;
            (responses.len().try_into().unwrap_or(0) as u32).encode(&mut self.write)?; // number of responses

            for r in responses {
                r.encode(&mut self.write)?; // write the reponses
            }
        });
        Ok(())
    }
}
