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
use core::str;
use std::cell::RefCell;
use std::time::SystemTime;

use auth::*;
use byteorder::{BigEndian, ByteOrder};
use bytes::Bytes;
use cert::PublicKeyOrCertificate;
use log::{debug, error, info, trace, warn};
use msg;
use signature::Verifier;
use ssh_encoding::{Decode, Encode, Reader};
use ssh_key::{PublicKey, Signature};
use tokio::time::Instant;

use super::super::*;
use super::*;
use crate::helpers::NameList;
use crate::map_err;
use crate::msg::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED;
use crate::parsing::{ChannelOpenConfirmation, ChannelType, OpenChannelMessage, ensure_end};

impl Session {
    /// Returns false iff a request was rejected.
    pub(crate) async fn server_read_encrypted<H: Handler + Send>(
        &mut self,
        handler: &mut H,
        pkt: &mut IncomingSshPacket,
    ) -> Result<(), H::Error> {
        self.process_packet(handler, &pkt.buffer).await
    }

    pub(crate) async fn process_packet<H: Handler + Send>(
        &mut self,
        handler: &mut H,
        buf: &[u8],
    ) -> Result<(), H::Error> {
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

        let Some(enc) = self.common.encrypted.as_mut() else {
            return Err(Error::Inconsistent.into());
        };

        // If we've successfully read a packet.
        match (&mut enc.state, buf.split_first()) {
            (
                EncryptedState::WaitingAuthServiceRequest { accepted, .. },
                Some((&msg::SERVICE_REQUEST, mut r)),
            ) => {
                let request = map_err!(String::decode(&mut r))?;
                map_err!(ensure_end(&r))?;
                debug!("request: {request:?}");
                if request == "ssh-userauth" {
                    let auth_request = server_accept_service(
                        handler.authentication_banner().await?,
                        self.common.config.as_ref().methods.clone(),
                        &mut enc.write,
                    )?;
                    *accepted = true;
                    enc.state = EncryptedState::WaitingAuthRequest(auth_request);
                }
                Ok(())
            }
            (EncryptedState::WaitingAuthRequest(_), Some((&msg::USERAUTH_REQUEST, mut r))) => {
                enc.server_read_auth_request(
                    rejection_wait_until,
                    initial_none_rejection_wait_until,
                    handler,
                    buf,
                    &mut r,
                    &mut self.common.auth_user,
                )
                .await?;
                self.common.auth_attempts += 1;
                if let EncryptedState::InitCompression = enc.state {
                    if enc.client_compression.is_deferred() {
                        enc.client_compression.init_decompress(&mut enc.decompress);
                    }
                    handler.auth_succeeded(self).await?;
                }
                Ok(())
            }
            (
                EncryptedState::WaitingAuthRequest(auth),
                Some((&msg::USERAUTH_INFO_RESPONSE, mut r)),
            ) => {
                let resp = read_userauth_info_response(
                    rejection_wait_until,
                    handler,
                    &mut enc.write,
                    auth,
                    &self.common.auth_user,
                    &mut r,
                )
                .await?;
                if resp {
                    enc.state = EncryptedState::InitCompression;
                    if enc.client_compression.is_deferred() {
                        enc.client_compression.init_decompress(&mut enc.decompress);
                    }
                    handler.auth_succeeded(self).await
                } else {
                    Ok(())
                }
            }
            (EncryptedState::InitCompression, Some((msg, mut r))) => {
                if enc.server_compression.is_deferred() {
                    enc.server_compression
                        .init_compress(self.common.packet_writer.compress());
                }
                enc.state = EncryptedState::Authenticated;
                self.server_read_authenticated(handler, *msg, &mut r).await
            }
            (EncryptedState::Authenticated, Some((msg, mut r))) => {
                self.server_read_authenticated(handler, *msg, &mut r).await
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::num::Wrapping;
    use std::sync::Arc;

    use bytes::BytesMut;
    use crate::compression::{Compression, Decompress};
    use crate::helpers::sign_with_hash_alg;
    use crate::kex::{SessionKexState, KEXES, NONE as KEX_NONE};
    use crate::keys::PrivateKeyWithHashAlg;
    use crate::tests::raw_no_crypto::{
        MSG_SERVICE_REQUEST, MSG_USERAUTH_FAILURE, MSG_USERAUTH_REQUEST, RawSession,
        assert_rejected, capture_panics, channel_request_payload, encode_string, pty_req_payload,
        raw_auth_request_signal, raw_channel_request_signal, raw_service_request_signal,
        read_packet, timeout,
    };

    #[tokio::test]
    async fn malformed_pty_req_truncated_modes_rejected_by_server() {
        let (result, panicked) = capture_panics(async {
            timeout(raw_channel_request_signal(|server_channel| {
                pty_req_payload(server_channel, &[Pty::VINTR as u8, 0, 0, 0])
            }))
            .await
        })
        .await;

        assert!(!panicked, "truncated pty terminal modes caused a panic");
        assert_rejected(result, "truncated pty terminal modes crashed or survived");
    }

    #[tokio::test]
    async fn malformed_pty_req_rejects_bytes_after_mode_end() {
        let result = timeout(raw_channel_request_signal(|server_channel| {
            pty_req_payload(server_channel, &[Pty::TTY_OP_END as u8, 0])
        }))
        .await;

        assert_rejected(
            result,
            "server accepted trailing bytes inside pty terminal modes",
        );
    }

    #[tokio::test]
    async fn malformed_pty_req_trailing_bytes_rejected_by_server() {
        let result = timeout(raw_channel_request_signal(|server_channel| {
            let mut payload = pty_req_payload(server_channel, &[Pty::TTY_OP_END as u8]);
            payload.push(0);
            payload
        }))
        .await;

        assert_rejected(result, "server accepted a pty request with trailing bytes");
    }

    #[tokio::test]
    async fn env_request_with_trailing_bytes_rejected_by_server() {
        let result = timeout(raw_channel_request_signal(|server_channel| {
            let mut payload = channel_request_payload(server_channel, b"env");
            encode_string(&mut payload, b"LANG");
            encode_string(&mut payload, b"C");
            payload.push(0);
            payload
        }))
        .await;

        assert_rejected(result, "server accepted an env request with trailing bytes");
    }

    #[tokio::test]
    async fn exec_request_with_trailing_bytes_rejected_by_server() {
        let result = timeout(raw_channel_request_signal(|server_channel| {
            let mut payload = channel_request_payload(server_channel, b"exec");
            encode_string(&mut payload, b"true");
            payload.push(0);
            payload
        }))
        .await;

        assert_rejected(
            result,
            "server accepted an exec request with trailing bytes",
        );
    }

    #[tokio::test]
    async fn signal_request_with_trailing_bytes_rejected_by_server() {
        let result = timeout(raw_channel_request_signal(|server_channel| {
            let mut payload = channel_request_payload(server_channel, b"signal");
            encode_string(&mut payload, b"TERM");
            payload.push(0);
            payload
        }))
        .await;

        assert_rejected(
            result,
            "server accepted a signal request with trailing bytes",
        );
    }

    #[tokio::test]
    async fn service_request_with_trailing_bytes_rejected_by_server() {
        let result = timeout(raw_service_request_signal(|payload| {
            payload.push(MSG_SERVICE_REQUEST);
            encode_string(payload, b"ssh-userauth");
            payload.push(0);
        }))
        .await;

        assert_rejected(
            result,
            "server accepted a service request with trailing bytes",
        );
    }

    #[tokio::test]
    async fn auth_none_with_trailing_bytes_rejected_by_server() {
        let result = timeout(raw_auth_request_signal(|payload| {
            payload.push(MSG_USERAUTH_REQUEST);
            encode_string(payload, b"test");
            encode_string(payload, b"ssh-connection");
            encode_string(payload, b"none");
            payload.push(0);
        }))
        .await;

        assert_rejected(
            result,
            "server accepted a none auth request with trailing bytes",
        );
    }

    #[tokio::test]
    async fn auth_password_with_trailing_bytes_rejected_by_server() {
        let result = timeout(raw_auth_request_signal(|payload| {
            payload.push(MSG_USERAUTH_REQUEST);
            encode_string(payload, b"test");
            encode_string(payload, b"ssh-connection");
            encode_string(payload, b"password");
            payload.push(0);
            encode_string(payload, b"secret");
            payload.push(0);
        }))
        .await;

        assert_rejected(
            result,
            "server accepted a password auth request with trailing bytes",
        );
    }

    #[tokio::test]
    async fn password_change_request_is_parsed_and_rejected_by_server() {
        let mut stream = RawSession::connect().await;
        stream.service_request().await.unwrap();

        let mut payload = Vec::new();
        payload.push(MSG_USERAUTH_REQUEST);
        encode_string(&mut payload, b"test");
        encode_string(&mut payload, b"ssh-connection");
        encode_string(&mut payload, b"password");
        payload.push(1);
        encode_string(&mut payload, b"old-password");
        encode_string(&mut payload, b"new-password");
        stream.send_packet(&payload).await.unwrap();

        let failure = read_packet(&mut stream.stream).await.unwrap();
        assert_eq!(failure.first(), Some(&MSG_USERAUTH_FAILURE));
        assert!(
            !stream.events.lock().unwrap().contains(&"auth_password"),
            "password-change requests should not call normal password auth"
        );
        stream.server_task.abort();
    }

    #[tokio::test]
    async fn signed_publickey_request_cannot_reuse_pk_ok_for_a_different_key() {
        struct Probe {
            pk_ok_key: PublicKey,
            signed_key: PublicKey,
            final_auth_reached_for_signed_key: bool,
        }

        impl Handler for Probe {
            type Error = Error;

            async fn auth_publickey_offered(
                &mut self,
                _user: &str,
                public_key: &PublicKey,
            ) -> Result<Auth, Self::Error> {
                if public_key == &self.pk_ok_key {
                    return Ok(Auth::Accept);
                }
                Ok(Auth::reject())
            }

            async fn auth_publickey(
                &mut self,
                _user: &str,
                public_key: &PublicKey,
            ) -> Result<Auth, Self::Error> {
                if public_key == &self.signed_key {
                    self.final_auth_reached_for_signed_key = true;
                }
                Ok(Auth::reject())
            }
        }

        let pk_ok_private =
            PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let signed_private =
            PrivateKey::random(&mut rand::rng(), ssh_key::Algorithm::Ed25519).unwrap();
        let pk_ok_key = pk_ok_private.public_key().clone();
        let signed_key = signed_private.public_key().clone();

        let mut session = test_auth_session();
        let mut handler = Probe {
            pk_ok_key: pk_ok_key.clone(),
            signed_key: signed_key.clone(),
            final_auth_reached_for_signed_key: false,
        };

        let probe = publickey_probe_packet("alice", &pk_ok_key);
        let mut probe = BytesMut::from(probe.as_slice());
        session.process_packet(&mut handler, &mut probe).await.unwrap();

        let signed = publickey_signed_packet("alice", Arc::new(signed_private), &signed_key);
        let mut signed = BytesMut::from(signed.as_slice());
        session.process_packet(&mut handler, &mut signed).await.unwrap();

        assert!(
            !handler.final_auth_reached_for_signed_key,
            "signed publickey request reused PK_OK state from a different public key"
        );
    }

    fn publickey_probe_packet(user: &str, public_key: &PublicKey) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(msg::USERAUTH_REQUEST);
        user.encode(&mut packet).unwrap();
        "ssh-connection".encode(&mut packet).unwrap();
        "publickey".encode(&mut packet).unwrap();
        0u8.encode(&mut packet).unwrap();
        public_key.algorithm().as_str().encode(&mut packet).unwrap();
        public_key.to_bytes().unwrap().encode(&mut packet).unwrap();
        packet
    }

    fn publickey_signed_packet(
        user: &str,
        private_key: Arc<PrivateKey>,
        public_key: &PublicKey,
    ) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.push(msg::USERAUTH_REQUEST);
        user.encode(&mut packet).unwrap();
        "ssh-connection".encode(&mut packet).unwrap();
        "publickey".encode(&mut packet).unwrap();
        1u8.encode(&mut packet).unwrap();
        public_key.algorithm().as_str().encode(&mut packet).unwrap();
        public_key.to_bytes().unwrap().encode(&mut packet).unwrap();

        let mut signed = Vec::new();
        CryptoVec::new().as_ref().encode(&mut signed).unwrap();
        signed.extend_from_slice(&packet);
        let signature =
            sign_with_hash_alg(&PrivateKeyWithHashAlg::new(private_key, None), &signed).unwrap();
        signature.encode(&mut packet).unwrap();
        packet
    }

    fn test_auth_session() -> Session {
        let mut config = Config::default();
        config.preferred = Preferred {
            kex: Cow::Owned(vec![KEX_NONE]),
            key: Cow::Owned(vec![ssh_key::Algorithm::Ed25519]),
            cipher: Cow::Owned(vec![cipher::NONE]),
            mac: Cow::Owned(vec![mac::NONE]),
            compression: Cow::Owned(vec![compression::NONE]),
        };
        let config = Arc::new(config);
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let handle = Handle {
            sender,
            channel_buffer_size: config.channel_buffer_size,
        };

        Session {
            target_window_size: config.window_size,
            common: CommonSession {
                packet_writer: PacketWriter::clear(),
                auth_user: String::new(),
                auth_method: None,
                auth_attempts: 0,
                remote_to_local: Box::new(clear::Key),
                encrypted: Some(test_auth_encrypted()),
                config,
                wants_reply: false,
                disconnected: false,
                buffer: Vec::new(),
                strict_kex: false,
                alive_timeouts: 0,
                received_data: false,
                remote_sshid: Vec::new(),
            },
            receiver,
            sender: handle,
            pending_reads: Vec::new(),
            pending_len: 0,
            channels: std::collections::HashMap::new(),
            open_global_requests: std::collections::VecDeque::new(),
            kex: SessionKexState::Idle,
        }
    }

    fn test_auth_encrypted() -> Encrypted {
        Encrypted {
            state: EncryptedState::WaitingAuthRequest(AuthRequest::server(MethodSet::all())),
            exchange: Some(Exchange::default()),
            kex: KEXES.get(&KEX_NONE).expect("none kex").make(),
            key: 0,
            client_mac: mac::NONE,
            server_mac: mac::NONE,
            session_id: CryptoVec::new(),
            channels: std::collections::HashMap::new(),
            last_channel_id: Wrapping(0),
            write: Vec::new(),
            write_cursor: 0,
            last_rekey: russh_util::time::Instant::now(),
            server_compression: Compression::None,
            client_compression: Compression::None,
            decompress: Decompress::None,
            rekey_wanted: false,
            received_extensions: Vec::new(),
            extension_info_awaiters: std::collections::HashMap::new(),
        }
    }
}

fn server_accept_service(
    banner: Option<String>,
    methods: MethodSet,
    buffer: &mut Vec<u8>,
) -> Result<AuthRequest, crate::Error> {
    push_packet!(buffer, {
        buffer.push(msg::SERVICE_ACCEPT);
        "ssh-userauth".encode(buffer)?;
    });

    if let Some(banner) = banner {
        push_packet!(buffer, {
            buffer.push(msg::USERAUTH_BANNER);
            banner.encode(buffer)?;
            "".encode(buffer)?;
        })
    }

    Ok(AuthRequest::server(methods))
}

impl Encrypted {
    /// Returns false iff the request was rejected.
    async fn server_read_auth_request<H: Handler + Send>(
        &mut self,
        mut until: Instant,
        initial_auth_until: Instant,
        handler: &mut H,
        original_packet: &[u8],
        r: &mut &[u8],
        auth_user: &mut String,
    ) -> Result<(), H::Error> {
        // https://tools.ietf.org/html/rfc4252#section-5
        let user = map_err!(String::decode(r))?;
        let service_name = map_err!(String::decode(r))?;
        let method = map_err!(String::decode(r))?;
        debug!("name: {user:?} {service_name:?} {method:?}",);

        if service_name == "ssh-connection" {
            {
                let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state
                {
                    a
                } else {
                    unreachable!()
                };
                if auth_request.bind_or_reset_principal(&user, &service_name) {
                    auth_user.clear();
                }
            }

            if method == "password" {
                let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state
                {
                    a
                } else {
                    unreachable!()
                };
                auth_user.clear();
                auth_user.push_str(&user);
                let change = map_err!(u8::decode(r))? != 0;
                let password = map_err!(String::decode(r))?;
                if change {
                    let _new_password = map_err!(String::decode(r))?;
                }
                map_err!(ensure_end(r))?;
                let auth = if change {
                    Auth::Reject {
                        proceed_with_methods: None,
                        partial_success: false,
                    }
                } else {
                    handler.auth_password(&user, &password).await?
                };
                if let Auth::Accept = auth {
                    server_auth_request_success(&mut self.write);
                    self.state = EncryptedState::InitCompression;
                } else {
                    auth_user.clear();
                    if let Auth::Reject {
                        proceed_with_methods: Some(proceed_with_methods),
                        partial_success,
                    } = auth
                    {
                        auth_request.methods = proceed_with_methods;
                        auth_request.partial_success = partial_success;
                    } else {
                        auth_request.methods.remove(MethodKind::Password);
                    }
                    auth_request.partial_success = false;
                    reject_auth_request(until, &mut self.write, auth_request).await?;
                }
                Ok(())
            } else if method == "publickey" {
                self.server_read_auth_request_pk(
                    until,
                    handler,
                    original_packet,
                    auth_user,
                    &user,
                    r,
                )
                .await
            } else if method == "none" {
                let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state
                {
                    a
                } else {
                    unreachable!()
                };

                until = initial_auth_until;
                map_err!(ensure_end(r))?;

                let auth = handler.auth_none(&user).await?;
                if let Auth::Accept = auth {
                    server_auth_request_success(&mut self.write);
                    self.state = EncryptedState::InitCompression;
                } else {
                    auth_user.clear();
                    if let Auth::Reject {
                        proceed_with_methods: Some(proceed_with_methods),
                        partial_success,
                    } = auth
                    {
                        auth_request.methods = proceed_with_methods;
                        auth_request.partial_success = partial_success;
                    } else {
                        auth_request.methods.remove(MethodKind::None);
                    }
                    auth_request.partial_success = false;
                    reject_auth_request(until, &mut self.write, auth_request).await?;
                }
                Ok(())
            } else if method == "keyboard-interactive" {
                let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state
                {
                    a
                } else {
                    unreachable!()
                };
                auth_user.clear();
                auth_user.push_str(&user);
                let _ = map_err!(String::decode(r))?; // language_tag, deprecated.
                let submethods = map_err!(String::decode(r))?;
                map_err!(ensure_end(r))?;
                debug!("{submethods:?}");
                auth_request.current = Some(CurrentRequest::KeyboardInteractive {
                    submethods: submethods.to_string(),
                });
                let auth = handler
                    .auth_keyboard_interactive(&user, &submethods, None)
                    .await?;
                if reply_userauth_info_response(until, auth_request, &mut self.write, auth).await? {
                    self.state = EncryptedState::InitCompression
                }
                Ok(())
            } else {
                // Other methods of the base specification are insecure or optional.
                let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state
                {
                    a
                } else {
                    unreachable!()
                };
                reject_auth_request(until, &mut self.write, auth_request).await?;
                Ok(())
            }
        } else {
            // Unknown service
            Err(Error::Inconsistent.into())
        }
    }
}

thread_local! {
    static SIGNATURE_BUFFER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

impl Encrypted {
    async fn server_read_auth_request_pk<H: Handler + Send>(
        &mut self,
        until: Instant,
        handler: &mut H,
        original_packet: &[u8],
        auth_user: &mut String,
        user: &str,
        r: &mut &[u8],
    ) -> Result<(), H::Error> {
        let auth_request = if let EncryptedState::WaitingAuthRequest(ref mut a) = self.state {
            a
        } else {
            unreachable!()
        };

        let is_real = map_err!(u8::decode(r))?;

        let pubkey_algo = map_err!(String::decode(r))?;
        let pubkey_key = map_err!(Bytes::decode(r))?;
        let key_or_cert = PublicKeyOrCertificate::decode(&pubkey_algo, &pubkey_key);

        // Parse the public key or certificate
        match key_or_cert {
            Ok(pk_or_cert) => {
                debug!("is_real = {is_real:?}");

                // Handle certificates specifically
                let pubkey = match pk_or_cert {
                    PublicKeyOrCertificate::PublicKey { ref key, .. } => key.clone(),
                    PublicKeyOrCertificate::Certificate(ref cert) => {
                        // Validate certificate expiration
                        let now = SystemTime::now();
                        if cert.valid_after_time().map(|t| now < t).unwrap_or_default()
                            || cert
                                .valid_before_time()
                                .map(|t| now > t)
                                .unwrap_or_default()
                        {
                            warn!("Certificate is expired or not yet valid");
                            reject_auth_request(until, &mut self.write, auth_request).await?;
                            return Ok(());
                        }

                        // Verify the certificate’s signature
                        if cert.verify_signature().is_err() {
                            warn!("Certificate signature is invalid");
                            reject_auth_request(until, &mut self.write, auth_request).await?;
                            return Ok(());
                        }

                        // Use certificate's public key for authentication
                        PublicKey::new(cert.public_key().clone(), "")
                    }
                };

                if is_real != 0 {
                    // SAFETY: both original_packet and pos0 are coming
                    // from the same allocation (pos0 is derived from
                    // a slice of the original_packet)
                    let sig_init_buffer = {
                        let pos0 = r.as_ptr();
                        let init_len = unsafe { pos0.offset_from(original_packet.as_ptr()) };
                        #[allow(clippy::indexing_slicing)] // length checked
                        &original_packet[0..init_len as usize]
                    };

                    let accepted_probe_matches = if let Some(CurrentRequest::PublicKey {
                        key,
                        algo,
                        sent_pk_ok,
                    }) = &auth_request.current
                    {
                        *sent_pk_ok
                            && algo.as_slice() == pubkey_algo.as_bytes()
                            && key.as_slice() == pubkey_key.as_ref()
                    } else {
                        false
                    };

                    let encoded_signature = map_err!(Vec::<u8>::decode(r))?;

                    let mut signature_reader = encoded_signature.as_slice();
                    let sig = map_err!(Signature::decode(&mut signature_reader))?;
                    map_err!(ensure_end(&signature_reader))?;
                    map_err!(ensure_end(r))?;

                    let is_valid = if accepted_probe_matches && user == auth_user {
                        true
                    } else {
                        auth_user.clear();
                        auth_user.push_str(user);
                        let auth = handler.auth_publickey_offered(user, &pubkey).await?;
                        auth == Auth::Accept
                    };

                    if is_valid {
                        let session_id = self.session_id.as_ref();
                        #[allow(clippy::blocks_in_conditions)]
                        if SIGNATURE_BUFFER.with(|buf| {
                            let mut buf = buf.borrow_mut();
                            buf.clear();
                            map_err!(session_id.encode(&mut *buf))?;
                            buf.extend_from_slice(sig_init_buffer);

                            Ok(Verifier::verify(&pubkey, &buf, &sig).is_ok())
                        })? {
                            debug!("signature verified");
                            let auth = match pk_or_cert {
                                PublicKeyOrCertificate::PublicKey { ref key, .. } => {
                                    handler.auth_publickey(user, key).await?
                                }
                                PublicKeyOrCertificate::Certificate(ref cert) => {
                                    handler.auth_openssh_certificate(user, cert).await?
                                }
                            };

                            if auth == Auth::Accept {
                                server_auth_request_success(&mut self.write);
                                self.state = EncryptedState::InitCompression;
                            } else {
                                if let Auth::Reject {
                                    proceed_with_methods: Some(proceed_with_methods),
                                    partial_success,
                                } = auth
                                {
                                    auth_request.methods = proceed_with_methods;
                                    auth_request.partial_success = partial_success;
                                }
                                auth_request.partial_success = false;
                                auth_user.clear();
                                reject_auth_request(until, &mut self.write, auth_request).await?;
                            }
                        } else {
                            debug!("signature wrong");
                            auth_user.clear();
                            reject_auth_request(until, &mut self.write, auth_request).await?;
                        }
                    } else {
                        auth_user.clear();
                        reject_auth_request(until, &mut self.write, auth_request).await?;
                    }
                    Ok(())
                } else {
                    map_err!(ensure_end(r))?;
                    auth_user.clear();
                    auth_user.push_str(user);
                    let auth = handler.auth_publickey_offered(user, &pubkey).await?;
                    match auth {
                        Auth::Accept => {
                            let mut public_key = Vec::new();
                            public_key.extend_from_slice(&pubkey_key);

                            let mut algo = Vec::new();
                            algo.extend_from_slice(pubkey_algo.as_bytes());
                            debug!("pubkey_key: {pubkey_key:?}");
                            push_packet!(self.write, {
                                self.write.push(msg::USERAUTH_PK_OK);
                                map_err!(pubkey_algo.encode(&mut self.write))?;
                                map_err!(pubkey_key.encode(&mut self.write))?;
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
                                partial_success,
                            } = auth
                            {
                                auth_request.methods = proceed_with_methods;
                                auth_request.partial_success = partial_success;
                            }
                            auth_request.partial_success = false;
                            auth_user.clear();
                            reject_auth_request(until, &mut self.write, auth_request).await?;
                        }
                    }
                    Ok(())
                }
            }
            Err(e) => match e {
                ssh_key::Error::AlgorithmUnknown
                | ssh_key::Error::AlgorithmUnsupported { .. }
                | ssh_key::Error::CertificateValidation => {
                    debug!("public key error: {e}");
                    reject_auth_request(until, &mut self.write, auth_request).await?;
                    Ok(())
                }
                e => Err(crate::Error::from(e).into()),
            },
        }
    }
}

async fn reject_auth_request(
    until: Instant,
    write: &mut Vec<u8>,
    auth_request: &mut AuthRequest,
) -> Result<(), Error> {
    debug!("rejecting {auth_request:?}");
    push_packet!(write, {
        write.push(msg::USERAUTH_FAILURE);
        NameList::from(&auth_request.methods).encode(write)?;
        write.push(auth_request.partial_success as u8);
    });
    auth_request.current = None;
    auth_request.rejection_count += 1;
    debug!("packet pushed");
    tokio::time::sleep_until(until).await;
    Ok(())
}

fn server_auth_request_success(buffer: &mut Vec<u8>) {
    push_packet!(buffer, {
        buffer.push(msg::USERAUTH_SUCCESS);
    })
}

async fn read_userauth_info_response<H: Handler + Send, R: Reader>(
    until: Instant,
    handler: &mut H,
    write: &mut Vec<u8>,
    auth_request: &mut AuthRequest,
    user: &str,
    r: &mut R,
) -> Result<bool, H::Error> {
    if let Some(CurrentRequest::KeyboardInteractive { ref submethods }) = auth_request.current {
        let n = map_err!(u32::decode(r))?;

        // Bound both allocation and iteration by remaining packet data to
        // prevent a malicious client from causing a multi-GB allocation or
        // billions of loop iterations with a crafted count.
        // Each response needs at least 4 bytes (length prefix).
        let max_responses = r.remaining_len().saturating_add(3) / 4;
        let n = (n as usize).min(max_responses);
        let mut responses = Vec::with_capacity(n);
        for _ in 0..n {
            responses.push(Bytes::decode(r).ok())
        }
        map_err!(ensure_end(r))?;

        let auth = handler
            .auth_keyboard_interactive(user, submethods, Some(Response(&mut responses.into_iter())))
            .await?;
        let resp = reply_userauth_info_response(until, auth_request, write, auth)
            .await
            .map_err(H::Error::from)?;
        Ok(resp)
    } else {
        reject_auth_request(until, write, auth_request).await?;
        Ok(false)
    }
}

async fn reply_userauth_info_response(
    until: Instant,
    auth_request: &mut AuthRequest,
    write: &mut Vec<u8>,
    auth: Auth,
) -> Result<bool, Error> {
    match auth {
        Auth::Accept => {
            server_auth_request_success(write);
            Ok(true)
        }
        Auth::Reject {
            proceed_with_methods,
            partial_success,
        } => {
            if let Some(proceed_with_methods) = proceed_with_methods {
                auth_request.methods = proceed_with_methods;
            }
            auth_request.partial_success = partial_success;
            reject_auth_request(until, write, auth_request).await?;
            Ok(false)
        }
        Auth::Partial {
            name,
            instructions,
            prompts,
        } => {
            push_packet!(write, {
                msg::USERAUTH_INFO_REQUEST.encode(write)?;
                name.as_ref().encode(write)?;
                instructions.as_ref().encode(write)?;
                "".encode(write)?; // lang, should be empty
                prompts.len().encode(write)?;
                for &(ref a, b) in prompts.iter() {
                    a.as_ref().encode(write)?;
                    (b as u8).encode(write)?;
                }
                Ok::<(), crate::Error>(())
            })?;
            Ok(false)
        }
        Auth::UnsupportedMethod => Err(Error::UnsupportedAuthMethod),
    }
}

impl Session {
    async fn server_read_authenticated<H: Handler + Send, R: Reader>(
        &mut self,
        handler: &mut H,
        msg: u8,
        r: &mut R,
    ) -> Result<(), H::Error> {
        match msg {
            msg::CHANNEL_OPEN => self
                .server_handle_channel_open(handler, r)
                .await
                .map(|_| ()),
            msg::CHANNEL_CLOSE => {
                let channel_num = map_err!(ChannelId::decode(r))?;
                map_err!(ensure_end(r))?;
                if let Some(ref mut enc) = self.common.encrypted {
                    enc.channels.remove(&channel_num);
                }
                // Forward the close to the channel before removing it, so that
                // consumers waiting on `Channel::wait()` receive an explicit
                // `ChannelMsg::Close` instead of just seeing `None`.
                if let Some(chan) = self.channels.get(&channel_num) {
                    chan.send(ChannelMsg::Close).await.unwrap_or(())
                }
                self.channels.remove(&channel_num);
                debug!("handler.channel_close {channel_num:?}");
                handler.channel_close(channel_num, self).await
            }
            msg::CHANNEL_EOF => {
                let channel_num = map_err!(ChannelId::decode(r))?;
                map_err!(ensure_end(r))?;
                if let Some(chan) = self.channels.get(&channel_num) {
                    chan.send(ChannelMsg::Eof).await.unwrap_or(())
                }
                debug!("handler.channel_eof {channel_num:?}");
                handler.channel_eof(channel_num, self).await
            }
            msg::CHANNEL_EXTENDED_DATA | msg::CHANNEL_DATA => {
                let channel_num = map_err!(ChannelId::decode(r))?;

                let ext = if msg == msg::CHANNEL_DATA {
                    None
                } else {
                    Some(map_err!(u32::decode(r))?)
                };
                trace!("handler.data {ext:?} {channel_num:?}");
                let data = map_err!(Bytes::decode(r))?;
                map_err!(ensure_end(r))?;
                let target = self.target_window_size;

                if let Some(ref mut enc) = self.common.encrypted {
                    if enc.adjust_window_size(channel_num, &data, target)? {
                        let window = handler.adjust_window(channel_num, self.target_window_size);
                        if window > 0 {
                            self.target_window_size = window
                        }
                    }
                }
                self.flush()?;
                if let Some(ext) = ext {
                    if let Some(chan) = self.channels.get(&channel_num) {
                        chan.send(ChannelMsg::ExtendedData {
                            ext,
                            data: data.clone(),
                        })
                        .await
                        .unwrap_or(())
                    }
                    handler.extended_data(channel_num, ext, &data, self).await
                } else {
                    if let Some(chan) = self.channels.get(&channel_num) {
                        chan.send(ChannelMsg::Data { data: data.clone() })
                            .await
                            .unwrap_or(())
                    }
                    handler.data(channel_num, &data, self).await
                }
            }

            msg::CHANNEL_WINDOW_ADJUST => {
                let channel_num = map_err!(ChannelId::decode(r))?;
                let amount = map_err!(u32::decode(r))?;
                map_err!(ensure_end(r))?;
                let mut new_size = 0;
                if let Some(ref mut enc) = self.common.encrypted {
                    if let Some(channel) = enc.channels.get_mut(&channel_num) {
                        new_size = channel.recipient_window_size.saturating_add(amount);
                        channel.recipient_window_size = new_size;
                    } else {
                        return Ok(());
                    }
                }
                let common = &mut self.common;
                if let Some(enc) = common.encrypted.as_mut() {
                    new_size -= enc
                        .flush_pending_with_writer(&mut common.packet_writer, channel_num)?
                        as u32;
                }
                if let Some(chan) = self.channels.get(&channel_num) {
                    chan.window_size().update(new_size).await;
                    // Use try_send to avoid blocking the session loop when channel buffer is full.
                    // WindowAdjusted is informational - the critical side effect (updating
                    // WindowSizeRef and notifying ChannelTx) already happens in update().
                    let _ = chan.try_send(ChannelMsg::WindowAdjusted { new_size });
                }
                debug!("handler.window_adjusted {channel_num:?}");
                handler.window_adjusted(channel_num, new_size, self).await
            }

            msg::CHANNEL_OPEN_CONFIRMATION => {
                debug!("channel_open_confirmation");
                let msg = map_err!(ChannelOpenConfirmation::decode(r))?;
                map_err!(ensure_end(r))?;
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
                handler
                    .channel_open_confirmation(
                        local_id,
                        msg.maximum_packet_size,
                        msg.initial_window_size,
                        self,
                    )
                    .await
            }

            msg::CHANNEL_REQUEST => {
                let channel_num = map_err!(ChannelId::decode(r))?;
                let req_type = map_err!(String::decode(r))?;
                let wants_reply = map_err!(u8::decode(r))?;
                if let Some(ref mut enc) = self.common.encrypted {
                    if let Some(channel) = enc.channels.get_mut(&channel_num) {
                        channel.wants_reply = wants_reply != 0;
                    }
                }
                match req_type.as_str() {
                    "pty-req" => {
                        let term = map_err!(String::decode(r))?;
                        let col_width = map_err!(u32::decode(r))?;
                        let row_height = map_err!(u32::decode(r))?;
                        let pix_width = map_err!(u32::decode(r))?;
                        let pix_height = map_err!(u32::decode(r))?;
                        let mut modes = [(Pty::TTY_OP_END, 0); 130];
                        let mut i = 0;
                        {
                            let mode_string = map_err!(Bytes::decode(r))?;
                            let mut mode_bytes = mode_string.as_ref();
                            while !mode_bytes.is_empty() {
                                #[allow(clippy::indexing_slicing)] // length checked
                                let code = mode_bytes[0];
                                if code == 0 {
                                    if mode_bytes.len() != 1 {
                                        return Err(Error::Inconsistent.into());
                                    }
                                    break;
                                }
                                if mode_bytes.len() < 5 {
                                    return Err(Error::Inconsistent.into());
                                }
                                #[allow(clippy::indexing_slicing)] // length checked
                                let num = BigEndian::read_u32(&mode_bytes[1..5]);
                                debug!("code = {code:?}");
                                if let Some(code) = Pty::from_u8(code) {
                                    #[allow(clippy::indexing_slicing)] // length checked
                                    if i < 130 {
                                        modes[i] = (code, num);
                                    } else {
                                        error!("pty-req: too many pty codes");
                                    }
                                } else {
                                    info!("pty-req: unknown pty code {code:?}");
                                }
                                i += 1;

                                #[allow(clippy::indexing_slicing, reason = "length checked")]
                                {
                                    mode_bytes = &mode_bytes[5..];
                                }
                            }
                        }
                        map_err!(ensure_end(r))?;

                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan
                                .send(ChannelMsg::RequestPty {
                                    want_reply: true,
                                    term: term.clone(),
                                    col_width,
                                    row_height,
                                    pix_width,
                                    pix_height,
                                    terminal_modes: modes.into(),
                                })
                                .await;
                        }

                        debug!("handler.pty_request {channel_num:?}");
                        #[allow(clippy::indexing_slicing)] // `modes` length checked
                        handler
                            .pty_request(
                                channel_num,
                                &term,
                                col_width,
                                row_height,
                                pix_width,
                                pix_height,
                                &modes[0..i],
                                self,
                            )
                            .await
                    }
                    "x11-req" => {
                        let single_connection = map_err!(u8::decode(r))? != 0;
                        let x11_auth_protocol = map_err!(String::decode(r))?;
                        let x11_auth_cookie = map_err!(String::decode(r))?;
                        let x11_screen_number = map_err!(u32::decode(r))?;
                        map_err!(ensure_end(r))?;

                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan
                                .send(ChannelMsg::RequestX11 {
                                    want_reply: true,
                                    single_connection,
                                    x11_authentication_cookie: x11_auth_cookie.clone(),
                                    x11_authentication_protocol: x11_auth_protocol.clone(),
                                    x11_screen_number,
                                })
                                .await;
                        }
                        debug!("handler.x11_request {channel_num:?}");
                        handler
                            .x11_request(
                                channel_num,
                                single_connection,
                                &x11_auth_protocol,
                                &x11_auth_cookie,
                                x11_screen_number,
                                self,
                            )
                            .await
                    }
                    "env" => {
                        let env_variable = map_err!(String::decode(r))?;
                        let env_value = map_err!(String::decode(r))?;
                        map_err!(ensure_end(r))?;

                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan
                                .send(ChannelMsg::SetEnv {
                                    want_reply: true,
                                    variable_name: env_variable.clone(),
                                    variable_value: env_value.clone(),
                                })
                                .await;
                        }

                        debug!("handler.env_request {channel_num:?}");
                        handler
                            .env_request(channel_num, &env_variable, &env_value, self)
                            .await
                    }
                    "shell" => {
                        map_err!(ensure_end(r))?;
                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan
                                .send(ChannelMsg::RequestShell { want_reply: true })
                                .await;
                        }
                        debug!("handler.shell_request {channel_num:?}");
                        handler.shell_request(channel_num, self).await
                    }
                    "auth-agent-req@openssh.com" => {
                        map_err!(ensure_end(r))?;
                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan
                                .send(ChannelMsg::AgentForward { want_reply: true })
                                .await;
                        }
                        debug!("handler.agent_request {channel_num:?}");

                        let response = handler.agent_request(channel_num, self).await?;
                        if response {
                            self.request_success()
                        } else {
                            self.request_failure()
                        }
                        Ok(())
                    }
                    "exec" => {
                        let req = map_err!(Bytes::decode(r))?;
                        map_err!(ensure_end(r))?;
                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan
                                .send(ChannelMsg::Exec {
                                    want_reply: true,
                                    command: req.to_vec(),
                                })
                                .await;
                        }
                        debug!("handler.exec_request {channel_num:?}");
                        handler.exec_request(channel_num, &req, self).await
                    }
                    "subsystem" => {
                        let name = map_err!(String::decode(r))?;
                        map_err!(ensure_end(r))?;

                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan
                                .send(ChannelMsg::RequestSubsystem {
                                    want_reply: true,
                                    name: name.clone(),
                                })
                                .await;
                        }
                        debug!("handler.subsystem_request {channel_num:?}");
                        handler.subsystem_request(channel_num, &name, self).await
                    }
                    "window-change" => {
                        let col_width = map_err!(u32::decode(r))?;
                        let row_height = map_err!(u32::decode(r))?;
                        let pix_width = map_err!(u32::decode(r))?;
                        let pix_height = map_err!(u32::decode(r))?;
                        map_err!(ensure_end(r))?;

                        if let Some(chan) = self.channels.get(&channel_num) {
                            let _ = chan
                                .send(ChannelMsg::WindowChange {
                                    col_width,
                                    row_height,
                                    pix_width,
                                    pix_height,
                                })
                                .await;
                        }

                        debug!("handler.window_change {channel_num:?}");
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
                    "signal" => {
                        let signal = Sig::from_name(&map_err!(String::decode(r))?);
                        map_err!(ensure_end(r))?;
                        if let Some(chan) = self.channels.get(&channel_num) {
                            chan.send(ChannelMsg::Signal {
                                signal: signal.clone(),
                            })
                            .await
                            .unwrap_or(())
                        }
                        debug!("handler.signal {channel_num:?} {signal:?}");
                        handler.signal(channel_num, signal, self).await
                    }
                    x => {
                        warn!("unknown channel request {x}");
                        self.channel_failure(channel_num)?;
                        Ok(())
                    }
                }
            }
            msg::GLOBAL_REQUEST => {
                let req_type = map_err!(String::decode(r))?;
                self.common.wants_reply = map_err!(u8::decode(r))? != 0;
                match req_type.as_str() {
                    "tcpip-forward" => {
                        let address = map_err!(String::decode(r))?;
                        let port = map_err!(u32::decode(r))?;
                        map_err!(ensure_end(r))?;
                        debug!("handler.tcpip_forward {address:?} {port:?}");
                        let mut returned_port = port;
                        let result = handler
                            .tcpip_forward(&address, &mut returned_port, self)
                            .await?;
                        if let Some(ref mut enc) = self.common.encrypted {
                            if result {
                                push_packet!(enc.write, {
                                    enc.write.push(msg::REQUEST_SUCCESS);
                                    if self.common.wants_reply && port == 0 && returned_port != 0 {
                                        map_err!(returned_port.encode(&mut enc.write))?;
                                    }
                                })
                            } else {
                                push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
                            }
                        }
                        Ok(())
                    }
                    "cancel-tcpip-forward" => {
                        let address = map_err!(String::decode(r))?;
                        let port = map_err!(u32::decode(r))?;
                        map_err!(ensure_end(r))?;
                        debug!("handler.cancel_tcpip_forward {address:?} {port:?}");
                        let result = handler.cancel_tcpip_forward(&address, port, self).await?;
                        if let Some(ref mut enc) = self.common.encrypted {
                            if result {
                                push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS))
                            } else {
                                push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
                            }
                        }
                        Ok(())
                    }
                    "streamlocal-forward@openssh.com" => {
                        let server_socket_path = map_err!(String::decode(r))?;
                        map_err!(ensure_end(r))?;
                        debug!("handler.streamlocal_forward {server_socket_path:?}");
                        let result = handler
                            .streamlocal_forward(&server_socket_path, self)
                            .await?;
                        if let Some(ref mut enc) = self.common.encrypted {
                            if result {
                                push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS))
                            } else {
                                push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
                            }
                        }
                        Ok(())
                    }
                    "cancel-streamlocal-forward@openssh.com" => {
                        let socket_path = map_err!(String::decode(r))?;
                        map_err!(ensure_end(r))?;
                        debug!("handler.cancel_streamlocal_forward {socket_path:?}");
                        let result = handler
                            .cancel_streamlocal_forward(&socket_path, self)
                            .await?;
                        if let Some(ref mut enc) = self.common.encrypted {
                            if result {
                                push_packet!(enc.write, enc.write.push(msg::REQUEST_SUCCESS))
                            } else {
                                push_packet!(enc.write, enc.write.push(msg::REQUEST_FAILURE))
                            }
                        }
                        Ok(())
                    }
                    _ => {
                        if let Some(ref mut enc) = self.common.encrypted {
                            push_packet!(enc.write, {
                                enc.write.push(msg::REQUEST_FAILURE);
                            });
                        }
                        Ok(())
                    }
                }
            }
            msg::CHANNEL_OPEN_FAILURE => {
                debug!("channel_open_failure");
                let channel_num = map_err!(ChannelId::decode(r))?;
                let reason = ChannelOpenFailure::from_u32(map_err!(u32::decode(r))?)
                    .unwrap_or(ChannelOpenFailure::Unknown);
                let description = map_err!(String::decode(r))?;
                let language_tag = map_err!(String::decode(r))?;
                map_err!(ensure_end(r))?;

                trace!("Channel open failure description: {description}");
                trace!("Channel open failure language tag: {language_tag}");

                if let Some(ref mut enc) = self.common.encrypted {
                    enc.channels.remove(&channel_num);
                }

                if let Some(channel_sender) = self.channels.remove(&channel_num) {
                    channel_sender
                        .send(ChannelMsg::OpenFailure(reason))
                        .await
                        .map_err(|_| crate::Error::SendError)?;
                }

                Ok(())
            }
            msg::REQUEST_SUCCESS => {
                trace!("Global Request Success");
                match self.open_global_requests.pop_front() {
                    Some(GlobalRequestResponse::Keepalive) => {
                        map_err!(ensure_end(r))?;
                        // ignore keepalives
                    }
                    Some(GlobalRequestResponse::Ping(return_channel)) => {
                        map_err!(ensure_end(r))?;
                        let _ = return_channel.send(());
                    }
                    Some(GlobalRequestResponse::TcpIpForward(return_channel)) => {
                        let result = if r.is_finished() {
                            // If a specific port was requested, the reply has no data
                            Some(0)
                        } else {
                            match u32::decode(r) {
                                Ok(port) => {
                                    if let Err(e) = ensure_end(r) {
                                        error!(
                                            "Error parsing port for TcpIpForward request: {e:?}"
                                        );
                                        None
                                    } else {
                                        Some(port)
                                    }
                                }
                                Err(e) => {
                                    error!("Error parsing port for TcpIpForward request: {e:?}");
                                    None
                                }
                            }
                        };
                        let _ = return_channel.send(result);
                    }
                    Some(GlobalRequestResponse::CancelTcpIpForward(return_channel)) => {
                        map_err!(ensure_end(r))?;
                        let _ = return_channel.send(true);
                    }
                    _ => {
                        error!("Received global request failure for unknown request!")
                    }
                }
                Ok(())
            }
            msg::REQUEST_FAILURE => {
                trace!("global request failure");
                map_err!(ensure_end(r))?;
                match self.open_global_requests.pop_front() {
                    Some(GlobalRequestResponse::Keepalive) => {
                        // ignore keepalives
                    }
                    Some(GlobalRequestResponse::Ping(return_channel)) => {
                        let _ = return_channel.send(());
                    }
                    Some(GlobalRequestResponse::TcpIpForward(return_channel)) => {
                        let _ = return_channel.send(None);
                    }
                    Some(GlobalRequestResponse::CancelTcpIpForward(return_channel)) => {
                        let _ = return_channel.send(false);
                    }
                    _ => {
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

    async fn server_handle_channel_open<H: Handler + Send, R: Reader>(
        &mut self,
        handler: &mut H,
        r: &mut R,
    ) -> Result<bool, H::Error> {
        let msg = OpenChannelMessage::parse(r)?;

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
            pending_eof: false,
            pending_close: false,
        };

        let (channel, reference) = Channel::new(
            sender_channel,
            self.sender.sender.clone(),
            channel_params.recipient_maximum_packet_size,
            channel_params.recipient_window_size,
            self.common.config.channel_buffer_size,
        );

        match &msg.typ {
            ChannelType::Session => {
                let mut result = handler.channel_open_session(channel, self).await;
                if let Ok(allowed) = &mut result {
                    self.channels.insert(sender_channel, reference);
                    self.finalize_channel_open(&msg, channel_params, *allowed)?;
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
                if let Ok(allowed) = &mut result {
                    self.channels.insert(sender_channel, reference);
                    self.finalize_channel_open(&msg, channel_params, *allowed)?;
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
                if let Ok(allowed) = &mut result {
                    self.channels.insert(sender_channel, reference);
                    self.finalize_channel_open(&msg, channel_params, *allowed)?;
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
                if let Ok(allowed) = &mut result {
                    self.channels.insert(sender_channel, reference);
                    self.finalize_channel_open(&msg, channel_params, *allowed)?;
                }
                result
            }
            ChannelType::DirectStreamLocal(d) => {
                let mut result = handler
                    .channel_open_direct_streamlocal(channel, &d.socket_path, self)
                    .await;
                if let Ok(allowed) = &mut result {
                    self.channels.insert(sender_channel, reference);
                    self.finalize_channel_open(&msg, channel_params, *allowed)?;
                }
                result
            }
            ChannelType::ForwardedStreamLocal(_) => {
                if let Some(ref mut enc) = self.common.encrypted {
                    msg.fail(
                        &mut enc.write,
                        msg::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        b"Unsupported channel type",
                    )?;
                }
                Ok(false)
            }
            ChannelType::AgentForward => {
                if let Some(ref mut enc) = self.common.encrypted {
                    msg.fail(
                        &mut enc.write,
                        msg::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                        b"Unsupported channel type",
                    )?;
                }
                Ok(false)
            }
            ChannelType::Unknown { typ } => {
                debug!("unknown channel type: {typ}");
                if let Some(ref mut enc) = self.common.encrypted {
                    msg.unknown_type(&mut enc.write)?;
                }
                Ok(false)
            }
        }
    }

    fn finalize_channel_open(
        &mut self,
        open: &OpenChannelMessage,
        channel: ChannelParams,
        allowed: bool,
    ) -> Result<(), Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if allowed {
                open.confirm(
                    &mut enc.write,
                    channel.sender_channel.0,
                    channel.sender_window_size,
                    channel.sender_maximum_packet_size,
                )?;
                enc.channels.insert(channel.sender_channel, channel);
            } else {
                open.fail(
                    &mut enc.write,
                    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
                    b"Rejected",
                )?;
            }
        }
        Ok(())
    }
}
