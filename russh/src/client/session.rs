use log::error;
use russh_cryptovec::CryptoVec;
use russh_keys::encoding::Encoding;
use tokio::sync::oneshot;

use crate::client::Session;
use crate::session::EncryptedState;
use crate::{msg, ChannelId, Disconnect, Pty, Sig};

impl Session {
    fn channel_open_generic<F>(
        &mut self,
        kind: &[u8],
        write_suffix: F,
    ) -> Result<ChannelId, crate::Error>
    where
        F: FnOnce(&mut CryptoVec),
    {
        let result = if let Some(ref mut enc) = self.common.encrypted {
            match enc.state {
                EncryptedState::Authenticated => {
                    let sender_channel = enc.new_channel(
                        self.common.config.window_size,
                        self.common.config.maximum_packet_size,
                    );
                    push_packet!(enc.write, {
                        enc.write.push(msg::CHANNEL_OPEN);
                        enc.write.extend_ssh_string(kind);

                        // sender channel id.
                        enc.write.push_u32_be(sender_channel.0);

                        // window.
                        enc.write
                            .push_u32_be(self.common.config.as_ref().window_size);

                        // max packet size.
                        enc.write
                            .push_u32_be(self.common.config.as_ref().maximum_packet_size);

                        write_suffix(&mut enc.write);
                    });
                    sender_channel
                }
                _ => return Err(crate::Error::NotAuthenticated),
            }
        } else {
            return Err(crate::Error::Inconsistent);
        };
        Ok(result)
    }

    pub fn channel_open_session(&mut self) -> Result<ChannelId, crate::Error> {
        self.channel_open_generic(b"session", |_| ())
    }

    pub fn channel_open_x11(
        &mut self,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, crate::Error> {
        self.channel_open_generic(b"x11", |write| {
            write.extend_ssh_string(originator_address.as_bytes());
            write.push_u32_be(originator_port); // sender channel id.
        })
    }

    pub fn channel_open_direct_tcpip(
        &mut self,
        host_to_connect: &str,
        port_to_connect: u32,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, crate::Error> {
        self.channel_open_generic(b"direct-tcpip", |write| {
            write.extend_ssh_string(host_to_connect.as_bytes());
            write.push_u32_be(port_to_connect); // sender channel id.
            write.extend_ssh_string(originator_address.as_bytes());
            write.push_u32_be(originator_port); // sender channel id.
        })
    }

    pub fn channel_open_direct_streamlocal(
        &mut self,
        socket_path: &str,
    ) -> Result<ChannelId, crate::Error> {
        self.channel_open_generic(b"direct-streamlocal@openssh.com", |write| {
            write.extend_ssh_string(socket_path.as_bytes());
            write.extend_ssh_string("".as_bytes()); // reserved
            write.push_u32_be(0); // reserved
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn request_pty(
        &mut self,
        channel: ChannelId,
        want_reply: bool,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        terminal_modes: &[(Pty, u32)],
    ) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"pty-req");
                    enc.write.push(want_reply as u8);

                    enc.write.extend_ssh_string(term.as_bytes());
                    enc.write.push_u32_be(col_width);
                    enc.write.push_u32_be(row_height);
                    enc.write.push_u32_be(pix_width);
                    enc.write.push_u32_be(pix_height);

                    enc.write.push_u32_be((1 + 5 * terminal_modes.len()) as u32);
                    for &(code, value) in terminal_modes {
                        enc.write.push(code as u8);
                        enc.write.push_u32_be(value)
                    }
                    // 0 code (to terminate the list)
                    enc.write.push(0);
                });
            }
        }
    }

    pub fn request_x11(
        &mut self,
        channel: ChannelId,
        want_reply: bool,
        single_connection: bool,
        x11_authentication_protocol: &str,
        x11_authentication_cookie: &str,
        x11_screen_number: u32,
    ) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"x11-req");
                    enc.write.push(want_reply as u8);
                    enc.write.push(single_connection as u8);
                    enc.write
                        .extend_ssh_string(x11_authentication_protocol.as_bytes());
                    enc.write
                        .extend_ssh_string(x11_authentication_cookie.as_bytes());
                    enc.write.push_u32_be(x11_screen_number);
                });
            }
        }
    }

    pub fn set_env(
        &mut self,
        channel: ChannelId,
        want_reply: bool,
        variable_name: &str,
        variable_value: &str,
    ) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"env");
                    enc.write.push(want_reply as u8);
                    enc.write.extend_ssh_string(variable_name.as_bytes());
                    enc.write.extend_ssh_string(variable_value.as_bytes());
                });
            }
        }
    }

    pub fn request_shell(&mut self, want_reply: bool, channel: ChannelId) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"shell");
                    enc.write.push(want_reply as u8);
                });
            }
        }
    }

    pub fn exec(&mut self, channel: ChannelId, want_reply: bool, command: &[u8]) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"exec");
                    enc.write.push(want_reply as u8);
                    enc.write.extend_ssh_string(command);
                });
                return;
            }
        }
        error!("exec");
    }

    pub fn signal(&mut self, channel: ChannelId, signal: Sig) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);
                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"signal");
                    enc.write.push(0);
                    enc.write.extend_ssh_string(signal.name().as_bytes());
                });
            }
        }
    }

    pub fn request_subsystem(&mut self, want_reply: bool, channel: ChannelId, name: &str) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"subsystem");
                    enc.write.push(want_reply as u8);
                    enc.write.extend_ssh_string(name.as_bytes());
                });
            }
        }
    }

    pub fn window_change(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);

                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"window-change");
                    enc.write.push(0); // this packet never wants reply
                    enc.write.push_u32_be(col_width);
                    enc.write.push_u32_be(row_height);
                    enc.write.push_u32_be(pix_width);
                    enc.write.push_u32_be(pix_height);
                });
            }
        }
    }

    /// Requests a TCP/IP forwarding from the server
    ///
    /// If `reply_channel` is not None, sets want_reply and returns the server's response via the channel,
    /// [`Some<u32>`] for a success message with port, or [`None`] for failure
    pub fn tcpip_forward(
        &mut self,
        reply_channel: Option<oneshot::Sender<Option<u32>>>,
        address: &str,
        port: u32,
    ) {
        if let Some(ref mut enc) = self.common.encrypted {
            let want_reply = reply_channel.is_some();
            if let Some(reply_channel) = reply_channel {
                self.open_global_requests.push_back(
                    crate::session::GlobalRequestResponse::TcpIpForward(reply_channel),
                );
            }
            push_packet!(enc.write, {
                enc.write.push(msg::GLOBAL_REQUEST);
                enc.write.extend_ssh_string(b"tcpip-forward");
                enc.write.push(want_reply as u8);
                enc.write.extend_ssh_string(address.as_bytes());
                enc.write.push_u32_be(port);
            });
        }
    }

    /// Requests cancellation of TCP/IP forwarding from the server
    ///
    /// If `want_reply` is `true`, returns a oneshot receiveing the server's reply:
    /// `true` for a success message, or `false` for failure
    pub fn cancel_tcpip_forward(
        &mut self,
        reply_channel: Option<oneshot::Sender<bool>>,
        address: &str,
        port: u32,
    ) {
        if let Some(ref mut enc) = self.common.encrypted {
            let want_reply = reply_channel.is_some();
            if let Some(reply_channel) = reply_channel {
                self.open_global_requests.push_back(
                    crate::session::GlobalRequestResponse::CancelTcpIpForward(reply_channel),
                );
            }
            push_packet!(enc.write, {
                enc.write.push(msg::GLOBAL_REQUEST);
                enc.write.extend_ssh_string(b"cancel-tcpip-forward");
                enc.write.push(want_reply as u8);
                enc.write.extend_ssh_string(address.as_bytes());
                enc.write.push_u32_be(port);
            });
        }
    }

    pub fn send_keepalive(&mut self, want_reply: bool) {
        self.open_global_requests
            .push_back(crate::session::GlobalRequestResponse::Keepalive);
        if let Some(ref mut enc) = self.common.encrypted {
            push_packet!(enc.write, {
                enc.write.push(msg::GLOBAL_REQUEST);
                enc.write.extend_ssh_string(b"keepalive@openssh.com");
                enc.write.push(want_reply as u8);
            });
        }
    }

    pub fn data(&mut self, channel: ChannelId, data: CryptoVec) {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.data(channel, data)
        } else {
            unreachable!()
        }
    }

    pub fn eof(&mut self, channel: ChannelId) {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.eof(channel)
        } else {
            unreachable!()
        }
    }

    pub fn close(&mut self, channel: ChannelId) {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.close(channel)
        } else {
            unreachable!()
        }
    }

    pub fn extended_data(&mut self, channel: ChannelId, ext: u32, data: CryptoVec) {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.extended_data(channel, ext, data)
        } else {
            unreachable!()
        }
    }

    pub fn agent_forward(&mut self, channel: ChannelId, want_reply: bool) {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    enc.write.push(msg::CHANNEL_REQUEST);
                    enc.write.push_u32_be(channel.recipient_channel);
                    enc.write.extend_ssh_string(b"auth-agent-req@openssh.com");
                    enc.write.push(want_reply as u8);
                });
            }
        }
    }

    pub fn disconnect(&mut self, reason: Disconnect, description: &str, language_tag: &str) {
        self.common.disconnect(reason, description, language_tag);
    }

    pub fn has_pending_data(&self, channel: ChannelId) -> bool {
        if let Some(ref enc) = self.common.encrypted {
            enc.has_pending_data(channel)
        } else {
            false
        }
    }

    pub fn sender_window_size(&self, channel: ChannelId) -> usize {
        if let Some(ref enc) = self.common.encrypted {
            enc.sender_window_size(channel)
        } else {
            0
        }
    }

    /// Returns the SSH ID (Protocol Version + Software Version) the server sent when connecting
    ///
    /// This should contain only ASCII characters for implementations conforming to RFC4253, Section 4.2:
    ///
    /// > Both the 'protoversion' and 'softwareversion' strings MUST consist of
    /// > printable US-ASCII characters, with the exception of whitespace
    /// > characters and the minus sign (-).
    ///
    /// So it usually is fine to convert it to a `String` using `String::from_utf8_lossy`
    pub fn remote_sshid(&self) -> &[u8] {
        &self.common.remote_sshid
    }
}
