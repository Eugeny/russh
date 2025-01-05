use log::error;
use russh_keys::map_err;
use ssh_encoding::Encode;
use tokio::sync::oneshot;

use crate::client::Session;
use crate::session::EncryptedState;
use crate::{msg, ChannelId, CryptoVec, Disconnect, Pty, Sig};

impl Session {
    fn channel_open_generic<F>(
        &mut self,
        kind: &[u8],
        write_suffix: F,
    ) -> Result<ChannelId, crate::Error>
    where
        F: FnOnce(&mut CryptoVec) -> Result<(), crate::Error>,
    {
        let result = if let Some(ref mut enc) = self.common.encrypted {
            match enc.state {
                EncryptedState::Authenticated => {
                    let sender_channel = enc.new_channel(
                        self.common.config.window_size,
                        self.common.config.maximum_packet_size,
                    );
                    push_packet!(enc.write, {
                        msg::CHANNEL_OPEN.encode(&mut enc.write)?;
                        kind.encode(&mut enc.write)?;

                        // sender channel id.
                        sender_channel.encode(&mut enc.write)?;

                        // window.
                        self.common
                            .config
                            .as_ref()
                            .window_size
                            .encode(&mut enc.write)?;

                        // max packet size.
                        self.common
                            .config
                            .as_ref()
                            .maximum_packet_size
                            .encode(&mut enc.write)?;

                        write_suffix(&mut enc.write)?;
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
        self.channel_open_generic(b"session", |_| Ok(()))
    }

    pub fn channel_open_x11(
        &mut self,
        originator_address: &str,
        originator_port: u32,
    ) -> Result<ChannelId, crate::Error> {
        self.channel_open_generic(b"x11", |write| {
            map_err!(originator_address.encode(write))?;
            map_err!(originator_port.encode(write))?; // sender channel id.
            Ok(())
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
            host_to_connect.encode(write)?;
            port_to_connect.encode(write)?; // sender channel id.
            originator_address.encode(write)?;
            originator_port.encode(write)?; // sender channel id.
            Ok(())
        })
    }

    pub fn channel_open_direct_streamlocal(
        &mut self,
        socket_path: &str,
    ) -> Result<ChannelId, crate::Error> {
        self.channel_open_generic(b"direct-streamlocal@openssh.com", |write| {
            socket_path.encode(write)?;
            "".encode(write)?; // reserved
            0u32.encode(write)?; // reserved
            Ok(())
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
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    map_err!(msg::CHANNEL_REQUEST.encode(&mut enc.write))?;

                    channel.recipient_channel.encode(&mut enc.write)?;
                    "pty-req".encode(&mut enc.write)?;
                    (want_reply as u8).encode(&mut enc.write)?;

                    term.encode(&mut enc.write)?;
                    col_width.encode(&mut enc.write)?;
                    row_height.encode(&mut enc.write)?;
                    pix_width.encode(&mut enc.write)?;
                    pix_height.encode(&mut enc.write)?;

                    ((1 + 5 * terminal_modes.len()) as u32).encode(&mut enc.write)?;
                    for &(code, value) in terminal_modes {
                        (code as u8).encode(&mut enc.write)?;
                        value.encode(&mut enc.write)?;
                    }
                    // 0 code (to terminate the list)
                    0u8.encode(&mut enc.write)?;
                });
            }
        }
        Ok(())
    }

    pub fn request_x11(
        &mut self,
        channel: ChannelId,
        want_reply: bool,
        single_connection: bool,
        x11_authentication_protocol: &str,
        x11_authentication_cookie: &str,
        x11_screen_number: u32,
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    msg::CHANNEL_REQUEST.encode(&mut enc.write)?;

                    channel.recipient_channel.encode(&mut enc.write)?;
                    "x11-req".encode(&mut enc.write)?;
                    enc.write.push(want_reply as u8);
                    enc.write.push(single_connection as u8);
                    x11_authentication_protocol.encode(&mut enc.write)?;
                    x11_authentication_cookie.encode(&mut enc.write)?;
                    x11_screen_number.encode(&mut enc.write)?;
                });
            }
        }
        Ok(())
    }

    pub fn set_env(
        &mut self,
        channel: ChannelId,
        want_reply: bool,
        variable_name: &str,
        variable_value: &str,
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    msg::CHANNEL_REQUEST.encode(&mut enc.write)?;

                    channel.recipient_channel.encode(&mut enc.write)?;
                    "env".encode(&mut enc.write)?;
                    (want_reply as u8).encode(&mut enc.write)?;
                    variable_name.encode(&mut enc.write)?;
                    variable_value.encode(&mut enc.write)?;
                });
            }
        }
        Ok(())
    }

    pub fn request_shell(
        &mut self,
        want_reply: bool,
        channel: ChannelId,
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    msg::CHANNEL_REQUEST.encode(&mut enc.write)?;

                    channel.recipient_channel.encode(&mut enc.write)?;
                    "shell".encode(&mut enc.write)?;
                    (want_reply as u8).encode(&mut enc.write)?;
                });
            }
        }
        Ok(())
    }

    pub fn exec(
        &mut self,
        channel: ChannelId,
        want_reply: bool,
        command: &[u8],
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    msg::CHANNEL_REQUEST.encode(&mut enc.write)?;

                    channel.recipient_channel.encode(&mut enc.write)?;
                    "exec".encode(&mut enc.write)?;
                    (want_reply as u8).encode(&mut enc.write)?;
                    command.encode(&mut enc.write)?;
                });
                return Ok(());
            }
        }
        error!("exec");
        Ok(())
    }

    pub fn signal(&mut self, channel: ChannelId, signal: Sig) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    msg::CHANNEL_REQUEST.encode(&mut enc.write)?;
                    channel.recipient_channel.encode(&mut enc.write)?;
                    "signal".encode(&mut enc.write)?;
                    0u8.encode(&mut enc.write)?;
                    signal.name().encode(&mut enc.write)?;
                });
            }
        }
        Ok(())
    }

    pub fn request_subsystem(
        &mut self,
        want_reply: bool,
        channel: ChannelId,
        name: &str,
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    msg::CHANNEL_REQUEST.encode(&mut enc.write)?;

                    channel.recipient_channel.encode(&mut enc.write)?;
                    "subsystem".encode(&mut enc.write)?;
                    (want_reply as u8).encode(&mut enc.write)?;
                    name.encode(&mut enc.write)?;
                });
            }
        }
        Ok(())
    }

    pub fn window_change(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    msg::CHANNEL_REQUEST.encode(&mut enc.write)?;

                    channel.recipient_channel.encode(&mut enc.write)?;
                    "window-change".encode(&mut enc.write)?;
                    0u8.encode(&mut enc.write)?;
                    col_width.encode(&mut enc.write)?;
                    row_height.encode(&mut enc.write)?;
                    pix_width.encode(&mut enc.write)?;
                    pix_height.encode(&mut enc.write)?;
                });
            }
        }
        Ok(())
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
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let want_reply = reply_channel.is_some();
            if let Some(reply_channel) = reply_channel {
                self.open_global_requests.push_back(
                    crate::session::GlobalRequestResponse::TcpIpForward(reply_channel),
                );
            }
            push_packet!(enc.write, {
                msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
                "tcpip-forward".encode(&mut enc.write)?;
                (want_reply as u8).encode(&mut enc.write)?;
                address.encode(&mut enc.write)?;
                port.encode(&mut enc.write)?;
            });
        }
        Ok(())
    }

    /// Requests cancellation of TCP/IP forwarding from the server
    ///
    /// If `reply_channel` is not None, sets want_reply and returns the server's response via the channel,
    /// `true` for a success message, or `false` for failure
    pub fn cancel_tcpip_forward(
        &mut self,
        reply_channel: Option<oneshot::Sender<bool>>,
        address: &str,
        port: u32,
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let want_reply = reply_channel.is_some();
            if let Some(reply_channel) = reply_channel {
                self.open_global_requests.push_back(
                    crate::session::GlobalRequestResponse::CancelTcpIpForward(reply_channel),
                );
            }
            push_packet!(enc.write, {
                msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
                "cancel-tcpip-forward".encode(&mut enc.write)?;
                (want_reply as u8).encode(&mut enc.write)?;
                address.encode(&mut enc.write)?;
                port.encode(&mut enc.write)?;
            });
        }
        Ok(())
    }

    /// Requests a UDS forwarding from the server, `socket path` being the server side socket path.
    ///
    /// If `reply_channel` is not None, sets want_reply and returns the server's response via the channel,
    /// `true` for a success message, or `false` for failure
    pub fn streamlocal_forward(
        &mut self,
        reply_channel: Option<oneshot::Sender<bool>>,
        socket_path: &str,
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let want_reply = reply_channel.is_some();
            if let Some(reply_channel) = reply_channel {
                self.open_global_requests.push_back(
                    crate::session::GlobalRequestResponse::StreamLocalForward(reply_channel),
                );
            }
            push_packet!(enc.write, {
                msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
                "streamlocal-forward@openssh.com".encode(&mut enc.write)?;
                (want_reply as u8).encode(&mut enc.write)?;
                socket_path.encode(&mut enc.write)?;
            });
        }
        Ok(())
    }

    /// Requests cancellation of UDS forwarding from the server
    ///
    /// If `reply_channel` is not None, sets want_reply and returns the server's response via the channel,
    /// `true` for a success message and `false` for failure.
    pub fn cancel_streamlocal_forward(
        &mut self,
        reply_channel: Option<oneshot::Sender<bool>>,
        socket_path: &str,
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            let want_reply = reply_channel.is_some();
            if let Some(reply_channel) = reply_channel {
                self.open_global_requests.push_back(
                    crate::session::GlobalRequestResponse::CancelStreamLocalForward(reply_channel),
                );
            }
            push_packet!(enc.write, {
                msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
                "cancel-streamlocal-forward@openssh.com".encode(&mut enc.write)?;
                (want_reply as u8).encode(&mut enc.write)?;
                socket_path.encode(&mut enc.write)?;
            });
        }
        Ok(())
    }

    pub fn send_keepalive(&mut self, want_reply: bool) -> Result<(), crate::Error> {
        self.open_global_requests
            .push_back(crate::session::GlobalRequestResponse::Keepalive);
        if let Some(ref mut enc) = self.common.encrypted {
            push_packet!(enc.write, {
                msg::GLOBAL_REQUEST.encode(&mut enc.write)?;
                "keepalive@openssh.com".encode(&mut enc.write)?;
                (want_reply as u8).encode(&mut enc.write)?;
            });
        }
        Ok(())
    }

    pub fn data(&mut self, channel: ChannelId, data: CryptoVec) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.data(channel, data, self.kex.active())
        } else {
            unreachable!()
        }
    }

    pub fn eof(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.eof(channel)
        } else {
            unreachable!()
        }
    }

    pub fn close(&mut self, channel: ChannelId) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.close(channel)
        } else {
            unreachable!()
        }
    }

    pub fn extended_data(
        &mut self,
        channel: ChannelId,
        ext: u32,
        data: CryptoVec,
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            enc.extended_data(channel, ext, data, self.kex.active())
        } else {
            unreachable!()
        }
    }

    pub fn agent_forward(
        &mut self,
        channel: ChannelId,
        want_reply: bool,
    ) -> Result<(), crate::Error> {
        if let Some(ref mut enc) = self.common.encrypted {
            if let Some(channel) = enc.channels.get(&channel) {
                push_packet!(enc.write, {
                    msg::CHANNEL_REQUEST.encode(&mut enc.write)?;
                    channel.recipient_channel.encode(&mut enc.write)?;
                    "auth-agent-req@openssh.com".encode(&mut enc.write)?;
                    (want_reply as u8).encode(&mut enc.write)?;
                });
            }
        }
        Ok(())
    }

    pub fn disconnect(
        &mut self,
        reason: Disconnect,
        description: &str,
        language_tag: &str,
    ) -> Result<(), crate::Error> {
        self.common.disconnect(reason, description, language_tag)
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
