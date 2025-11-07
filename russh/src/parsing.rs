use ssh_encoding::{Decode, Encode, Reader};

use crate::{msg, CryptoVec};

use crate::map_err;

#[derive(Debug)]
pub struct OpenChannelMessage {
    pub typ: ChannelType,
    pub recipient_channel: u32,
    pub recipient_window_size: u32,
    pub recipient_maximum_packet_size: u32,
}

impl OpenChannelMessage {
    pub fn parse<R: Reader>(r: &mut R) -> Result<Self, crate::Error> {
        // https://tools.ietf.org/html/rfc4254#section-5.1
        let typ = map_err!(String::decode(r))?;
        let sender = map_err!(u32::decode(r))?;
        let window = map_err!(u32::decode(r))?;
        let maxpacket = map_err!(u32::decode(r))?;

        let typ = match typ.as_str() {
            "session" => ChannelType::Session,
            "x11" => {
                let originator_address = map_err!(String::decode(r))?;
                let originator_port = map_err!(u32::decode(r))?;
                ChannelType::X11 {
                    originator_address,
                    originator_port,
                }
            }
            "direct-tcpip" => ChannelType::DirectTcpip(TcpChannelInfo::decode(r)?),
            "direct-streamlocal@openssh.com" => {
                ChannelType::DirectStreamLocal(StreamLocalChannelInfo::decode(r)?)
            }
            "forwarded-tcpip" => ChannelType::ForwardedTcpIp(TcpChannelInfo::decode(r)?),
            "forwarded-streamlocal@openssh.com" => {
                ChannelType::ForwardedStreamLocal(StreamLocalChannelInfo::decode(r)?)
            }
            "auth-agent@openssh.com" => ChannelType::AgentForward,
            _ => ChannelType::Unknown { typ },
        };

        Ok(Self {
            typ,
            recipient_channel: sender,
            recipient_window_size: window,
            recipient_maximum_packet_size: maxpacket,
        })
    }

    /// Pushes a confirmation that this channel was opened to the vec.
    pub fn confirm(
        &self,
        buffer: &mut CryptoVec,
        sender_channel: u32,
        window_size: u32,
        packet_size: u32,
    ) -> Result<(), crate::Error> {
        push_packet!(buffer, {
            msg::CHANNEL_OPEN_CONFIRMATION.encode(buffer)?;
            self.recipient_channel.encode(buffer)?; // remote channel number.
            sender_channel.encode(buffer)?; // our channel number.
            window_size.encode(buffer)?;
            packet_size.encode(buffer)?;
        });
        Ok(())
    }

    /// Pushes a failure message to the vec.
    pub fn fail(
        &self,
        buffer: &mut CryptoVec,
        reason: u8,
        message: &[u8],
    ) -> Result<(), crate::Error> {
        push_packet!(buffer, {
            msg::CHANNEL_OPEN_FAILURE.encode(buffer)?;
            self.recipient_channel.encode(buffer)?;
            (reason as u32).encode(buffer)?;
            message.encode(buffer)?;
            "en".encode(buffer)?;
        });
        Ok(())
    }

    /// Pushes an unknown type error to the vec.
    pub fn unknown_type(&self, buffer: &mut CryptoVec) -> Result<(), crate::Error> {
        self.fail(
            buffer,
            msg::SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
            b"Unknown channel type",
        )
    }
}

#[derive(Debug)]
pub enum ChannelType {
    Session,
    X11 {
        originator_address: String,
        originator_port: u32,
    },
    DirectTcpip(TcpChannelInfo),
    DirectStreamLocal(StreamLocalChannelInfo),
    ForwardedTcpIp(TcpChannelInfo),
    ForwardedStreamLocal(StreamLocalChannelInfo),
    AgentForward,
    Unknown {
        typ: String,
    },
}

#[derive(Debug)]
pub struct TcpChannelInfo {
    pub host_to_connect: String,
    pub port_to_connect: u32,
    pub originator_address: String,
    pub originator_port: u32,
}

#[derive(Debug)]
pub struct StreamLocalChannelInfo {
    pub socket_path: String,
}

impl Decode for StreamLocalChannelInfo {
    type Error = ssh_encoding::Error;

    fn decode(r: &mut impl Reader) -> Result<Self, Self::Error> {
        let socket_path = String::decode(r)?.to_owned();
        Ok(Self { socket_path })
    }
}

impl Decode for TcpChannelInfo {
    type Error = ssh_encoding::Error;

    fn decode(r: &mut impl Reader) -> Result<Self, Self::Error> {
        let host_to_connect = String::decode(r)?;
        let port_to_connect = u32::decode(r)?;
        let originator_address = String::decode(r)?;
        let originator_port = u32::decode(r)?;

        Ok(Self {
            host_to_connect,
            port_to_connect,
            originator_address,
            originator_port,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ChannelOpenConfirmation {
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u32,
}

impl Decode for ChannelOpenConfirmation {
    type Error = ssh_encoding::Error;

    fn decode(r: &mut impl Reader) -> Result<Self, Self::Error> {
        let recipient_channel = u32::decode(r)?;
        let sender_channel = u32::decode(r)?;
        let initial_window_size = u32::decode(r)?;
        let maximum_packet_size = u32::decode(r)?;

        Ok(Self {
            recipient_channel,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
        })
    }
}
