use super::*;
use russh_cryptovec::CryptoVec;
use russh_keys::encoding::{Encoding, Position};

#[derive(Debug)]
pub struct OpenChannelMessage {
    pub typ: ChannelType,
    pub recipient_channel: u32,
    pub recipient_window_size: u32,
    pub recipient_maximum_packet_size: u32,
}

impl OpenChannelMessage {
    pub fn parse(r: &mut Position) -> Result<Self, crate::Error> {
        // https://tools.ietf.org/html/rfc4254#section-5.1
        let typ = r.read_string().map_err(crate::Error::from)?;
        let sender = r.read_u32().map_err(crate::Error::from)?;
        let window = r.read_u32().map_err(crate::Error::from)?;
        let maxpacket = r.read_u32().map_err(crate::Error::from)?;

        let typ = match typ {
            b"session" => ChannelType::Session,
            b"x11" => {
                let originator_address =
                    std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
                        .map_err(crate::Error::from)?
                        .to_owned();
                let originator_port = r.read_u32().map_err(crate::Error::from)?;
                ChannelType::X11 {
                    originator_address,
                    originator_port,
                }
            }
            b"direct-tcpip" => ChannelType::DirectTcpip(TcpChannelInfo::new(r)?),
            b"forwarded-tcpip" => ChannelType::ForwardedTcpIp(TcpChannelInfo::new(r)?),
            t => ChannelType::Unknown { typ: t.to_vec() },
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
    ) {
        push_packet!(buffer, {
            buffer.push(msg::CHANNEL_OPEN_CONFIRMATION);
            buffer.push_u32_be(self.recipient_channel); // remote channel number.
            buffer.push_u32_be(sender_channel); // our channel number.
            buffer.push_u32_be(window_size);
            buffer.push_u32_be(packet_size);
        });
    }

    /// Pushes an unknown type error to the vec.
    pub fn unknown_type(&self, buffer: &mut CryptoVec) {
        push_packet!(buffer, {
            buffer.push(msg::CHANNEL_OPEN_FAILURE);
            buffer.push_u32_be(self.recipient_channel);
            buffer.push_u32_be(3); // SSH_OPEN_UNKNOWN_CHANNEL_TYPE
            buffer.extend_ssh_string(b"Unknown channel type");
            buffer.extend_ssh_string(b"en");
        });
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
    ForwardedTcpIp(TcpChannelInfo),
    Unknown {
        typ: Vec<u8>,
    },
}

#[derive(Debug)]
pub struct TcpChannelInfo {
    pub host_to_connect: String,
    pub port_to_connect: u32,
    pub originator_address: String,
    pub originator_port: u32,
}

impl TcpChannelInfo {
    fn new(r: &mut Position) -> Result<Self, crate::Error> {
        let host_to_connect = std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
            .map_err(crate::Error::from)?
            .to_owned();
        let port_to_connect = r.read_u32().map_err(crate::Error::from)?;
        let originator_address = std::str::from_utf8(r.read_string().map_err(crate::Error::from)?)
            .map_err(crate::Error::from)?
            .to_owned();
        let originator_port = r.read_u32().map_err(crate::Error::from)?;

        Ok(Self {
            host_to_connect,
            port_to_connect,
            originator_address,
            originator_port,
        })
    }
}
