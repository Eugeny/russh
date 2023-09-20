use russh_cryptovec::CryptoVec;
use tokio::sync::mpsc::{Sender, UnboundedReceiver};
use log::debug;

use crate::{ChannelId, ChannelOpenFailure, ChannelStream, Error, Pty, Sig};

#[derive(Debug)]
#[non_exhaustive]
/// Possible messages that [Channel::wait] can receive.
pub enum ChannelMsg {
    Open {
        id: ChannelId,
        max_packet_size: u32,
        window_size: u32,
    },
    Data {
        data: CryptoVec,
    },
    ExtendedData {
        data: CryptoVec,
        ext: u32,
    },
    Eof,
    /// (client only)
    RequestPty {
        want_reply: bool,
        term: String,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        terminal_modes: Vec<(Pty, u32)>,
    },
    /// (client only)
    RequestShell {
        want_reply: bool,
    },
    /// (client only)
    Exec {
        want_reply: bool,
        command: Vec<u8>,
    },
    /// (client only)
    Signal {
        signal: Sig,
    },
    /// (client only)
    RequestSubsystem {
        want_reply: bool,
        name: String,
    },
    /// (client only)
    RequestX11 {
        want_reply: bool,
        single_connection: bool,
        x11_authentication_protocol: String,
        x11_authentication_cookie: String,
        x11_screen_number: u32,
    },
    /// (client only)
    SetEnv {
        want_reply: bool,
        variable_name: String,
        variable_value: String,
    },
    /// (client only)
    WindowChange {
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    },
    /// (client only)
    AgentForward {
        want_reply: bool,
    },

    /// (server only)
    XonXoff {
        client_can_do: bool,
    },
    /// (server only)
    ExitStatus {
        exit_status: u32,
    },
    /// (server only)
    ExitSignal {
        signal_name: Sig,
        core_dumped: bool,
        error_message: String,
        lang_tag: String,
    },
    /// (server only)
    WindowAdjusted {
        new_size: u32,
    },
    /// (server only)
    Success,
    /// (server only)
    Failure,
    /// (server only)
    Close,
    OpenFailure(ChannelOpenFailure),
}

/// A handle to a session channel.
///
/// Allows you to read and write from a channel without borrowing the session
pub struct Channel<Send: From<(ChannelId, ChannelMsg)>> {
    pub(crate) id: ChannelId,
    pub(crate) sender: Sender<Send>,
    pub(crate) receiver: UnboundedReceiver<ChannelMsg>,
    pub(crate) max_packet_size: u32,
    pub(crate) window_size: u32,
}

impl<T: From<(ChannelId, ChannelMsg)>> std::fmt::Debug for Channel<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel").field("id", &self.id).finish()
    }
}

impl<S: From<(ChannelId, ChannelMsg)> + Send + 'static> Channel<S> {
    pub fn id(&self) -> ChannelId {
        self.id
    }

    /// Returns the min between the maximum packet size and the
    /// remaining window size in the channel.
    pub fn writable_packet_size(&self) -> usize {
        self.max_packet_size.min(self.window_size) as usize
    }

    /// Request a pseudo-terminal with the given characteristics.
    #[allow(clippy::too_many_arguments)] // length checked
    pub async fn request_pty(
        &mut self,
        want_reply: bool,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        terminal_modes: &[(Pty, u32)],
    ) -> Result<(), Error> {
        self.send_msg(ChannelMsg::RequestPty {
            want_reply,
            term: term.to_string(),
            col_width,
            row_height,
            pix_width,
            pix_height,
            terminal_modes: terminal_modes.to_vec(),
        })
        .await?;
        Ok(())
    }

    /// Request a remote shell.
    pub async fn request_shell(&mut self, want_reply: bool) -> Result<(), Error> {
        self.send_msg(ChannelMsg::RequestShell { want_reply })
            .await?;
        Ok(())
    }

    /// Execute a remote program (will be passed to a shell). This can
    /// be used to implement scp (by calling a remote scp and
    /// tunneling to its standard input).
    pub async fn exec<A: Into<Vec<u8>>>(
        &mut self,
        want_reply: bool,
        command: A,
    ) -> Result<(), Error> {
        self.send_msg(ChannelMsg::Exec {
            want_reply,
            command: command.into(),
        })
        .await?;
        Ok(())
    }

    /// Signal a remote process.
    pub async fn signal(&mut self, signal: Sig) -> Result<(), Error> {
        self.send_msg(ChannelMsg::Signal { signal }).await?;
        Ok(())
    }

    /// Request the start of a subsystem with the given name.
    pub async fn request_subsystem<A: Into<String>>(
        &mut self,
        want_reply: bool,
        name: A,
    ) -> Result<(), Error> {
        self.send_msg(ChannelMsg::RequestSubsystem {
            want_reply,
            name: name.into(),
        })
        .await?;
        Ok(())
    }

    /// Request X11 forwarding through an already opened X11
    /// channel. See
    /// [RFC4254](https://tools.ietf.org/html/rfc4254#section-6.3.1)
    /// for security issues related to cookies.
    pub async fn request_x11<A: Into<String>, B: Into<String>>(
        &mut self,
        want_reply: bool,
        single_connection: bool,
        x11_authentication_protocol: A,
        x11_authentication_cookie: B,
        x11_screen_number: u32,
    ) -> Result<(), Error> {
        self.send_msg(ChannelMsg::RequestX11 {
            want_reply,
            single_connection,
            x11_authentication_protocol: x11_authentication_protocol.into(),
            x11_authentication_cookie: x11_authentication_cookie.into(),
            x11_screen_number,
        })
        .await?;
        Ok(())
    }

    /// Set a remote environment variable.
    pub async fn set_env<A: Into<String>, B: Into<String>>(
        &mut self,
        want_reply: bool,
        variable_name: A,
        variable_value: B,
    ) -> Result<(), Error> {
        self.send_msg(ChannelMsg::SetEnv {
            want_reply,
            variable_name: variable_name.into(),
            variable_value: variable_value.into(),
        })
        .await?;
        Ok(())
    }

    /// Inform the server that our window size has changed.
    pub async fn window_change(
        &mut self,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> Result<(), Error> {
        self.send_msg(ChannelMsg::WindowChange {
            col_width,
            row_height,
            pix_width,
            pix_height,
        })
        .await?;
        Ok(())
    }

    /// Inform the server that we will accept agent forwarding channels
    pub async fn agent_forward(&mut self, want_reply: bool) -> Result<(), Error> {
        self.send_msg(ChannelMsg::AgentForward { want_reply })
            .await?;
        Ok(())
    }

    /// Send data to a channel.
    pub async fn data<R: tokio::io::AsyncReadExt + Unpin>(&mut self, data: R) -> Result<(), Error> {
        self.send_data(None, data).await
    }

    /// Send data to a channel. The number of bytes added to the
    /// "sending pipeline" (to be processed by the event loop) is
    /// returned.
    pub async fn extended_data<R: tokio::io::AsyncReadExt + Unpin>(
        &mut self,
        ext: u32,
        data: R,
    ) -> Result<(), Error> {
        self.send_data(Some(ext), data).await
    }

    async fn send_data<R: tokio::io::AsyncReadExt + Unpin>(
        &mut self,
        ext: Option<u32>,
        mut data: R,
    ) -> Result<(), Error> {
        let mut total = 0;
        loop {
            // wait for the window to be restored.
            while self.window_size == 0 {
                match self.receiver.recv().await {
                    Some(ChannelMsg::WindowAdjusted { new_size }) => {
                        debug!("window adjusted: {:?}", new_size);
                        self.window_size = new_size;
                        break;
                    }
                    Some(msg) => {
                        debug!("unexpected channel msg: {:?}", msg);
                    }
                    None => break,
                }
            }
            debug!(
                "sending data, self.window_size = {:?}, self.max_packet_size = {:?}, total = {:?}",
                self.window_size, self.max_packet_size, total
            );
            let sendable = self.window_size.min(self.max_packet_size) as usize;

            debug!("sendable {:?}", sendable);

            // If we can not send anymore, continue
            // and wait for server window adjustment
            if sendable == 0 {
                continue;
            }

            let mut c = CryptoVec::new_zeroed(sendable);
            let n = data.read(&mut c[..]).await?;
            total += n;
            c.resize(n);
            self.window_size -= n as u32;
            self.send_data_packet(ext, c).await?;
            if n == 0 {
                break;
            } else if self.window_size > 0 {
                continue;
            }
        }
        Ok(())
    }

    async fn send_data_packet(&mut self, ext: Option<u32>, data: CryptoVec) -> Result<(), Error> {
        self.send_msg(if let Some(ext) = ext {
            ChannelMsg::ExtendedData { ext, data }
        } else {
            ChannelMsg::Data { data }
        })
        .await?;
        Ok(())
    }

    pub async fn eof(&mut self) -> Result<(), Error> {
        self.send_msg(ChannelMsg::Eof).await?;
        Ok(())
    }

    /// Wait for data to come.
    pub async fn wait(&mut self) -> Option<ChannelMsg> {
        match self.receiver.recv().await {
            Some(ChannelMsg::WindowAdjusted { new_size }) => {
                self.window_size = new_size;
                Some(ChannelMsg::WindowAdjusted { new_size })
            }
            Some(msg) => Some(msg),
            None => None,
        }
    }

    async fn send_msg(&self, msg: ChannelMsg) -> Result<(), Error> {
        self.sender
            .send((self.id, msg).into())
            .await
            .map_err(|_| Error::SendError)
    }

    /// Request that the channel be closed.
    pub async fn close(&self) -> Result<(), Error> {
        self.send_msg(ChannelMsg::Close).await?;
        Ok(())
    }

    pub fn into_stream(mut self) -> ChannelStream {
        let (stream, mut r_rx, w_tx) = ChannelStream::new();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    data = r_rx.recv() => {
                        match data {
                            Some(data) if !data.is_empty() => self.data(&data[..]).await?,
                            Some(_) => {
                                log::debug!("closing chan {:?}, received empty data", &self.id);
                                self.eof().await?;
                                self.close().await?;
                                break;
                            },
                            None => {
                                self.close().await?;
                                break
                            }
                        }
                    },
                    msg = self.wait() => {
                        match msg {
                            Some(ChannelMsg::Data { data }) => {
                                w_tx.send(data[..].into()).map_err(|_| crate::Error::SendError)?;
                            }
                            Some(ChannelMsg::Eof) => {
                                // Send a 0-length chunk to indicate EOF.
                                w_tx.send("".into()).map_err(|_| crate::Error::SendError)?;
                                break
                            }
                            None => break,
                            _ => (),
                        }
                    }
                }
            }
            Ok::<_, crate::Error>(())
        });
        stream
    }
}
