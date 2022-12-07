// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
// Originally from microsoft/dev-tunnels

use std::task::Poll;

/// Helper used when converting Future interfaces to poll-based interfaces.
/// Stores excess data that can be reused on future polls.
#[derive(Default)]
pub(crate) struct ReadBuffer(Option<(Vec<u8>, usize)>);

impl ReadBuffer {
    /// Removes any data stored in the read buffer
    pub fn take_data(&mut self) -> Option<(Vec<u8>, usize)> {
        self.0.take()
    }

    /// Writes as many bytes as possible to the readbuf, stashing any extra.
    pub fn put_data(
        &mut self,
        target: &mut tokio::io::ReadBuf<'_>,
        bytes: Vec<u8>,
        start: usize,
    ) -> Poll<std::io::Result<()>> {
        if target.remaining() >= bytes.len() - start {
            if start < bytes.len() {
                #[allow(clippy::indexing_slicing)]
                target.put_slice(&bytes[start..]);
            }
            self.0 = None;
        } else {
            let end = start + target.remaining();
            if start < bytes.len() && end <= bytes.len() {
                #[allow(clippy::indexing_slicing)]
                target.put_slice(&bytes[start..end]);
            }
            self.0 = Some((bytes, end));
        }

        Poll::Ready(Ok(()))
    }
}
