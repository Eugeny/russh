use ssh_encoding::{Result, Writer};

use crate::CryptoVec;

impl Writer for CryptoVec {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend(bytes);
        Ok(())
    }
}
