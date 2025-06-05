use ssh_encoding::{Reader, Result, Writer};

use crate::CryptoVec;

impl Reader for CryptoVec {
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        (&self[..]).read(out)
    }

    fn remaining_len(&self) -> usize {
        self.len()
    }
}

impl Writer for CryptoVec {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend(bytes);
        Ok(())
    }
}
