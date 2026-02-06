use ssh_encoding::{Decode, Error, Reader, Result, Writer};

use crate::CryptoVec;

impl Reader for CryptoVec {
    fn read<'o>(&mut self, out: &'o mut [u8]) -> Result<&'o [u8]> {
        (&self[..]).read(out)
    }

    fn remaining_len(&self) -> usize {
        self.len()
    }

    fn read_prefixed<T, E, F>(&mut self, f: F) -> std::result::Result<T, E>
    where
        E: From<Error>,
        F: FnOnce(&mut Self) -> std::result::Result<T, E>,
    {
        let mut slice = &self[..];
        let len = match u32::decode(&mut slice) {
            Ok(len) => len,
            Err(e) => return Err(e.into()),
        };
        if slice.len() < len as usize {
            return Err(Error::Length.into());
        }
        let sub_data = &slice[..len as usize];
        let mut sub = CryptoVec::from(sub_data);
        // Advance self
        let rest = self[4 + len as usize..].to_vec();
        self.clear();
        self.extend(rest.as_slice());
        f(&mut sub)
    }
}

impl Writer for CryptoVec {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.extend(bytes);
        Ok(())
    }
}
