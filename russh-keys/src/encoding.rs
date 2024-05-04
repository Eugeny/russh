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

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use russh_cryptovec::CryptoVec;

use crate::Error;

#[doc(hidden)]
pub trait Bytes {
    fn bytes(&self) -> &[u8];
}

impl<A: AsRef<str>> Bytes for A {
    fn bytes(&self) -> &[u8] {
        self.as_ref().as_bytes()
    }
}

/// Encode in the SSH format.
pub trait Encoding {
    /// Push an SSH-encoded string to `self`.
    fn extend_ssh_string(&mut self, s: &[u8]);
    /// Push an SSH-encoded blank string of length `s` to `self`.
    fn extend_ssh_string_blank(&mut self, s: usize) -> &mut [u8];
    /// Push an SSH-encoded multiple-precision integer.
    fn extend_ssh_mpint(&mut self, s: &[u8]);
    /// Push an SSH-encoded list.
    fn extend_list<A: Bytes, I: Iterator<Item = A>>(&mut self, list: I);
    /// Push an SSH-encoded empty list.
    fn write_empty_list(&mut self);
    /// Push an SSH-encoded value.
    fn extend_ssh<T: SshWrite>(&mut self, v: &T) {
        v.write_ssh(self)
    }
    /// Push a nested SSH-encoded value.
    fn extend_wrapped<F>(&mut self, write: F)
    where
        F: FnOnce(&mut Self);
}

/// Trait for writing value in SSH-encoded format.
pub trait SshWrite {
    /// Write the value.
    fn write_ssh<E: Encoding + ?Sized>(&self, encoder: &mut E);
}

/// Encoding length of the given mpint.
#[allow(clippy::indexing_slicing)]
pub fn mpint_len(s: &[u8]) -> usize {
    let mut i = 0;
    while i < s.len() && s[i] == 0 {
        i += 1
    }
    (if s[i] & 0x80 != 0 { 5 } else { 4 }) + s.len() - i
}

impl Encoding for Vec<u8> {
    #[allow(clippy::unwrap_used)] // writing into Vec<> can't panic
    fn extend_ssh_string(&mut self, s: &[u8]) {
        self.write_u32::<BigEndian>(s.len() as u32).unwrap();
        self.extend(s);
    }

    #[allow(clippy::unwrap_used)] // writing into Vec<> can't panic
    fn extend_ssh_string_blank(&mut self, len: usize) -> &mut [u8] {
        self.write_u32::<BigEndian>(len as u32).unwrap();
        let current = self.len();
        self.resize(current + len, 0u8);
        #[allow(clippy::indexing_slicing)] // length is known
        &mut self[current..]
    }

    #[allow(clippy::unwrap_used)] // writing into Vec<> can't panic
    #[allow(clippy::indexing_slicing)] // length is known
    fn extend_ssh_mpint(&mut self, s: &[u8]) {
        // Skip initial 0s.
        let mut i = 0;
        while i < s.len() && s[i] == 0 {
            i += 1
        }
        // If the first non-zero is >= 128, write its length (u32, BE), followed by 0.
        if s[i] & 0x80 != 0 {
            self.write_u32::<BigEndian>((s.len() - i + 1) as u32)
                .unwrap();
            self.push(0)
        } else {
            self.write_u32::<BigEndian>((s.len() - i) as u32).unwrap();
        }
        self.extend(&s[i..]);
    }

    #[allow(clippy::indexing_slicing)] // length is known
    fn extend_list<A: Bytes, I: Iterator<Item = A>>(&mut self, list: I) {
        let len0 = self.len();
        self.extend([0, 0, 0, 0]);
        let mut first = true;
        for i in list {
            if !first {
                self.push(b',')
            } else {
                first = false;
            }
            self.extend(i.bytes())
        }
        let len = (self.len() - len0 - 4) as u32;

        BigEndian::write_u32(&mut self[len0..], len);
    }

    fn write_empty_list(&mut self) {
        self.extend([0, 0, 0, 0]);
    }

    fn extend_wrapped<F>(&mut self, write: F)
    where
        F: FnOnce(&mut Self),
    {
        let len_offset = self.len();
        #[allow(clippy::unwrap_used)] // writing into Vec<> can't panic
        self.write_u32::<BigEndian>(0).unwrap();
        let data_offset = self.len();
        write(self);
        let data_len = self.len() - data_offset;
        #[allow(clippy::indexing_slicing)] // length is known
        BigEndian::write_u32(&mut self[len_offset..], data_len as u32);
    }
}

impl Encoding for CryptoVec {
    fn extend_ssh_string(&mut self, s: &[u8]) {
        self.push_u32_be(s.len() as u32);
        self.extend(s);
    }

    #[allow(clippy::indexing_slicing)] // length is known
    fn extend_ssh_string_blank(&mut self, len: usize) -> &mut [u8] {
        self.push_u32_be(len as u32);
        let current = self.len();
        self.resize(current + len);
        &mut self[current..]
    }

    #[allow(clippy::indexing_slicing)] // length is known
    fn extend_ssh_mpint(&mut self, s: &[u8]) {
        // Skip initial 0s.
        let mut i = 0;
        while i < s.len() && s[i] == 0 {
            i += 1
        }
        // If the first non-zero is >= 128, write its length (u32, BE), followed by 0.
        if s[i] & 0x80 != 0 {
            self.push_u32_be((s.len() - i + 1) as u32);
            self.push(0)
        } else {
            self.push_u32_be((s.len() - i) as u32);
        }
        self.extend(&s[i..]);
    }

    fn extend_list<A: Bytes, I: Iterator<Item = A>>(&mut self, list: I) {
        let len0 = self.len();
        self.extend(&[0, 0, 0, 0]);
        let mut first = true;
        for i in list {
            if !first {
                self.push(b',')
            } else {
                first = false;
            }
            self.extend(i.bytes())
        }
        let len = (self.len() - len0 - 4) as u32;

        #[allow(clippy::indexing_slicing)] // length is known
        BigEndian::write_u32(&mut self[len0..], len);
    }

    fn write_empty_list(&mut self) {
        self.extend(&[0, 0, 0, 0]);
    }

    fn extend_wrapped<F>(&mut self, write: F)
    where
        F: FnOnce(&mut Self),
    {
        let len_offset = self.len();
        self.push_u32_be(0);
        let data_offset = self.len();
        write(self);
        let data_len = self.len() - data_offset;
        #[allow(clippy::indexing_slicing)] // length is known
        BigEndian::write_u32(&mut self[len_offset..], data_len as u32);
    }
}

/// A cursor-like trait to read SSH-encoded things.
pub trait Reader {
    /// Create an SSH reader for `self`.
    fn reader(&self, starting_at: usize) -> Position;
}

impl Reader for CryptoVec {
    fn reader(&self, starting_at: usize) -> Position {
        Position {
            s: self,
            position: starting_at,
        }
    }
}

impl Reader for [u8] {
    fn reader(&self, starting_at: usize) -> Position {
        Position {
            s: self,
            position: starting_at,
        }
    }
}

/// A cursor-like type to read SSH-encoded values.
#[derive(Debug)]
pub struct Position<'a> {
    s: &'a [u8],
    #[doc(hidden)]
    pub position: usize,
}
impl<'a> Position<'a> {
    /// Read one string from this reader.
    pub fn read_string(&mut self) -> Result<&'a [u8], Error> {
        let len = self.read_u32()? as usize;
        if self.position + len <= self.s.len() {
            #[allow(clippy::indexing_slicing)] // length is known
            let result = &self.s[self.position..(self.position + len)];
            self.position += len;
            Ok(result)
        } else {
            Err(Error::IndexOutOfBounds)
        }
    }
    /// Read a `u32` from this reader.
    pub fn read_u32(&mut self) -> Result<u32, Error> {
        if self.position + 4 <= self.s.len() {
            #[allow(clippy::indexing_slicing)] // length is known
            let u = BigEndian::read_u32(&self.s[self.position..]);
            self.position += 4;
            Ok(u)
        } else {
            Err(Error::IndexOutOfBounds)
        }
    }
    /// Read one byte from this reader.
    pub fn read_byte(&mut self) -> Result<u8, Error> {
        if self.position < self.s.len() {
            #[allow(clippy::indexing_slicing)] // length is known
            let u = self.s[self.position];
            self.position += 1;
            Ok(u)
        } else {
            Err(Error::IndexOutOfBounds)
        }
    }

    /// Read one byte from this reader.
    pub fn read_mpint(&mut self) -> Result<&'a [u8], Error> {
        let len = self.read_u32()? as usize;
        if self.position + len <= self.s.len() {
            #[allow(clippy::indexing_slicing)] // length was checked
            let result = &self.s[self.position..(self.position + len)];
            self.position += len;
            Ok(result)
        } else {
            Err(Error::IndexOutOfBounds)
        }
    }

    pub fn read_ssh<T: SshRead<'a>>(&mut self) -> Result<T, Error> {
        T::read_ssh(self)
    }
}

/// Trait for reading value in SSH-encoded format.
pub trait SshRead<'a>: Sized + 'a {
    /// Read the value from a position.
    fn read_ssh(pos: &mut Position<'a>) -> Result<Self, Error>;
}

impl<'a> ssh_encoding::Reader for Position<'a> {
    fn read<'o>(&mut self, out: &'o mut [u8]) -> ssh_encoding::Result<&'o [u8]> {
        out.copy_from_slice(
            self.s
                .get(self.position..(self.position + out.len()))
                .ok_or(ssh_encoding::Error::Length)?,
        );
        self.position += out.len();
        Ok(out)
    }

    fn remaining_len(&self) -> usize {
        self.s.len() - self.position
    }
}
