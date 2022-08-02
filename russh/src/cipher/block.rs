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

use std::marker::PhantomData;

use super::super::Error;
use aes::cipher::{IvSizeUser, KeyIvInit, KeySizeUser, StreamCipher};
use byteorder::{BigEndian, ByteOrder};
use digest::typenum::U20;
use digest::CtOutput;
use generic_array::GenericArray;
use hmac::{Hmac, Mac};
use russh_libsodium::random::randombytes;
use sha1::Sha1;

const MAC_KEY_BYTES: usize = 20;
type MacKey = GenericArray<u8, U20>;

pub struct SshBlockCipher<C: StreamCipher + KeySizeUser + IvSizeUser> {
    pub c: PhantomData<C>,
}

impl<C: StreamCipher + KeySizeUser + IvSizeUser + KeyIvInit + Send + 'static> super::Cipher
    for SshBlockCipher<C>
{
    fn key_len(&self) -> usize {
        C::key_size()
    }

    fn mac_key_len(&self) -> usize {
        MAC_KEY_BYTES
    }

    fn nonce_len(&self) -> usize {
        C::iv_size()
    }

    fn make_opening_key(&self, k: &[u8], n: &[u8], m: &[u8]) -> Box<dyn super::OpeningKey + Send> {
        let mut key = GenericArray::<u8, C::KeySize>::default();
        let mut nonce = GenericArray::<u8, C::IvSize>::default();
        let mut mac_key = GenericArray::from([0u8; MAC_KEY_BYTES]);
        key.clone_from_slice(k);
        nonce.clone_from_slice(n);
        mac_key.clone_from_slice(m);
        Box::new(OpeningKey {
            cipher: C::new(&key, &nonce),
            mac_key,
        })
    }

    fn make_sealing_key(&self, k: &[u8], n: &[u8], m: &[u8]) -> Box<dyn super::SealingKey + Send> {
        let mut key = GenericArray::<u8, C::KeySize>::default();
        let mut nonce = GenericArray::<u8, C::IvSize>::default();
        let mut mac_key = GenericArray::from([0u8; MAC_KEY_BYTES]);
        key.clone_from_slice(k);
        nonce.clone_from_slice(n);
        mac_key.clone_from_slice(m);
        Box::new(SealingKey {
            cipher: C::new(&key, &nonce),
            mac_key,
        })
    }
}

pub struct OpeningKey<C: StreamCipher + KeySizeUser + IvSizeUser> {
    mac_key: MacKey,
    cipher: C,
}

pub struct SealingKey<C: StreamCipher + KeySizeUser + IvSizeUser> {
    mac_key: MacKey,
    cipher: C,
}

const TAG_LEN: usize = 20;

impl<C: StreamCipher + KeySizeUser + IvSizeUser> super::OpeningKey for OpeningKey<C> {
    fn decrypt_packet_length(
        &self,
        _sequence_number: u32,
        mut encrypted_packet_length: [u8; 4],
    ) -> [u8; 4] {
        // Work around uncloneable Aes<>
        let mut cipher: C = unsafe { std::ptr::read(&self.cipher as *const C) };
        cipher.apply_keystream(&mut encrypted_packet_length);
        encrypted_packet_length
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn open<'a>(
        &mut self,
        sequence_number: u32,
        ciphertext_in_plaintext_out: &'a mut [u8],
        tag: &[u8],
    ) -> Result<&'a [u8], Error> {
        self.cipher.apply_keystream(ciphertext_in_plaintext_out);

        let mac = hmac(sequence_number, ciphertext_in_plaintext_out, &self.mac_key);

        let mut rcvd_mac = GenericArray::from([0u8; TAG_LEN]);
        rcvd_mac.copy_from_slice(tag);
        let rcvd_mac = CtOutput::<Hmac<Sha1>>::new(rcvd_mac);

        if mac != rcvd_mac {
            return Err(Error::PacketAuth);
        }

        Ok(ciphertext_in_plaintext_out)
    }
}

impl<C: StreamCipher + KeySizeUser + IvSizeUser> super::SealingKey for SealingKey<C> {
    fn padding_length(&self, payload: &[u8]) -> usize {
        let block_size = 16;
        let extra_len = super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN + TAG_LEN;
        let padding_len = if payload.len() + extra_len <= super::MINIMUM_PACKET_LEN {
            super::MINIMUM_PACKET_LEN
                - payload.len()
                - super::PADDING_LENGTH_LEN
                - super::PACKET_LENGTH_LEN
        } else {
            block_size
                - ((super::PACKET_LENGTH_LEN + super::PADDING_LENGTH_LEN + payload.len())
                    % block_size)
        };
        if padding_len < super::PACKET_LENGTH_LEN {
            padding_len + block_size
        } else {
            padding_len
        }
    }

    fn fill_padding(&self, padding_out: &mut [u8]) {
        randombytes(padding_out);
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn seal(
        &mut self,
        sequence_number: u32,
        plaintext_in_ciphertext_out: &mut [u8],
        tag_out: &mut [u8],
    ) {
        tag_out.copy_from_slice(
            &hmac(sequence_number, plaintext_in_ciphertext_out, &self.mac_key).into_bytes(),
        );
        self.cipher.apply_keystream(plaintext_in_ciphertext_out);
    }
}

fn hmac(seq: u32, packet: &[u8], key: &MacKey) -> CtOutput<Hmac<Sha1>> {
    let mut hmac = Hmac::<Sha1>::new_from_slice(key).unwrap();
    let mut buf = vec![0; 4];
    BigEndian::write_u32(&mut buf, seq);
    hmac.update(&buf);
    hmac.update(packet);
    hmac.finalize()
}
