use aes::*;

use super::Encryption;
use crate::{key, Error};

/// Decode a secret key in the PKCS#5 format, possibly deciphering it
/// using the supplied password.
pub fn decode_pkcs5(
    secret: &[u8],
    password: Option<&str>,
    enc: Encryption,
) -> Result<key::KeyPair, Error> {
    use aes::cipher::{BlockDecryptMut, KeyIvInit};
    use block_padding::Pkcs7;

    if let Some(pass) = password {
        let sec = match enc {
            Encryption::Aes128Cbc(ref iv) => {
                let mut c = md5::Context::new();
                c.consume(pass.as_bytes());
                c.consume(&iv[..8]);
                let md5 = c.compute();

                #[allow(clippy::unwrap_used)] // AES parameters are static
                let c = cbc::Decryptor::<Aes128>::new_from_slices(&md5.0, &iv[..]).unwrap();
                let mut dec = secret.to_vec();
                c.decrypt_padded_mut::<Pkcs7>(&mut dec)?.to_vec()
            }
            Encryption::Aes256Cbc(_) => unimplemented!(),
        };
        super::decode_rsa(&sec)
    } else {
        Err(Error::KeyIsEncrypted)
    }
}
