use super::Encryption;
use crate::{key, Error};

/// Decode a secret key in the PKCS#5 format, possible deciphering it
/// using the supplied password.
#[cfg(feature = "openssl")]
pub fn decode_pkcs5(
    secret: &[u8],
    password: Option<&str>,
    enc: Encryption,
) -> Result<key::KeyPair, Error> {
    use openssl::symm::{decrypt, Cipher};

    if let Some(pass) = password {
        let sec = match enc {
            Encryption::Aes128Cbc(ref iv) => {
                let mut c = md5::Context::new();
                c.consume(pass.as_bytes());
                c.consume(&iv[..8]);
                let md5 = c.compute();

                #[allow(clippy::unwrap_used)] // AES parameters are static
                decrypt(Cipher::aes_128_cbc(), &md5.0, Some(&iv[..]), secret)?
            }
            Encryption::Aes256Cbc(_) => unimplemented!(),
        };
        super::decode_rsa(&sec)
    } else {
        Err(Error::KeyIsEncrypted)
    }
}
