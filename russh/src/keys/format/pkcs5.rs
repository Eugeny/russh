use aes::*;
use ssh_key::PrivateKey;

use super::Encryption;
use crate::keys::Error;

/// Decode a secret key in the PKCS#5 format, possibly deciphering it
/// using the supplied password.
pub fn decode_pkcs5(
    secret: &[u8],
    password: Option<&str>,
    enc: Encryption,
) -> Result<PrivateKey, Error> {
    use aes::cipher::KeyIvInit;
    use block_padding::{Error as UnpadError, Padding, Pkcs7};
    use cbc::cipher::BlockModeDecrypt;
    use hybrid_array::Array;
    use hybrid_array::typenum::U16;

    if let Some(pass) = password {
        let sec = match enc {
            Encryption::Aes128Cbc(ref iv) => {
                let mut c = md5::Context::new();
                c.consume(pass.as_bytes());
                c.consume(&iv[..8]);
                let md5 = c.finalize();

                #[allow(clippy::unwrap_used)] // AES parameters are static
                let mut c = cbc::Decryptor::<Aes128>::new_from_slices(&md5.0, &iv[..]).unwrap();
                let mut dec = secret.to_vec();

                // Input must be full blocks.
                if dec.is_empty() || dec.len() % 16 != 0 {
                    return Err(Error::Unpad(UnpadError));
                }

                // Decrypt in-place, block by block.
                for chunk in dec.chunks_exact_mut(16) {
                    // Make the block size explicit to avoid `Array<u8, _>` inference failures.
                    let block: &mut Block = chunk.try_into().expect("chunk is 16 bytes");
                    c.decrypt_blocks(std::slice::from_mut(block));
                }

                // Unpad PKCS#7 based on the final plaintext block.
                let last_block_start = dec.len() - 16;
                let last_block: Array<u8, U16> =
                    Array::try_from(&dec[last_block_start..]).expect("valid block size");
                let unpadded = Pkcs7::unpad(&last_block).map_err(Error::Unpad)?;
                dec.truncate(last_block_start + unpadded.len());
                dec
            }
            Encryption::Aes256Cbc(_) => unimplemented!(),
        };
        // TODO: presumably pkcs5 could contain non-RSA keys?
        #[cfg(feature = "rsa")]
        {
            super::decode_rsa_pkcs1_der(&sec).map(Into::into)
        }
        #[cfg(not(feature = "rsa"))]
        {
            Err(Error::UnsupportedKeyType {
                key_type_string: "RSA".to_string(),
                key_type_raw: vec![],
            })
        }
    } else {
        Err(Error::KeyIsEncrypted)
    }
}
