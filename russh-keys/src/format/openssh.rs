use ssh_key::PrivateKey;

use crate::Error;

/// Decode a secret key given in the OpenSSH format, deciphering it if
/// needed using the supplied password.
pub fn decode_openssh(secret: &[u8], password: Option<&str>) -> Result<PrivateKey, Error> {
    let pk = PrivateKey::from_bytes(secret)?;
    if pk.is_encrypted() {
        if let Some(password) = password {
            return Ok(pk.decrypt(password)?);
        } else {
            return Err(Error::KeyIsEncrypted);
        }
    }
    Ok(pk)
}

/// Parse a private key given in the OpenSSH PEM format, deciphering it if
/// needed using the supplied password.
///
/// OpenSSH-formatted private keys begin with the following:
///
/// ```text
/// -----BEGIN OPENSSH PRIVATE KEY-----
/// ```
pub fn parse_openssh_pem(
    pem: impl AsRef<[u8]>,
    password: Option<&str>,
) -> Result<PrivateKey, Error> {
    let pk = PrivateKey::from_openssh(pem)?;
    if pk.is_encrypted() {
        if let Some(password) = password {
            return Ok(pk.decrypt(password)?);
        } else {
            return Err(Error::KeyIsEncrypted);
        }
    }
    Ok(pk)
}
