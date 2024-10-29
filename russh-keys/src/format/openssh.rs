use ssh_key::private::PrivateKey;

use crate::key::KeyPair;
use crate::Error;

/// Decode a secret key given in the OpenSSH format, deciphering it if
/// needed using the supplied password.
pub fn decode_openssh(secret: &[u8], password: Option<&str>) -> Result<KeyPair, Error> {
    let pk = PrivateKey::from_bytes(secret)?;
    if pk.is_encrypted() {
        if let Some(password) = password {
            return Ok(pk.decrypt(password)?);
        } else {
            return Err(Error::KeyIsEncrypted);
        }
    }
    Ok(pk.into())
}
