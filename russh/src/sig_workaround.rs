// TODO only needed until https://github.com/RustCrypto/SSH/pull/315 is released
use std::convert::TryFrom;

use signature::Verifier;
use ssh_encoding::Decode;
use ssh_key::{Algorithm, PublicKey, Signature};

pub enum Sig {
    Normal(Signature),
    SshRsa(Vec<u8>),
}

impl Sig {
    pub fn new(algo: Algorithm, sigbuf: Vec<u8>) -> ssh_key::Result<Self> {
        match algo {
            Algorithm::Rsa { hash: None } => Ok(Sig::SshRsa(sigbuf)),
            _ => Ok(Sig::Normal(Signature::new(algo, sigbuf)?)),
        }
    }

    pub fn decode(reader: &mut &[u8]) -> ssh_key::Result<Self> {
        let algo = Algorithm::decode(reader)?;
        let sigbuf = Vec::decode(reader)?;
        Self::new(algo, sigbuf)
    }
}

// TODO only needed until https://github.com/RustCrypto/SSH/pull/315 is released
pub fn verify(pubkey: &PublicKey, buf: &[u8], sig: &Sig) -> Result<(), signature::Error> {
    match sig {
        Sig::Normal(sig) => Verifier::verify(pubkey, buf, sig),
        Sig::SshRsa(sig) => {
            let Some(rsa_key) = pubkey.key_data().rsa() else {
                return Err(signature::Error::new());
            };
            let signature = rsa::pkcs1v15::Signature::try_from(sig.as_slice())?;
            rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::try_from(rsa_key)?.verify(buf, &signature)
        }
    }
}
