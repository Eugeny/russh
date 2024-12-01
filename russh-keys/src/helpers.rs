use ssh_encoding::Encode;

#[doc(hidden)]
pub trait EncodedExt {
    fn encoded(&self) -> ssh_key::Result<Vec<u8>>;
}

impl<E: Encode> EncodedExt for E {
    fn encoded(&self) -> ssh_key::Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.encode(&mut buf)?;
        Ok(buf)
    }
}

pub struct NameList(pub Vec<String>);

impl NameList {
    pub fn as_encoded_string(&self) -> String {
        self.0.join(",")
    }
}

impl Encode for NameList {
    fn encoded_len(&self) -> Result<usize, ssh_encoding::Error> {
        self.as_encoded_string().encoded_len()
    }

    fn encode(&self, writer: &mut impl ssh_encoding::Writer) -> Result<(), ssh_encoding::Error> {
        self.as_encoded_string().encode(writer)
    }
}

#[macro_export]
#[doc(hidden)]
#[allow(clippy::crate_in_macro_def)]
macro_rules! map_err {
    ($result:expr) => {
        $result.map_err(|e| crate::Error::from(e))
    };
}

pub use map_err;
use ssh_key::PrivateKey;

// TODO only needed until https://github.com/RustCrypto/SSH/pull/318 is released
#[doc(hidden)]
pub fn sign_workaround(
    key: &PrivateKey,
    data: &[u8],
) -> Result<ssh_key::Signature, signature::Error> {
    Ok(match key.key_data() {
        ssh_key::private::KeypairData::Rsa(rsa_keypair) => {
            let pk = rsa::RsaPrivateKey::from_components(
                <rsa::BigUint as std::convert::TryFrom<_>>::try_from(&rsa_keypair.public.n)?,
                <rsa::BigUint as std::convert::TryFrom<_>>::try_from(&rsa_keypair.public.e)?,
                <rsa::BigUint as std::convert::TryFrom<_>>::try_from(&rsa_keypair.private.d)?,
                vec![
                    <rsa::BigUint as std::convert::TryFrom<_>>::try_from(&rsa_keypair.private.p)?,
                    <rsa::BigUint as std::convert::TryFrom<_>>::try_from(&rsa_keypair.private.q)?,
                ],
            )?;
            let signature = signature::Signer::try_sign(
                &rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(pk),
                data,
            )?;
            ssh_key::Signature::new(
                ssh_key::Algorithm::Rsa {
                    hash: Some(ssh_key::HashAlg::Sha512),
                },
                <rsa::pkcs1v15::Signature as signature::SignatureEncoding>::to_vec(&signature),
            )?
        }
        keypair => signature::Signer::try_sign(keypair, data)?,
    })
}
