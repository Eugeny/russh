use crate::key::safe_rng;
use crate::Error;
use elliptic_curve::{Curve, CurveArithmetic, FieldBytes, FieldBytesSize};

// p521::{SigningKey, VerifyingKey} are wrapped versions and do not provide PartialEq and Eq, hence
// we make our own type alias here.
mod local_p521 {
    use rand_core::CryptoRngCore;
    use sha2::{Digest, Sha512};

    pub type NistP521 = p521::NistP521;
    pub type VerifyingKey = ecdsa::VerifyingKey<NistP521>;
    pub type SigningKey = ecdsa::SigningKey<NistP521>;
    pub type Signature = ecdsa::Signature<NistP521>;
    pub type Result<T> = ecdsa::Result<T>;

    // Implement signing because p521::NistP521 does not implement DigestPrimitive trait.
    pub fn try_sign_with_rng(
        key: &SigningKey,
        rng: &mut impl CryptoRngCore,
        msg: &[u8],
    ) -> Result<Signature> {
        use ecdsa::hazmat::{bits2field, sign_prehashed};
        use elliptic_curve::Field;
        let prehash = Sha512::digest(msg);
        let z = bits2field::<NistP521>(&prehash)?;
        let k = p521::Scalar::random(rng);
        sign_prehashed(key.as_nonzero_scalar().as_ref(), k, &z).map(|sig| sig.0)
    }

    // Implement verifying because ecdsa::VerifyingKey<p521::NistP521> does not satisfy the trait
    // bound requirements of the DigestVerifier's implementation in ecdsa crate.
    pub fn verify(key: &VerifyingKey, msg: &[u8], signature: &Signature) -> Result<()> {
        use ecdsa::signature::hazmat::PrehashVerifier;
        key.verify_prehash(&Sha512::digest(msg), signature)
    }
}

const CURVE_NISTP256: &str = "nistp256";
const CURVE_NISTP384: &str = "nistp384";
const CURVE_NISTP521: &str = "nistp521";

/// An ECC public key.
#[derive(Clone, Eq, PartialEq)]
pub enum PublicKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    P521(local_p521::VerifyingKey),
}

impl PublicKey {
    /// Returns the elliptic curve domain parameter identifiers defined in RFC 5656 section 6.1.
    pub fn ident(&self) -> &'static str {
        match self {
            Self::P256(_) => CURVE_NISTP256,
            Self::P384(_) => CURVE_NISTP384,
            Self::P521(_) => CURVE_NISTP521,
        }
    }

    /// Returns the ECC public key algorithm name defined in RFC 5656 section 6.2, in the form of
    /// `"ecdsa-sha2-[identifier]"`.
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::P256(_) => crate::ECDSA_SHA2_NISTP256,
            Self::P384(_) => crate::ECDSA_SHA2_NISTP384,
            Self::P521(_) => crate::ECDSA_SHA2_NISTP521,
        }
    }

    /// Creates a `PrivateKey` from algorithm name and SEC1-encoded point on curve.
    pub fn from_sec1_bytes(algorithm: &[u8], bytes: &[u8]) -> Result<Self, Error> {
        match algorithm {
            crate::KEYTYPE_ECDSA_SHA2_NISTP256 => Ok(Self::P256(
                p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes)?,
            )),
            crate::KEYTYPE_ECDSA_SHA2_NISTP384 => Ok(Self::P384(
                p384::ecdsa::VerifyingKey::from_sec1_bytes(bytes)?,
            )),
            crate::KEYTYPE_ECDSA_SHA2_NISTP521 => Ok(Self::P521(
                local_p521::VerifyingKey::from_sec1_bytes(bytes)?,
            )),
            _ => Err(Error::UnsupportedKeyType {
                key_type_string: String::from_utf8(algorithm.to_vec())
                    .unwrap_or_else(|_| format!("{algorithm:?}")),
                key_type_raw: algorithm.to_vec(),
            }),
        }
    }

    /// Returns the SEC1-encoded public curve point.
    pub fn to_sec1_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(key) => key.to_encoded_point(false).as_bytes().to_vec(),
            Self::P384(key) => key.to_encoded_point(false).as_bytes().to_vec(),
            Self::P521(key) => key.to_encoded_point(false).as_bytes().to_vec(),
        }
    }

    /// Verifies message against signature `(r, s)` using the associated digest algorithm.
    pub fn verify(&self, msg: &[u8], r: &[u8], s: &[u8]) -> Result<(), Error> {
        use ecdsa::signature::Verifier;
        match self {
            Self::P256(key) => {
                key.verify(msg, &signature_from_scalar_bytes::<p256::NistP256>(r, s)?)
            }
            Self::P384(key) => {
                key.verify(msg, &signature_from_scalar_bytes::<p384::NistP384>(r, s)?)
            }
            Self::P521(key) => local_p521::verify(
                key,
                msg,
                &signature_from_scalar_bytes::<p521::NistP521>(r, s)?,
            ),
        }
        .map_err(Error::from)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Self::P256(_) => write!(f, "P256"),
            Self::P384(_) => write!(f, "P384"),
            Self::P521(_) => write!(f, "P521"),
        }
    }
}

/// An ECC private key.
#[derive(Clone, Eq, PartialEq)]
pub enum PrivateKey {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    P521(local_p521::SigningKey),
}

impl PrivateKey {
    /// Creates a `PrivateKey` with algorithm name and scalar.
    pub fn new_from_secret_scalar(algorithm: &[u8], scalar: &[u8]) -> Result<Self, Error> {
        match algorithm {
            crate::KEYTYPE_ECDSA_SHA2_NISTP256 => {
                Ok(Self::P256(p256::ecdsa::SigningKey::from_slice(scalar)?))
            }
            crate::KEYTYPE_ECDSA_SHA2_NISTP384 => {
                Ok(Self::P384(p384::ecdsa::SigningKey::from_slice(scalar)?))
            }
            crate::KEYTYPE_ECDSA_SHA2_NISTP521 => {
                Ok(Self::P521(local_p521::SigningKey::from_slice(scalar)?))
            }
            _ => Err(Error::UnsupportedKeyType {
                key_type_string: String::from_utf8(algorithm.to_vec())
                    .unwrap_or_else(|_| format!("{algorithm:?}")),
                key_type_raw: algorithm.to_vec(),
            }),
        }
    }

    /// Returns the elliptic curve domain parameter identifiers defined in RFC 5656 section 6.1.
    pub fn ident(&self) -> &'static str {
        match self {
            Self::P256(_) => CURVE_NISTP256,
            Self::P384(_) => CURVE_NISTP384,
            Self::P521(_) => CURVE_NISTP521,
        }
    }

    /// Returns the ECC public key algorithm name defined in RFC 5656 section 6.2, in the form of
    /// `"ecdsa-sha2-[identifier]"`.
    pub fn algorithm(&self) -> &'static str {
        match self {
            Self::P256(_) => crate::ECDSA_SHA2_NISTP256,
            Self::P384(_) => crate::ECDSA_SHA2_NISTP384,
            Self::P521(_) => crate::ECDSA_SHA2_NISTP521,
        }
    }

    /// Returns the public key.
    pub fn to_public_key(&self) -> PublicKey {
        match self {
            Self::P256(key) => PublicKey::P256(*key.verifying_key()),
            Self::P384(key) => PublicKey::P384(*key.verifying_key()),
            Self::P521(key) => PublicKey::P521(*key.verifying_key()),
        }
    }

    /// Returns the secret scalar in bytes.
    pub fn to_secret_bytes(&self) -> Vec<u8> {
        match self {
            Self::P256(key) => key.to_bytes().to_vec(),
            Self::P384(key) => key.to_bytes().to_vec(),
            Self::P521(key) => key.to_bytes().to_vec(),
        }
    }

    /// Sign the message with associated digest algorithm.
    pub fn try_sign(&self, msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        use ecdsa::signature::RandomizedSigner;
        Ok(match self {
            Self::P256(key) => {
                signature_to_scalar_bytes(key.try_sign_with_rng(&mut safe_rng(), msg)?)
            }
            Self::P384(key) => {
                signature_to_scalar_bytes(key.try_sign_with_rng(&mut safe_rng(), msg)?)
            }
            Self::P521(key) => {
                signature_to_scalar_bytes(local_p521::try_sign_with_rng(key, &mut safe_rng(), msg)?)
            }
        })
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Self::P256(_) => write!(f, "P256 {{ (hidden) }}"),
            Self::P384(_) => write!(f, "P384 {{ (hidden) }}"),
            Self::P521(_) => write!(f, "P521 {{ (hidden) }}"),
        }
    }
}

fn try_field_bytes_from_mpint<C>(b: &[u8]) -> Option<FieldBytes<C>>
where
    C: Curve + CurveArithmetic,
{
    use typenum::Unsigned;
    let size = FieldBytesSize::<C>::to_usize();
    assert!(size > 0);
    #[allow(clippy::indexing_slicing)] // Length checked
    if b.len() == size + 1 && b[0] == 0 {
        Some(FieldBytes::<C>::clone_from_slice(&b[1..]))
    } else if b.len() == size {
        Some(FieldBytes::<C>::clone_from_slice(b))
    } else if b.len() < size {
        let mut fb: FieldBytes<C> = Default::default();
        fb.as_mut_slice()[size - b.len()..].clone_from_slice(b);
        Some(fb)
    } else {
        None
    }
}

fn signature_from_scalar_bytes<C>(r: &[u8], s: &[u8]) -> Result<ecdsa::Signature<C>, Error>
where
    C: Curve + CurveArithmetic + elliptic_curve::PrimeCurve,
    ecdsa::SignatureSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
{
    Ok(ecdsa::Signature::<C>::from_scalars(
        try_field_bytes_from_mpint::<C>(r).ok_or(Error::InvalidSignature)?,
        try_field_bytes_from_mpint::<C>(s).ok_or(Error::InvalidSignature)?,
    )?)
}

fn signature_to_scalar_bytes<C>(sig: ecdsa::Signature<C>) -> (Vec<u8>, Vec<u8>)
where
    C: Curve + CurveArithmetic + elliptic_curve::PrimeCurve,
    ecdsa::SignatureSize<C>: elliptic_curve::generic_array::ArrayLength<u8>,
{
    let (r, s) = sig.split_bytes();
    (r.to_vec(), s.to_vec())
}
