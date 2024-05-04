use russh_cryptovec::CryptoVec;
use russh_keys::encoding::Encoding;
use ssh_encoding::Encode;
use ssh_key::{Algorithm, Certificate, EcdsaCurve};
use crate::{key::PubKey, negotiation::Named};

/// OpenSSH certificate for DSA public key
const CERT_DSA: &str = "ssh-dss-cert-v01@openssh.com";

/// OpenSSH certificate for ECDSA (NIST P-256) public key
const CERT_ECDSA_SHA2_P256: &str = "ecdsa-sha2-nistp256-cert-v01@openssh.com";

/// OpenSSH certificate for ECDSA (NIST P-384) public key
const CERT_ECDSA_SHA2_P384: &str = "ecdsa-sha2-nistp384-cert-v01@openssh.com";

/// OpenSSH certificate for ECDSA (NIST P-521) public key
const CERT_ECDSA_SHA2_P521: &str = "ecdsa-sha2-nistp521-cert-v01@openssh.com";

/// OpenSSH certificate for Ed25519 public key
const CERT_ED25519: &str = "ssh-ed25519-cert-v01@openssh.com";

/// OpenSSH certificate with RSA public key
const CERT_RSA: &str = "ssh-rsa-cert-v01@openssh.com";

/// OpenSSH certificate for ECDSA (NIST P-256) U2F/FIDO security key
const CERT_SK_ECDSA_SHA2_P256: &str = "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com";

/// OpenSSH certificate for Ed25519 U2F/FIDO security key
const CERT_SK_SSH_ED25519: &str = "sk-ssh-ed25519-cert-v01@openssh.com";

/// None
const NONE: &str = "none";

impl PubKey for Certificate {
    fn push_to(&self, buffer: &mut CryptoVec) {
        let mut cert_encoded = Vec::new();
        let _ = self.encode(&mut cert_encoded);

        buffer.extend_ssh_string(&cert_encoded);
    }
}

impl Named for Certificate {
    fn name(&self) -> &'static str {
        match self.algorithm() {
            Algorithm::Dsa => CERT_DSA,
            Algorithm::Ecdsa { curve } => match curve {
                EcdsaCurve::NistP256 => CERT_ECDSA_SHA2_P256,
                EcdsaCurve::NistP384 => CERT_ECDSA_SHA2_P384,
                EcdsaCurve::NistP521 => CERT_ECDSA_SHA2_P521,
            },
            Algorithm::Ed25519 => CERT_ED25519,
            Algorithm::Rsa { .. } => CERT_RSA,
            Algorithm::SkEcdsaSha2NistP256 => CERT_SK_ECDSA_SHA2_P256,
            Algorithm::SkEd25519 => CERT_SK_SSH_ED25519,
            Algorithm::Other(_) => NONE,
            _ => NONE,
        }
    }
}
