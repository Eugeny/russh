use rand;
use std::convert::TryInto;
use std::ops::Shl;

use num_bigint::{BigUint, RandBigInt};
use static_dh_ecdh::dh::dh::unhexlify_to_bytearray;

pub const DH_GROUP_14_PRIME: &str = "
	FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
	29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
	EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
	E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
	EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
	C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
	83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
	670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
	E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
	DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF";

pub const DH_GROUP_14_GENERATOR: usize = 2;
pub const DH_GROUP_14_EXPONENT_LENGTH: u64 = 256;

/// A data struct to hold state for DH_GROUP_ID 14 as per RFC - https://tools.ietf.org/html/rfc3526
#[derive(Debug, PartialEq, Clone)]
pub struct DH14 {
    prime_num: BigUint,
    generator: usize,
    exp_size: u64,
    private_key: BigUint, // should be private but marked pub for testing
    public_key: BigUint,
    shared_secret: BigUint, // should be private but marked pub for testing
}

impl DH14 {
    /// Create a new DH14 group with a prime value `DH_GROUP_14_PRIME`, generator `2`, and exp_size `256`
    pub fn new() -> Self {
        let mut this = DH14 {
            prime_num: BigUint::default(),
            generator: 0,
            exp_size: 0,
            private_key: BigUint::default(),
            public_key: BigUint::default(),
            shared_secret: BigUint::default(),
        };
        let prime_byte_arr = unhexlify_to_bytearray::<256>(
            &DH_GROUP_14_PRIME
                .replace(" ", "")
                .replace("\n", "")
                .replace("\t", ""),
        );
        this.prime_num = BigUint::from_bytes_be(&prime_byte_arr);
        this.generator = DH_GROUP_14_GENERATOR;
        this.exp_size = DH_GROUP_14_EXPONENT_LENGTH;
        this
    }

    /// Generate the private key
    pub fn generate_private_key(&mut self) -> BigUint {
        let mut rng = rand::thread_rng();
        self.private_key = rng.gen_biguint((self.exp_size * 8) - 2u64).shl(1);
        return self.private_key.clone(); // Need to change the return type to () after testing
    }

    /// Generate the public key
    pub fn generate_public_key(&mut self) -> BigUint {
        self.public_key = BigUint::from(self.generator).modpow(&self.private_key, &self.prime_num);
        return self.public_key.clone(); // Need to change the return type to () after testing
    }

    /// Compute the shared secret
    pub fn compute_shared_secret(&mut self, other_public_key: BigUint) -> BigUint {
        self.shared_secret = other_public_key.modpow(&self.private_key, &self.prime_num);
        self.shared_secret.clone() // Need to change the return type to () after testing
    }

    pub fn decode_public_key(buffer: &[u8]) -> BigUint {
        BigUint::from_bytes_be(buffer)
    }
}
