use std::fmt::Debug;
use std::ops::Deref;

use hex_literal::hex;
use num_bigint::{BigUint, RandBigInt};
use rand;

#[derive(Clone)]
pub enum DhGroupUInt {
    Static(&'static [u8]),
    Owned(Vec<u8>),
}

impl From<Vec<u8>> for DhGroupUInt {
    fn from(x: Vec<u8>) -> Self {
        Self::Owned(x)
    }
}

impl DhGroupUInt {
    pub const fn new(x: &'static [u8]) -> Self {
        Self::Static(x)
    }
}

impl Deref for DhGroupUInt {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Static(x) => x,
            Self::Owned(x) => x,
        }
    }
}

#[derive(Clone)]
pub struct DhGroup {
    pub(crate) prime: DhGroupUInt,
    pub(crate) generator: DhGroupUInt,
    // pub(crate) exp_size: u64,
}

impl DhGroup {
    pub fn bit_size(&self) -> usize {
        let Some(fsb_idx) = self.prime.deref().iter().position(|&x| x != 0) else {
            return 0;
        };
        (self.prime.deref().len() - fsb_idx) * 8
    }
}

impl Debug for DhGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhGroup")
            .field("prime", &format!("<{} bytes>", self.prime.deref().len()))
            .field(
                "generator",
                &format!("<{} bytes>", self.generator.deref().len()),
            )
            .finish()
    }
}

pub const DH_GROUP1: DhGroup = DhGroup {
    prime: DhGroupUInt::new(
        hex!(
            "
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
         29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
         EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
         E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
         EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
         FFFFFFFF FFFFFFFF
        "
        )
        .as_slice(),
    ),
    generator: DhGroupUInt::new(&[2]),
    // exp_size: 256,
};

pub const DH_GROUP14: DhGroup = DhGroup {
    prime: DhGroupUInt::new(
        hex!(
            "
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
        15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
        "
        )
        .as_slice(),
    ),
    generator: DhGroupUInt::new(&[2]),
    // exp_size: 256,
};

pub const DH_GROUP16: DhGroup = DhGroup {
    prime: DhGroupUInt::new(
        hex!(
            "
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
        15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
        ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
        ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
        F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
        BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
        43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
        88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
        2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
        287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
        1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
        93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
        FFFFFFFF FFFFFFFF
        "
        )
        .as_slice(),
    ),
    generator: DhGroupUInt::new(&[2]),
    // exp_size: 512,
};

pub const DH_GROUP15: DhGroup = DhGroup {
    prime: DhGroupUInt::new(
        hex!(
            "
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
        FFFFFFFF FFFFFFFF
            "
        )
        .as_slice(),
    ),
    generator: DhGroupUInt::new(&[2]),
};

pub const DH_GROUP17: DhGroup = DhGroup {
    prime: DhGroupUInt::new(
        hex!(
            "
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
    FFFFFFFF FFFFFFFF 7ADBB2CE 2FCBF1A1 8E3A443F 71FB6F5D
    382CFB52 9A007F1C 4E4B3A3F B4C30C05 0E634647 34626B76
    07D6F0E0 C2D97300 C813EFC6 15F69E5C 95F4917A D7EB9C25
    4E957C2F 34AA2F99 798FC7B4 27C6BC9F F9B109F1 5B3F5946
    7F0ABDB6 C67DDEA7 A38D0811 B2C6C272 70D91FBD 5C6DAA4C
    DF4A4036 726F52A5 95C6ACDB CDE06C2A B7D225A1 7C7B7FE3
    FFFFFFFF FFFFFFFF
    "
        )
        .as_slice(),
    ),
    generator: DhGroupUInt::new(&[2]),
};

pub const DH_GROUP18: DhGroup = DhGroup {
    prime: DhGroupUInt::new(
        hex!(
            "
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
    FFFFFFFF FFFFFFFF 7ADBB2CE 2FCBF1A1 8E3A443F 71FB6F5D
    382CFB52 9A007F1C 4E4B3A3F B4C30C05 0E634647 34626B76
    07D6F0E0 C2D97300 C813EFC6 15F69E5C 95F4917A D7EB9C25
    4E957C2F 34AA2F99 798FC7B4 27C6BC9F F9B109F1 5B3F5946
    7F0ABDB6 C67DDEA7 A38D0811 B2C6C272 70D91FBD 5C6DAA4C
    DF4A4036 726F52A5 95C6ACDB CDE06C2A B7D225A1 7C7B7FE3
    2BCDF302 6D7F5034 26CFFDA0 10A0D08C 6D28E169 A7EFA46E
    EFC381D9 31C6E9A0 3D56D26A 42EFB168 2AE4C3B3 7B72C6E0
    AF568AB3 956C0A39 F83F7B2A 2D8F6E90 3732FD7B 4C6D9314
    ED0A0EED 3395FC82 187F6D2C 17C43A67 67C5D74F D56A1B4A
    B44F6DA0 36E1DBA5 6C0B605F CF2ED8D6 9B43A65B B3FD6192
    E39529FA A6C1835C 888A0A20 4CED7829 A691B20E 96A8D050
    31E589FC C4FCD4E4 58E2D50B 7B0AF49F 9D79C358 81A0A93B
    C62AF35B 3876DD66 75BD0B02 3C2743FB 9012B3D5 85EAD0F1
    58B6A4F4 7EA37AC6 84B67D3D 6C3F6E99 7F7F19F6 41D6B423
    6E21E7C6 C8DA55E7 C58989A9 0D3E196E 72E1D845 97938EC5
    71F7C0B5 83599B9E 5B6C0F84 91D23D87 3985A747 746B10F2
    CA6C175D 8926E51A A04D4E77 A2A3684B 89C0591E 917C0670
    9A68BEBC 73CDB7F9 7C927C3A F60ACD3E F89E4B06 B56C5E5C
    0C602283 5A691DB6 3AFEAFA6 C364B8C4 7D1F5969 7E9E3C2F
    FFFFFFFF FFFFFFFF
            "
        )
        .as_slice(),
    ),
    generator: DhGroupUInt::new(&[2]),
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct DH {
    prime_num: BigUint,
    generator: BigUint,
    private_key: BigUint,
    public_key: BigUint,
    shared_secret: BigUint,
}

impl DH {
    pub fn new(group: &DhGroup) -> Self {
        Self {
            prime_num: BigUint::from_bytes_be(&group.prime),
            generator: BigUint::from_bytes_be(&group.generator),
            private_key: BigUint::default(),
            public_key: BigUint::default(),
            shared_secret: BigUint::default(),
        }
    }

    pub fn generate_private_key(&mut self, is_server: bool) -> BigUint {
        let q = (&self.prime_num - &BigUint::from(1u8)) / &BigUint::from(2u8);
        let mut rng = rand::thread_rng();
        self.private_key =
            rng.gen_biguint_range(&if is_server { 1u8.into() } else { 2u8.into() }, &q);
        self.private_key.clone()
    }

    pub fn generate_public_key(&mut self) -> BigUint {
        self.public_key = self.generator.modpow(&self.private_key, &self.prime_num);
        self.public_key.clone()
    }

    pub fn compute_shared_secret(&mut self, other_public_key: BigUint) -> BigUint {
        self.shared_secret = other_public_key.modpow(&self.private_key, &self.prime_num);
        self.shared_secret.clone()
    }

    pub fn validate_shared_secret(&self, shared_secret: &BigUint) -> bool {
        let one = BigUint::from(1u8);
        let prime_minus_one = &self.prime_num - &one;

        shared_secret > &one && shared_secret < &prime_minus_one
    }

    pub fn decode_public_key(buffer: &[u8]) -> BigUint {
        BigUint::from_bytes_be(buffer)
    }

    pub fn validate_public_key(&self, public_key: &BigUint) -> bool {
        let one = BigUint::from(1u8);
        let prime_minus_one = &self.prime_num - &one;

        public_key > &one && public_key < &prime_minus_one
    }
}

pub(crate) const BUILTIN_SAFE_DH_GROUPS: &[&DhGroup] = &[&DH_GROUP14, &DH_GROUP16];
