use ssh_key::{Algorithm, PrivateKey};

use crate::keys::pkcs8::{decode_pkcs8, encode_pkcs8_encrypted};

use super::decode_secret_key;

#[test]
fn test_ec_private_key() {
    let key = r#"-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBNK0jwKqqf8zkM+Z2l++9r8bzdTS/XCoB4N1J07dPxpByyJyGbhvIy
1kLvY2gIvlmgBwYFK4EEACKhZANiAAQvPxAK2RhvH/k5inDa9oMxUZPvvb9fq8G3
9dKW1tS+ywhejnKeu/48HXAXgx2g6qMJjEPpcTy/DaYm12r3GTaRzOBQmxSItStk
lpQg5vf23Fc9fFrQ9AnQKrb1dgTkoxQ=
-----END EC PRIVATE KEY-----"#;
    decode_secret_key(key, None).unwrap();
}

#[test]
fn test_pkcs8_roundtrip() {
    let password = b"SomePassword";
    let original_key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();

    let encrypted = encode_pkcs8_encrypted(password, 10, &original_key).unwrap();
    let decrypted = decode_pkcs8(&encrypted, Some(password)).unwrap();
    assert_eq!(decrypted, original_key);
}
