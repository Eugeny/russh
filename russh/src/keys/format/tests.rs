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
