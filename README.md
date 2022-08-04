# Russh

Async (tokio) SSH2 client and server rimplementation.

This is a fork of [Thrussh](//nest.pijul.com/pijul/thrussh) by Pierre-Étienne Meunier which adds:

* More safety guarantees
* New ciphers:
  * aes256-gcm@openssh.com
  * aes256-ctr
  * aes192-ctr
  * aes128-ctr
* New key exchanges:
  * diffie-hellman-group1-sha1
  * diffie-hellman-group14-sha1
  * diffie-hellman-group14-sha256
* HMACs:
  * hmac-sha1
  * hmac-sha2-256
  * hmac-sha2-512
  * hmac-sha1-etm@openssh.com
  * hmac-sha2-256-etm@openssh.com
  * hmac-sha2-512-etm@openssh.com
* Legacy `ssh-rsa` host keys support
* Dependency updates

## Safety

* `deny(clippy::unwrap_used)`
* `deny(clippy::expect_used)`
* `deny(clippy::indexing_slicing)`
* `deny(clippy::panic)`
* Exceptions are checked manually

### Panics

* When the Rust allocator fails to allocate memory during a CryptoVec being resized.

### Unsafe code

* `cryptovec` uses `unsafe` for faster copying, initialization and binding to native API.
* `russh-libsodium` uses `unsafe` for `libsodium` bindings.
