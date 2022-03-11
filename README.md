# Russh

Async (tokio) SSH2 client and serve rimplementation.

This is a fork of [Thrussh]((//nest.pijul.com/pijul/thrussh) by Pierre-Étienne Meunier which adds:

* More safety guarantees
* AES256-GCM support
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
