# Russh
<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-2-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

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

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://github.com/mihirsamdarshi"><img src="https://avatars.githubusercontent.com/u/5462077?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Mihir Samdarshi</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=mihirsamdarshi" title="Documentation">📖</a></td>
    <td align="center"><a href="https://peet.io/"><img src="https://avatars.githubusercontent.com/u/2230985?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Connor Peet</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=connor4312" title="Code">💻</a></td>
  </tr>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!