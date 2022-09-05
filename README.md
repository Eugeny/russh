# Russh
[![Rust](https://github.com/warp-tech/russh/actions/workflows/rust.yml/badge.svg)](https://github.com/warp-tech/russh/actions/workflows/rust.yml)  <!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-5-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

Async (tokio) SSH2 client and server implementation.

This is a fork of [Thrussh](//nest.pijul.com/pijul/thrussh) by Pierre-Étienne Meunier which adds:

> :sparkles: = added in this fork

* More safety guarantees :sparkles:
* `forward-tcpip` (remote port forwarding) :sparkles:
* Ciphers:
  * `chacha20-poly1305@openssh.com`
  * `aes256-gcm@openssh.com` :sparkles:
  * `aes256-ctr` :sparkles:
  * `aes192-ctr` :sparkles:
  * `aes128-ctr` :sparkles:
* Key exchanges:
  * `curve25519-sha256@libssh.org`
  * `diffie-hellman-group1-sha1` :sparkles:
  * `diffie-hellman-group14-sha1` :sparkles:
  * `diffie-hellman-group14-sha256` :sparkles:
* MACs:
  * `hmac-sha1` :sparkles:
  * `hmac-sha2-256` :sparkles:
  * `hmac-sha2-512` :sparkles:
  * `hmac-sha1-etm@openssh.com` :sparkles:
  * `hmac-sha2-256-etm@openssh.com` :sparkles:
  * `hmac-sha2-512-etm@openssh.com` :sparkles:
* Host keys:
  * `ssh-ed25519`
  * `rsa-sha2-256`
  * `rsa-sha2-512`
  * `ssh-rsa` :sparkles:
* Dependency updates
* Handle openssh sshd keepalive channel requests :sparkles:

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

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tr>
    <td align="center"><a href="https://github.com/mihirsamdarshi"><img src="https://avatars.githubusercontent.com/u/5462077?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Mihir Samdarshi</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=mihirsamdarshi" title="Documentation">📖</a></td>
    <td align="center"><a href="https://peet.io/"><img src="https://avatars.githubusercontent.com/u/2230985?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Connor Peet</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=connor4312" title="Code">💻</a></td>
    <td align="center"><a href="https://github.com/kvzn"><img src="https://avatars.githubusercontent.com/u/313271?v=4?s=100" width="100px;" alt=""/><br /><sub><b>KVZN</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=kvzn" title="Code">💻</a></td>
    <td align="center"><a href="https://www.telekom.de"><img src="https://avatars.githubusercontent.com/u/21334898?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Adrian Müller (DTT)</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=amtelekom" title="Code">💻</a></td>
    <td align="center"><a href="https://www.evilsocket.net"><img src="https://avatars.githubusercontent.com/u/86922?v=4?s=100" width="100px;" alt=""/><br /><sub><b>Simone Margaritelli</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=evilsocket" title="Code">💻</a></td>
  </tr>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
