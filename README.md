# Russh
[![Rust](https://github.com/warp-tech/russh/actions/workflows/rust.yml/badge.svg)](https://github.com/warp-tech/russh/actions/workflows/rust.yml)  <!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-22-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

Low-level Tokio SSH2 client and server implementation.

Examples: [simple client](russh/examples/client_exec_simple.rs), [interactive PTY client](russh/examples/client_exec_interactive.rs), [server](russh/examples/echoserver.rs), [SFTP client](russh/examples/sftp_client.rs), [SFTP server](russh/examples/sftp_server.rs).

This is a fork of [Thrussh](https://nest.pijul.com/pijul/thrussh) by Pierre-Étienne Meunier.

> ✨ = added in Russh

* [More panic safety](https://github.com/warp-tech/russh#safety) ✨
* `async_trait` support ✨
* `direct-tcpip` (local port forwarding)
* `forward-tcpip` (remote port forwarding) ✨
* `direct-streamlocal` (local UNIX socket forwarding, client only) ✨
* Ciphers:
  * `chacha20-poly1305@openssh.com`
  * `aes256-gcm@openssh.com` ✨
  * `aes256-ctr` ✨
  * `aes192-ctr` ✨
  * `aes128-ctr` ✨
* Key exchanges:
  * `curve25519-sha256@libssh.org`
  * `diffie-hellman-group1-sha1` ✨
  * `diffie-hellman-group14-sha1` ✨
  * `diffie-hellman-group14-sha256` ✨
* MACs:
  * `hmac-sha1` ✨
  * `hmac-sha2-256` ✨
  * `hmac-sha2-512` ✨
  * `hmac-sha1-etm@openssh.com` ✨
  * `hmac-sha2-256-etm@openssh.com` ✨
  * `hmac-sha2-512-etm@openssh.com` ✨
* Key types:
  * `ssh-ed25519`
  * `rsa-sha2-256`
  * `rsa-sha2-512`
  * `ssh-rsa` ✨
  * `ecdsa-sha2-nistp256` ✨
* Dependency updates
* OpenSSH keepalive request handling ✨
* OpenSSH agent forwarding channels ✨
* OpenSSH `server-sig-algs` extension ✨

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

## Ecosystem

* [russh-sftp](https://crates.io/crates/russh-sftp) - server-side and client-side SFTP subsystem support for `russh` - see `russh/examples/sftp_server.rs` or `russh/examples/sftp_client.rs`.
* [async-ssh2-tokio](https://crates.io/crates/async-ssh2-tokio) - simple high-level API for running commands over SSH.

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/mihirsamdarshi"><img src="https://avatars.githubusercontent.com/u/5462077?v=4?s=100" width="100px;" alt="Mihir Samdarshi"/><br /><sub><b>Mihir Samdarshi</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=mihirsamdarshi" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://peet.io/"><img src="https://avatars.githubusercontent.com/u/2230985?v=4?s=100" width="100px;" alt="Connor Peet"/><br /><sub><b>Connor Peet</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=connor4312" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/kvzn"><img src="https://avatars.githubusercontent.com/u/313271?v=4?s=100" width="100px;" alt="KVZN"/><br /><sub><b>KVZN</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=kvzn" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://www.telekom.de"><img src="https://avatars.githubusercontent.com/u/21334898?v=4?s=100" width="100px;" alt="Adrian Müller (DTT)"/><br /><sub><b>Adrian Müller (DTT)</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=amtelekom" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://www.evilsocket.net"><img src="https://avatars.githubusercontent.com/u/86922?v=4?s=100" width="100px;" alt="Simone Margaritelli"/><br /><sub><b>Simone Margaritelli</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=evilsocket" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://joegrund.com"><img src="https://avatars.githubusercontent.com/u/458717?v=4?s=100" width="100px;" alt="Joe Grund"/><br /><sub><b>Joe Grund</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=jgrund" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/AspectUnk"><img src="https://avatars.githubusercontent.com/u/59799956?v=4?s=100" width="100px;" alt="AspectUnk"/><br /><sub><b>AspectUnk</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=AspectUnk" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://0io.eu"><img src="https://avatars.githubusercontent.com/u/203575?v=4?s=100" width="100px;" alt="Simão Mata"/><br /><sub><b>Simão Mata</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=simao" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://mariotaku.org"><img src="https://avatars.githubusercontent.com/u/830358?v=4?s=100" width="100px;" alt="Mariotaku"/><br /><sub><b>Mariotaku</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=mariotaku" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/yorkz1994"><img src="https://avatars.githubusercontent.com/u/16678950?v=4?s=100" width="100px;" alt="yorkz1994"/><br /><sub><b>yorkz1994</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=yorkz1994" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://volution.ro/"><img src="https://avatars.githubusercontent.com/u/29785?v=4?s=100" width="100px;" alt="Ciprian Dorin Craciun"/><br /><sub><b>Ciprian Dorin Craciun</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=cipriancraciun" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/mllken"><img src="https://avatars.githubusercontent.com/u/11590808?v=4?s=100" width="100px;" alt="Eric Milliken"/><br /><sub><b>Eric Milliken</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=mllken" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Swelio"><img src="https://avatars.githubusercontent.com/u/24651896?v=4?s=100" width="100px;" alt="Swelio"/><br /><sub><b>Swelio</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=Swelio" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/joshbenz"><img src="https://avatars.githubusercontent.com/u/94999261?v=4?s=100" width="100px;" alt="Joshua Benz"/><br /><sub><b>Joshua Benz</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=joshbenz" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="http://homepage.ruhr-uni-bochum.de/Jan.Holthuis/"><img src="https://avatars.githubusercontent.com/u/1834516?v=4?s=100" width="100px;" alt="Jan Holthuis"/><br /><sub><b>Jan Holthuis</b></sub></a><br /><a href="#security-Holzhaus" title="Security">🛡️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/mateuszkj"><img src="https://avatars.githubusercontent.com/u/2494082?v=4?s=100" width="100px;" alt="mateuszkj"/><br /><sub><b>mateuszkj</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=mateuszkj" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://gotlou.srht.site"><img src="https://avatars.githubusercontent.com/u/23006870?v=4?s=100" width="100px;" alt="Saksham Mittal"/><br /><sub><b>Saksham Mittal</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=gotlougit" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://canoncollision.com"><img src="https://avatars.githubusercontent.com/u/5120858?v=4?s=100" width="100px;" alt="Lucas Kent"/><br /><sub><b>Lucas Kent</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=rukai" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/RDruon"><img src="https://avatars.githubusercontent.com/u/64585623?v=4?s=100" width="100px;" alt="Raphael Druon"/><br /><sub><b>Raphael Druon</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=RDruon" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Nurrl"><img src="https://avatars.githubusercontent.com/u/15341887?v=4?s=100" width="100px;" alt="Maya the bee"/><br /><sub><b>Maya the bee</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=Nurrl" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/mmirate"><img src="https://avatars.githubusercontent.com/u/992859?v=4?s=100" width="100px;" alt="Milo Mirate"/><br /><sub><b>Milo Mirate</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=mmirate" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/george-hopkins"><img src="https://avatars.githubusercontent.com/u/552590?v=4?s=100" width="100px;" alt="George Hopkins"/><br /><sub><b>George Hopkins</b></sub></a><br /><a href="https://github.com/warp-tech/russh/commits?author=george-hopkins" title="Code">💻</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
