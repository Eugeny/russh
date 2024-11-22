# Russh

[![Rust](https://github.com/warp-tech/russh/actions/workflows/rust.yml/badge.svg)](https://github.com/warp-tech/russh/actions/workflows/rust.yml)  <!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->
[![All Contributors](https://img.shields.io/badge/all_contributors-48-orange.svg?style=flat-square)](#contributors-)
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
* `forward-streamlocal` (remote UNIX socket forwarding) ✨
* Ciphers:
  * `chacha20-poly1305@openssh.com`
  * `aes256-gcm@openssh.com` ✨
  * `aes256-ctr` ✨
  * `aes192-ctr` ✨
  * `aes128-ctr` ✨
  * `aes256-cbc` ✨
  * `aes192-cbc` ✨
  * `aes128-cbc` ✨
  * `3des-cbc` ✨
* Key exchanges:
  * `curve25519-sha256@libssh.org`
  * `diffie-hellman-group1-sha1` ✨
  * `diffie-hellman-group14-sha1` ✨
  * `diffie-hellman-group14-sha256` ✨
  * `diffie-hellman-group16-sha512` ✨
  * `ecdh-sha2-nistp256` ✨
  * `ecdh-sha2-nistp384` ✨
  * `ecdh-sha2-nistp521` ✨
* MACs:
  * `hmac-sha1` ✨
  * `hmac-sha2-256` ✨
  * `hmac-sha2-512` ✨
  * `hmac-sha1-etm@openssh.com` ✨
  * `hmac-sha2-256-etm@openssh.com` ✨
  * `hmac-sha2-512-etm@openssh.com` ✨
* Host keys and public key auth:
  * `ssh-ed25519`
  * `rsa-sha2-256`
  * `rsa-sha2-512`
  * `ssh-rsa` ✨
  * `ecdsa-sha2-nistp256` ✨
  * `ecdsa-sha2-nistp384` ✨
  * `ecdsa-sha2-nistp521` ✨
* Authentication methods:
  * `password`
  * `publickey`
  * `keyboard-interactive`
  * `none`
  * OpenSSH certificates ✨
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
* When `mlock`/`munlock` fails to protect sensitive data in memory.

### Unsafe code

* `cryptovec` uses `unsafe` for faster copying, initialization and binding to native API.

## Ecosystem

* [russh-sftp](https://crates.io/crates/russh-sftp) - server-side and client-side SFTP subsystem support for `russh` - see `russh/examples/sftp_server.rs` or `russh/examples/sftp_client.rs`.
* [async-ssh2-tokio](https://crates.io/crates/async-ssh2-tokio) - simple high-level API for running commands over SSH.

## Adopters

* [HexPatch](https://github.com/Etto48/HexPatch) - A binary patcher and editor written in Rust with terminal user interface (TUI).
  * Uses `russh::client` and `russh_sftp::client` to allow remote editing of files.
* [kartoffels](https://github.com/Patryk27/kartoffels) - A game where you're given a potato and your job is to implement a firmware for it
  * Uses `russh:server` to deliver the game, using `ratatui` as the rendering engine.
* [kty](https://github.com/grampelberg/kty) - The terminal for Kubernetes.
  * Uses `russh::server` to deliver the `ratatui` based TUI and `russh_sftp::server` to provide `scp` based file management.
* [lapdev](https://github.com/lapce/lapdev) - Self-Hosted Remote Dev Environment
  * Uses `russh::server` to construct a proxy into your development environment.
* [medusa](https://github.com/evilsocket/medusa) - A fast and secure multi protocol honeypot.
  * Uses `russh::server` to be the basis of the honyepot.
* [rebels-in-the-sky](https://github.com/ricott1/rebels-in-the-sky) - P2P terminal game about spacepirates playing basketball across the galaxy
  * Uses `russh::server` to deliver the game, using `ratatui` as the rendering engine.
* [warpgate](https://github.com/warp-tech/warpgate) - Smart SSH, HTTPS and MySQL bastion that requires no additional client-side software
  * Uses `russh::server` in addition to `russh::client` as part of the smart SSH functionality.
* [Devolutions Gateway](https://github.com/Devolutions/devolutions-gateway/) - Establish a secure entry point for internal or external segmented networks that require authorized just-in-time (JIT) access.
  * Uses `russh::client` for the web-based SSH client of the standalone web application.

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/mihirsamdarshi"><img src="https://avatars.githubusercontent.com/u/5462077?v=4?s=100" width="100px;" alt="Mihir Samdarshi"/><br /><sub><b>Mihir Samdarshi</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=mihirsamdarshi" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://peet.io/"><img src="https://avatars.githubusercontent.com/u/2230985?v=4?s=100" width="100px;" alt="Connor Peet"/><br /><sub><b>Connor Peet</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=connor4312" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/kvzn"><img src="https://avatars.githubusercontent.com/u/313271?v=4?s=100" width="100px;" alt="KVZN"/><br /><sub><b>KVZN</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=kvzn" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://www.telekom.de"><img src="https://avatars.githubusercontent.com/u/21334898?v=4?s=100" width="100px;" alt="Adrian Müller (DTT)"/><br /><sub><b>Adrian Müller (DTT)</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=amtelekom" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://www.evilsocket.net"><img src="https://avatars.githubusercontent.com/u/86922?v=4?s=100" width="100px;" alt="Simone Margaritelli"/><br /><sub><b>Simone Margaritelli</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=evilsocket" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://joegrund.com"><img src="https://avatars.githubusercontent.com/u/458717?v=4?s=100" width="100px;" alt="Joe Grund"/><br /><sub><b>Joe Grund</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=jgrund" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/AspectUnk"><img src="https://avatars.githubusercontent.com/u/59799956?v=4?s=100" width="100px;" alt="AspectUnk"/><br /><sub><b>AspectUnk</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=AspectUnk" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://0io.eu"><img src="https://avatars.githubusercontent.com/u/203575?v=4?s=100" width="100px;" alt="Simão Mata"/><br /><sub><b>Simão Mata</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=simao" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://mariotaku.org"><img src="https://avatars.githubusercontent.com/u/830358?v=4?s=100" width="100px;" alt="Mariotaku"/><br /><sub><b>Mariotaku</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=mariotaku" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/yorkz1994"><img src="https://avatars.githubusercontent.com/u/16678950?v=4?s=100" width="100px;" alt="yorkz1994"/><br /><sub><b>yorkz1994</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=yorkz1994" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://volution.ro/"><img src="https://avatars.githubusercontent.com/u/29785?v=4?s=100" width="100px;" alt="Ciprian Dorin Craciun"/><br /><sub><b>Ciprian Dorin Craciun</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=cipriancraciun" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/mllken"><img src="https://avatars.githubusercontent.com/u/11590808?v=4?s=100" width="100px;" alt="Eric Milliken"/><br /><sub><b>Eric Milliken</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=mllken" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Swelio"><img src="https://avatars.githubusercontent.com/u/24651896?v=4?s=100" width="100px;" alt="Swelio"/><br /><sub><b>Swelio</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=Swelio" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/joshbenz"><img src="https://avatars.githubusercontent.com/u/94999261?v=4?s=100" width="100px;" alt="Joshua Benz"/><br /><sub><b>Joshua Benz</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=joshbenz" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="http://homepage.ruhr-uni-bochum.de/Jan.Holthuis/"><img src="https://avatars.githubusercontent.com/u/1834516?v=4?s=100" width="100px;" alt="Jan Holthuis"/><br /><sub><b>Jan Holthuis</b></sub></a><br /><a href="#security-Holzhaus" title="Security">🛡️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/mateuszkj"><img src="https://avatars.githubusercontent.com/u/2494082?v=4?s=100" width="100px;" alt="mateuszkj"/><br /><sub><b>mateuszkj</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=mateuszkj" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://gotlou.srht.site"><img src="https://avatars.githubusercontent.com/u/23006870?v=4?s=100" width="100px;" alt="Saksham Mittal"/><br /><sub><b>Saksham Mittal</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=gotlougit" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://canoncollision.com"><img src="https://avatars.githubusercontent.com/u/5120858?v=4?s=100" width="100px;" alt="Lucas Kent"/><br /><sub><b>Lucas Kent</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=rukai" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/RDruon"><img src="https://avatars.githubusercontent.com/u/64585623?v=4?s=100" width="100px;" alt="Raphael Druon"/><br /><sub><b>Raphael Druon</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=RDruon" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Nurrl"><img src="https://avatars.githubusercontent.com/u/15341887?v=4?s=100" width="100px;" alt="Maya the bee"/><br /><sub><b>Maya the bee</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=Nurrl" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/mmirate"><img src="https://avatars.githubusercontent.com/u/992859?v=4?s=100" width="100px;" alt="Milo Mirate"/><br /><sub><b>Milo Mirate</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=mmirate" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/george-hopkins"><img src="https://avatars.githubusercontent.com/u/552590?v=4?s=100" width="100px;" alt="George Hopkins"/><br /><sub><b>George Hopkins</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=george-hopkins" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://amcoff.net/"><img src="https://avatars.githubusercontent.com/u/17624114?v=4?s=100" width="100px;" alt="Åke Amcoff"/><br /><sub><b>Åke Amcoff</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=akeamc" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://brendonho.com"><img src="https://avatars.githubusercontent.com/u/12106620?v=4?s=100" width="100px;" alt="Brendon Ho"/><br /><sub><b>Brendon Ho</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=bho01" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://samlikes.pizza/"><img src="https://avatars.githubusercontent.com/u/226872?v=4?s=100" width="100px;" alt="Samuel Ainsworth"/><br /><sub><b>Samuel Ainsworth</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=samuela" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Sherlock-Holo"><img src="https://avatars.githubusercontent.com/u/10096425?v=4?s=100" width="100px;" alt="Sherlock Holo"/><br /><sub><b>Sherlock Holo</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=sherlock-holo" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/ricott1"><img src="https://avatars.githubusercontent.com/u/16502243?v=4?s=100" width="100px;" alt="Alessandro Ricottone"/><br /><sub><b>Alessandro Ricottone</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=ricott1" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/T0b1-iOS"><img src="https://avatars.githubusercontent.com/u/15174814?v=4?s=100" width="100px;" alt="T0b1-iOS"/><br /><sub><b>T0b1-iOS</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=T0b1-iOS" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://mecha.so"><img src="https://avatars.githubusercontent.com/u/4598631?v=4?s=100" width="100px;" alt="Shoaib Merchant"/><br /><sub><b>Shoaib Merchant</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=shoaibmerchant" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/gleason-m"><img src="https://avatars.githubusercontent.com/u/86493344?v=4?s=100" width="100px;" alt="Michael Gleason"/><br /><sub><b>Michael Gleason</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=gleason-m" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://ana.gelez.xyz"><img src="https://avatars.githubusercontent.com/u/16254623?v=4?s=100" width="100px;" alt="Ana Gelez"/><br /><sub><b>Ana Gelez</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=elegaanz" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/tomknig"><img src="https://avatars.githubusercontent.com/u/3586316?v=4?s=100" width="100px;" alt="Tom König"/><br /><sub><b>Tom König</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=tomknig" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://www.legaltile.com/"><img src="https://avatars.githubusercontent.com/u/45085843?v=4?s=100" width="100px;" alt="Pierre Barre"/><br /><sub><b>Pierre Barre</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=Barre" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://skutnik.page"><img src="https://avatars.githubusercontent.com/u/22240065?v=4?s=100" width="100px;" alt="Jean-Baptiste Skutnik"/><br /><sub><b>Jean-Baptiste Skutnik</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=spoutn1k" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://blog.packetsource.net/"><img src="https://avatars.githubusercontent.com/u/6276475?v=4?s=100" width="100px;" alt="Adam Chappell"/><br /><sub><b>Adam Chappell</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=packetsource" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/CertainLach"><img src="https://avatars.githubusercontent.com/u/6235312?v=4?s=100" width="100px;" alt="Yaroslav Bolyukin"/><br /><sub><b>Yaroslav Bolyukin</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=CertainLach" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://www.systemscape.de"><img src="https://avatars.githubusercontent.com/u/20155974?v=4?s=100" width="100px;" alt="Julian"/><br /><sub><b>Julian</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=JuliDi" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://saunter.org"><img src="https://avatars.githubusercontent.com/u/47992?v=4?s=100" width="100px;" alt="Thomas Rampelberg"/><br /><sub><b>Thomas Rampelberg</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=grampelberg" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://belak.io"><img src="https://avatars.githubusercontent.com/u/107097?v=4?s=100" width="100px;" alt="Kaleb Elwert"/><br /><sub><b>Kaleb Elwert</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=belak" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://garyguo.net"><img src="https://avatars.githubusercontent.com/u/4065244?v=4?s=100" width="100px;" alt="Gary Guo"/><br /><sub><b>Gary Guo</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=nbdd0121" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/irvingoujAtDevolution"><img src="https://avatars.githubusercontent.com/u/139169536?v=4?s=100" width="100px;" alt="irvingouj @ Devolutions"/><br /><sub><b>irvingouj @ Devolutions</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=irvingoujAtDevolution" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://tonipeter.de"><img src="https://avatars.githubusercontent.com/u/4614215?v=4?s=100" width="100px;" alt="Toni Peter"/><br /><sub><b>Toni Peter</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=Tehforsch" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Nathy-bajo"><img src="https://avatars.githubusercontent.com/u/73991674?v=4?s=100" width="100px;" alt="Nathaniel Bajo"/><br /><sub><b>Nathaniel Bajo</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=Nathy-bajo" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://eric.dev.br"><img src="https://avatars.githubusercontent.com/u/3129194?v=4?s=100" width="100px;" alt="Eric Rodrigues Pires"/><br /><sub><b>Eric Rodrigues Pires</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=EpicEric" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="http://www.fly.io"><img src="https://avatars.githubusercontent.com/u/43325?v=4?s=100" width="100px;" alt="Jerome Gravel-Niquet"/><br /><sub><b>Jerome Gravel-Niquet</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=jeromegn" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://qsantos.fr/"><img src="https://avatars.githubusercontent.com/u/8493765?v=4?s=100" width="100px;" alt="Quentin Santos"/><br /><sub><b>Quentin Santos</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=qsantos" title="Documentation">📖</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/ogedei-khan"><img src="https://avatars.githubusercontent.com/u/181673956?v=4?s=100" width="100px;" alt="André Almeida"/><br /><sub><b>André Almeida</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=ogedei-khan" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/snaggen"><img src="https://avatars.githubusercontent.com/u/6420639?v=4?s=100" width="100px;" alt="Mattias Eriksson"/><br /><sub><b>Mattias Eriksson</b></sub></a><br /><a href="https://github.com/Eugeny/russh/commits?author=snaggen" title="Code">💻</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!
