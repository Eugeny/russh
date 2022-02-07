# Thrussh

A full implementation of the SSH 2 protocol, both server-side and client-side.

Thrussh is completely asynchronous, and can be combined with other protocols using [Tokio](//tokio.rs).

## Contributing

We welcome contributions. Currently, the main areas where we need help are:

- Handling SSH keys correctly on all platforms. In particular, interactions with agents, PGP, and password-protected/encrypted keys are not yet implemented.

- Auditing our code, and writing tests. The code is written so that the protocol can be entirely run inside vectors (instead of network sockets).

By contributing, you agree to license all your contributions under the Apache 2.0 license.

Moreover, the main platform for contributing is [the Nest](//nest.pijul.com/pijul/thrussh), which is still at an experimental stage. Therefore, even though we do our best to avoid it, our repository might be reset, causing the patches of all contributors to be merged.


## Issue Reporting

Please report bugs on the [issue page of this repository](//nest.pijul.com/pijul/thrussh).
Thrussh has a full disclosure vulnerability policy.
Please do NOT attempt to report any security vulnerability in this code privately to anybody.
