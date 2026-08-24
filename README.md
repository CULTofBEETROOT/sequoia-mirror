Sequoia PGP
===========

Sequoia is an implementation of OpenPGP as defined by [RFC 9580] and
[RFC 9980] as well as the deprecated OpenPGP as defined by [RFC 4880],
and various related standards.

OpenPGP is a standard by the IETF.  It was derived from the PGP
software, which was created by Phil Zimmermann in 1991.

[RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html
[RFC 9980]: https://www.rfc-editor.org/rfc/rfc9980.html
[RFC 4880]: https://tools.ietf.org/html/rfc4880

Sequoia consists of several crates, providing both a low-level and a
high-level API for dealing with OpenPGP data.

Low-level API
-------------

The low-level API can be found in the [openpgp](./openpgp) crate.
This crate aims to provide a complete implementation of OpenPGP as
defined by [RFC 9580] and [RFC 9980] as well as the deprecated OpenPGP
as defined by [RFC 4880].  This includes support for unbuffered
message processing.

The [openpgp](./openpgp) crate tries hard to avoid dictating how
OpenPGP should be used.  This doesn't mean that we don't have opinions
about how OpenPGP should be used in a number of common scenarios (for
instance, message validation).

Mid-level API
-------------

Sequoia's mid-level API is implemented in various crates.  For
historical reasons, some are maintained in this repository, and some
are maintained outside of this repository.  These are the most
important crates:

  - [`sequoia-cert-store`](http://docs.rs/sequoia-cert-store): A store
    for certificates.
  - [`sequoia-keystore`](http://docs.rs/sequoia-keystore): A store for
    secret keys.
  - [`sequoia-wot`](http://docs.rs/sequoia-wot): An implementation of
    the Web-of-Trust, a PKI engine.
  - [`sequoia-policy-config`](http://docs.rs/sequoia-policy-config):
    Loads cryptographic policies from files.
  - [`sequoia-net`](./net): Network services for OpenPGP.
  - [`sequoia-ipc`](./ipc): Low-level IPC services for Sequoia.
  - [`sequoia-autocrypt`](./autocrypt): Low-level Autocrypt support.

High-level API
--------------

The high-level API is implemented in the [`sequoia`] crate.  The crate
aims to be usable by developers without deep understanding of the
OpenPGP standard or the Sequoia ecosystem.  To achieve this, it is
highly opinionated.  Nevertheless, because it builds on and reuses the
low-level data structures, it is often possible to tweak its behavior
when the semantics of the high-level functionality do not match the
requirements.

  [`sequoia`]: https://gitlab.com/sequoia-pgp/sequoia-sq/-/tree/main/lib

[`sequoia`]'s interface is similar to [`sq`]'s interface.

  [`sq`]: https://gitlab.com/sequoia-pgp/sequoia-sq/-/tree/main/tool

Command line interface
----------------------

We maintain [`sq`], a command line interface use OpenPGP conveniently
from the command line.  See the [sq user documentation] for
instructions, or browse the [manual pages].  `sq` is packaged for most
Linux distributions and should be easy to install.

[sq user documentation]: https://book.sequoia-pgp.org
[manual pages]: https://sequoia-pgp.gitlab.io/sequoia-sq/man/

We also maintain a minimalist command-line verification tool for
detached signatures called ['sqv'].

['sqv']: https://gitlab.com/sequoia-pgp/sequoia-sqv

Sequoia for GnuPG users
-----------------------

The Sequoia crates and `sq` provide good compatibility with existing
GnuPG installations.  For example, `sq` will discover all certificates
in GnuPG's keyrings, and can use secret keys managed by `gpg-agent`,
all without additional configuration.

For anyone directly or indirectly using GnuPG who wants to migrate to
Sequoia, there is a re-implementation and drop-in replacement of `gpg`
and `gpgv` called the [Sequoia Chameleon] (or just `gpg-sq` and
`gpgv-sq`).

[Sequoia Chameleon]: https://gitlab.com/sequoia-pgp/sequoia-chameleon-gnupg

LICENSE
=======

Sequoia is licensed under the GNU Library General Public License
version 2 or any later version.  See the file
[LICENSE.txt](LICENSE.txt) or visit
https://www.gnu.org/licenses/lgpl-2.0.html for details.

Using Sequoia
=============

If you want to use Sequoia from Rust in a binary crate, you can simply
register the dependency in your `Cargo.toml` file as with any other
project.  Please see [this guide] on how to use Sequoia in a library
crate, or how to control the cryptographic backend used by Sequoia.

```toml
sequoia-openpgp = "2"
```

Sequoia supports a number of different crypto backend.  Some of those
use C libraries, which must be present.  When building their
development packages also need to be installed. See the
**Requirements** section below.

[this guide]: ./openpgp/README.md#feature-flags

Features
--------

Sequoia is currently supported on a variety of platforms.

### Cryptography

By default Sequoia uses the Nettle cryptographic library (version
3.9.1 or up) but it can be used with different cryptographic backends
including OpenSSL, Botan, Rust Crypto and the native Windows
[Cryptographic API: Next Generation (CNG)].

The desired backend is enabled via Cargo features,
e.g. `crypto-nettle` or `crypto-cng`, and exactly one can be enabled
at a time.

Currently, the `crypto-nettle` feature is enabled by default -
regardless of the operating system used. If you choose to enable a
different backend, please make sure to disable the default first.

See [this guide] for more information.

Building Sequoia
================

Using Cargo
-----------

To build all Sequoia components, simply execute `cargo build
[--release] --all`.

## Requirements

Sequoia aims to be compatible with the version of `rustc` included in
[Debian testing].  Consequently, the MSRV tries to follow what is
available there.  Increasing the MSRV will be accompanied by a raise
in the minor version of all crates.

[Debian testing]: https://tracker.debian.org/pkg/rustc

Building Sequoia may require additional libraries.  These primarily
depend on the cryptographic backend that you choose to use.  If you
use `sequoia-net`, then you currently also need OpenSSL.  Please see
below for OS-specific commands to install the needed libraries when
using Nettle, the default cryptographic backend.

Notes:

  - Make sure your Rust compiler is new enough.  You can use [rustup]
    if your distribution only includes an older Rust version.
  - You need at least Nettle 3.9.1.  Debian 13 (trixie) and up is
    fine.
  - `libssl-dev` is only required by the `sequoia-net` crate and
    crates depending on it (`sq`).

[rustup]: https://rustup.rs/

### Debian

```shell
# apt install cargo clang git nettle-dev pkg-config libssl-dev
```

### Arch Linux

```shell
# pacman -S clang git pkgconf rustup --needed
```

### Fedora

```shell
# dnf install cargo clang git nettle-devel openssl-devel
```

### NixOS

Development environment for use with `nix-shell` or `direnv`:
<details>
  <summary>
    `shell.nix`
  </summary>

```nix
let
  oxalica_overlay = import (builtins.fetchTarball
    "https://github.com/oxalica/rust-overlay/archive/master.tar.gz");
  nixpkgs = import <nixpkgs> { overlays = [ oxalica_overlay ]; };
  rust_channel = nixpkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain;
in with nixpkgs;
pkgs.mkShell {
  buildInputs = [
    nettle
    openssl
  ];

  nativeBuildInputs = [
    (rust_channel.override{
        extensions = [ "rust-src" "rust-std" ];
    })

    llvmPackages.clang
    pkgconfig

    # tools
    codespell
  ];

  RUST_BACKTRACE = 1;

  # compilation of -sys packages requires manually setting LIBCLANG_PATH
  LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
}
```

</details>


### macOS

#### MacPorts

```shell
$ sudo port install cargo nettle pkgconfig
```

#### Brew

```shell
$ brew install rust nettle
```

### Windows

Please make sure to preserve line-endings when cloning the Sequoia
repository.  The relevant git option is `core.autocrlf` which must be
set to `false`.

#### CNG

On Windows Sequoia PGP can use one of several cryptographic backends.
The recommended one is Windows Cryptography API (CNG) as it doesn't
require as many additional dependencies.  The standard tooling
required to build native dependencies ([Visual Studio Build Tools][])
is still needed.

[Visual Studio Build Tools]: https://visualstudio.microsoft.com/downloads?q=build+tools

When building, make sure to disable default features (to disable
Nettle) and enable the CNG via `crypto-cng` Cargo feature:

```bash
$ cargo build --no-default-features --features crypto-cng,compression # Only change crypto backend
```

#### Nettle

It is also possible to use Sequoia's default backend (Nettle) on
Windows through [MSYS2][].

[MSYS2]: https://www.msys2.org

You can install the needed libraries with the following command:

```shell
$ pacman -S mingw-w64-x86_64-{bzip2,clang,gcc,pkg-config,nettle}
```

#### Other

MSYS2 can also be used to build Sequoia with the Windows-native CNG
backend.  The list of packages is the same as for Nettle with the
exception of `mingw-w64-x86_64-nettle` which is not needed.  Build
command is the same as for the CNG backend.

Sequoia PGP can also be built for 32-bit Windows.  See
`.gitlab-ci.yml` for detailed example.

Additionally, the Rust backend can also be used on Windows. See the
`sequoia-openpgp` crate's documentation for details.

Getting help
============

Links to Sequoia's documentation are here:
https://sequoia-pgp.org/docs/

You can join our mailing list by sending a mail to
devel-subscribe@lists.sequoia-pgp.org.

You can talk to us using IRC on [OFTC](https://www.oftc.net/) in `#sequoia`.

Reporting bugs
==============

Please report bug and feature requests to [our bugtracker].  If you
find a security vulnerability, please refer to our [security
vulnerability guide].

  [our bugtracker]: https://gitlab.com/sequoia-pgp/sequoia/issues
  [security vulnerability guide]: https://gitlab.com/sequoia-pgp/sequoia/-/blob/main/doc/security-vulnerabilities.md


### Contributing

You want to help, great!
We have two guides for you to read: [our guide for new contributors](./GETTING_STARTED.md),
or you can take a look at our general [contributing](./CONTRIBUTING.md) guide.
