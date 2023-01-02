# Tendermint KMS 🔐

[![Crate][crate-image]][crate-link]
[![Build Status][build-image]][build-link]
[![Apache 2.0 Licensed][license-image]][license-link]
![MSRV][rustc-image]

Key Management System for [Tendermint] applications such as
[Cosmos Validators].

Provides isolated, optionally HSM-backed signing key management for Tendermint
applications including validators, oracles, IBC relayers, and other transaction
signing applications.

## About

This repository contains `tmkms`, a key management service intended to be deployed
in conjunction with [Tendermint] applications (ideally on separate physical hosts)
which provides the following:

- **High-availability** access to validator signing keys
- **Double-signing** prevention even in the event the validator process is compromised
- **Hardware security module** storage for validator keys which can survive host compromise

## Status

Tendermint KMS is currently *beta quality*. It has undergone one security audit
with only one low-severity finding.

### Double Signing / High Availability

Tendermint KMS implements *beta quality* double signing detection.
It has undergone some testing, however we do not (yet) recommend using the KMS
in conjunction with multiple simultaneously active validators on the same
network for prolonged periods of time.

In particular, there is presently **no double signing defense** in the case
that multiple KMS instances are running simultaneously and connecting to
multiple validators on the same network.

## Signing Providers

You **MUST** select one or more signing provider(s) when compiling the KMS,
passed as the argument to the `--features` flag (see below for more
instructions on how to build Tendermint KMS).

The following signing backend providers are presently supported:

#### Hardware Security Modules (recommended)
- [FortanixDSM](./README.fortanixdsm.md) (gated under the `fortanixdsm` cargo feature. See [README.fortanixdsm.md](./README.fortanixdsm.md) 
- [YubiHSM2] (gated under the `yubihsm` cargo feature. See [README.yubihsm.md][yubihsm2] for more info)
- [Ledger] (gated under the `ledger` cargo feature)

#### Software-Only (not recommended)

- `softsign` backend which uses [ed25519-dalek]

## Supported Platforms

`tmkms` should build on any [supported Rust platform] which is also supported
by [libusb], however there are some platforms which meet those criteria which
are unsuitable for cryptography purposes due to lack of constant-time CPU
instructions. Below are some of the available tier 1, 2, and 3 Rust platforms
which meet our minimum criteria for KMS use.

NOTE: `tmkms` is presently tested on Linux/x86_64. We don't otherwise guarantee
support for any of the platforms below, but they theoretically meet the necessary
prerequisites for support.

### Operating Systems

- Linux (recommended)
- FreeBSD
- NetBSD
- OpenBSD
- macOS

### CPU Architectures

- `x86_64` (recommended)
- `arm` (32-bit ARM)
- `aarch64` (64-bit ARM)
- `riscv32` (32-bit RISC-V)
- `riscv64` (64-bit RISC-V)

## Installation

You will need the following prerequisites:

- **Rust** (stable; **1.60+**): https://rustup.rs/
- **C compiler**: e.g. gcc, clang
- **pkg-config**
- **libusb** (1.0+). Install instructions for common platforms:
  - Debian/Ubuntu: `apt install libusb-1.0-0-dev`
  - RedHat/CentOS: `yum install libusb1-devel`
  - macOS (Homebrew): `brew install libusb`

NOTE (x86_64 only): Configure `RUSTFLAGS` environment variable:
`export RUSTFLAGS=-Ctarget-feature=+aes,+ssse3`

There are two ways to install `tmkms`: either compiling the source code after
cloning it from git, or using Rust's `cargo install` command.

### Compiling from source code (via git)

`tmkms` can be compiled directly from the git repository source code using the
following method.

The following example adds `--features=yubihsm` to enable YubiHSM 2 support.

```
$ git clone https://github.com/iqlusioninc/tmkms.git && cd tmkms
[...]
$ cargo build --release --features=yubihsm
```

Alternatively, substitute `--features=ledger` to enable Ledger support.

If successful, this will produce a `tmkms` executable located at
`./target/release/tmkms`

### Installing with the `cargo install` command

With Rust (1.56+) installed, you can install tmkms with the following:

```
cargo install tmkms --features=yubihsm
```

Or to install a specific version (recommended):

```
cargo install tmkms --features=yubihsm --version=0.4.0
```

Alternatively, substitute `--features=ledger` to enable Ledger support.

## Configuration: `tmkms init`

The `tmkms init` command can be used to generate a directory containing
the configuration files needed to run the KMS. Run the following:

```
$ tmkms init /path/to/kms/home
```

This will output a `tmkms.toml` file, a `kms-identity.key` (used to authenticate
the KMS to the validator), and create `secrets` and `state` subdirectories.

Please look through `tmkms.toml` after it's generated, as various sections
will require some customization.

The `tmkms init` command also accepts a `-n` or `--networks` argument which can
be used to specify certain well-known Tendermint chains to initialize:

```
$ tmkms init -n cosmoshub,irishub,columbus /path/to/kms/home
```

## Running: `tmkms start`

After creading the configuration, start `tmkms` with the following:

```
$ tmkms start
```

This will read the configuration from the `tmkms.toml` file in the current
working directory.

To explicitly specify the path to the configuration, use the `-c` flag:

```
$ tmkms start -c /path/to/tmkms.toml
```

## Development

The following are instructions for setting up a development environment.
They assume you've already followed steps 1 & 2 from the Installation
section above.

- Install **rustfmt**: `rustup component add rustfmt`
- Install **clippy**: `rustup component add clippy`

Alternatively, you can build a Docker image from the [Dockerfile] in the top
level of the repository, which is what is used to run tests in CI.

Before opening a pull request, please run the checks below:

### Testing

Run the test suite with:

```
cargo test --all-features -- --test-threads 1
```

### Format checking (rustfmt)

Make sure your code is well-formatted by running:

```
cargo fmt
```

### Lint (clippy)

Lint your code (i.e. check it for common issues) with:

```
cargo clippy
```

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/tmkms.svg
[crate-link]: https://crates.io/crates/tmkms
[build-image]: https://github.com/iqlusioninc/tmkms/workflows/CI/badge.svg?branch=main&event=push
[build-link]: https://github.com/iqlusioninc/tmkms/actions
[license-image]: https://img.shields.io/badge/license-Apache2.0-blue.svg
[license-link]: https://github.com/iqlusioninc/tmkms/blob/main/LICENSE
[rustc-image]: https://img.shields.io/badge/rustc-1.60+-blue.svg

[//]: # (general links)

[Tendermint]: https://tendermint.com/
[Cosmos Validators]: https://cosmos.network/docs/gaia/validators/validator-faq.html
[YubiHSM2]: https://github.com/iqlusioninc/tmkms/blob/main/README.yubihsm.md
[Ledger]: https://www.ledger.com/
[ed25519-dalek]: https://github.com/dalek-cryptography/ed25519-dalek
[supported Rust platform]: https://forge.rust-lang.org/platform-support.html
[libusb]: https://libusb.info/
[Dockerfile]: https://github.com/iqlusioninc/tmkms/blob/main/Dockerfile
