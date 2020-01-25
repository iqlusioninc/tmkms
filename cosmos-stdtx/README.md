# cosmos-stdtx.rs 🌌

[![Crate][crate-image]][crate-link]
[![Build Status][build-image]][build-link]
[![Apache 2.0 Licensed][license-image]][license-link]
![MSRV][rustc-image]

Extensible schema-driven [Cosmos] [StdTx] builder and serializer.

## About

**cosmos-stdtx.rs** is a Rust library for composing transactions in the [StdTx]
format used by several [Tendermint]-based networks.

It includes support for cryptographically signing transactions and serializing
them in the [Amino] encoding format.

Definitions of transaction types are easily extensible, and can be defined at
runtime by loading them from a TOML definition file. This allows
**cosmos-stdtx.rs** to be used with any [Tendermint]-based software which
uses the [StdTx] format without requiring upstream modifications.

## Minimum Supported Rust Version

- Rust **1.39+**

## License

Copyright © 2020 Tony Arcieri

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

[crate-image]: https://img.shields.io/crates/v/cosmos-stdtx.svg
[crate-link]: https://crates.io/crates/cosmos-stdtx
[build-image]: https://circleci.com/gh/tendermint/kms.svg?style=shield
[build-link]: https://circleci.com/gh/tendermint/kms
[license-image]: https://img.shields.io/badge/license-Apache2.0-blue.svg
[license-link]: https://github.com/tendermint/kms/blob/master/LICENSE
[rustc-image]: https://img.shields.io/badge/rustc-1.39+-blue.svg

[//]: # (general links)

[Cosmos]: https://cosmos.network/
[StdTx]: https://godoc.org/github.com/cosmos/cosmos-sdk/x/auth/types#StdTx
[Tendermint]: https://tendermint.com/
[Amino]: https://github.com/tendermint/go-amino
