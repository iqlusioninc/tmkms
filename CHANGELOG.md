# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.11.0 (2022-02-11)
### Added
- Sentinel config ([#351])
- Osmosis config ([#370])
- Persistence config ([#373])
- New `key_format` type: `cosmos-json` ([#407])

### Changed
- Rust 2021 edition upgrade ([#465])
- Dependency updates:
  - `abscissa` framework v0.6 upgrade: includes new `clap` v3 argument parser ([#478])
  - `k256` to v0.10 ([#457])
  - `signature` v1.3.2 ([#417])
  - `stdtx` v0.6 ([#457])
  - `tendermint.rs` v0.23.3 ([#457])
  - `yubishm.rs` v0.40 ([#457])

### Fixed
- Sporadic deadlocks when using the YubiHSM2 backend ([#37])
- `tmkms keys import -t priv_validator` ([#350])

[#37]: https://github.com/iqlusioninc/tmkms/pull/37
[#350]: https://github.com/iqlusioninc/tmkms/pull/350
[#351]: https://github.com/iqlusioninc/tmkms/pull/351
[#370]: https://github.com/iqlusioninc/tmkms/pull/370
[#373]: https://github.com/iqlusioninc/tmkms/pull/373
[#407]: https://github.com/iqlusioninc/tmkms/pull/407
[#417]: https://github.com/iqlusioninc/tmkms/pull/417
[#457]: https://github.com/iqlusioninc/tmkms/pull/457
[#465]: https://github.com/iqlusioninc/tmkms/pull/465
[#478]: https://github.com/iqlusioninc/tmkms/pull/478

## 0.10.1 (2021-04-22)
### Changed
- Bump tendermint-rs crates to v0.19 ([#327])

[#327]: https://github.com/iqlusioninc/tmkms/pull/327

## 0.10.0 (2021-02-16)

This release is compatible with [tendermint v0.34] or older.

It includes initial support for "Stargate", an upgrade to Cosmos Hub which
will enable IBC. It also retains backwards compatibility for all older versions
of Tendermint via the `[validator.protocol_version]` setting in `tmkms.toml`.

For Stargate, configure this value to:

```toml
[[validator]]
chain_id = "cosmoshub-4"
protocol_version = "v0.34"
state_file = "/path/to/cosmoshub-4-state.json"
```

Also make sure to update the `state_file` with a new filename
(e.g. `cosmoshub-4-state.json`) and retain the old state file for `cosmoshub-3`.
You'll need the old state file if a chain rollback is required!

### Added
- Tendermint v0.34 signing compatibility ([#211])

### Changed
- rpc: add support for protobuf-encoded messages ([#201])
- tx-signer: retry failed transactions up to 3 times ([#213])
- Use `consensus::State` serializers from `tendermint-rs` ([#232])
- Use `tendermint-p2p` crate for secret connection ([#234], [#290])
- Bump `stdtx` to v0.4 ([#249])
- Bump `tendermint-rs` to v0.18 ([#290])
- Bump `tokio` to v1.0 ([#290])
- Bump `yubihsm` crate dependency to v0.38 ([#289])
- MSRV 1.46+ ([#249])

[tendermint v0.34]: https://github.com/tendermint/tendermint/blob/master/CHANGELOG.md#v0340
[#201]: https://github.com/iqlusioninc/tmkms/pull/201
[#211]: https://github.com/iqlusioninc/tmkms/pull/211
[#213]: https://github.com/iqlusioninc/tmkms/pull/213
[#232]: https://github.com/iqlusioninc/tmkms/pull/232
[#234]: https://github.com/iqlusioninc/tmkms/pull/234
[#249]: https://github.com/iqlusioninc/tmkms/pull/249
[#289]: https://github.com/iqlusioninc/tmkms/pull/289
[#290]: https://github.com/iqlusioninc/tmkms/pull/290

## 0.9.0 (2020-10-22)

This release is compatible with [tendermint v0.33] or older.

It's primarily a maintenance release containing dependency upgrades as well as
a small number of breaking changes.

While it contains preliminary work to support newer versions (e.g. Stargate),
this work is in a partial/incomplete state and it is *NOT* yet compatible.
We intend to have full Stargate (Tendermint v0.34) support in the *next*
release (v0.10).

Notable breaking changes:

- The `ledgertm` cargo feature has been renamed to `ledger`
- The `protocol_version` field of `[[validator]]` is now mandatory.
  Please set it to `legacy` if it was omitted before.
- The JSONRPC format used by `tx-signer` has changed. Please see `README.txsigner.md`.

### Added
- HTTPS support ([#188])
- `tx-signer`: JSONRPC request params ([#170])

### Changed
- Rename `ledgertm` Cargo feature to `ledger` ([#186])
- Vendor the `signatory-ledger-tm` crate into the tmkms app ([#186])
- Bump dependencies ([#104], [#115], [#121], [#122], [#183], [#184]
- `tx-signer`: logging improvements ([#146], [#152], [#154], [#167], [#177])
- `tx-signer`: use `broadcast_tx_commit` instead of `broadcast_tx_sync` ([#165])
- `tx-signer`: include signer's public key in transaction ([#148])

### Fixed
- `tx-signer`: error and sequence number handling ([#181], [#178], [#168])
- Bogus secret connection identity key handling - non-security-critical bug ([#164])

[#188]: https://github.com/iqlusioninc/tmkms/pull/188
[#181]: https://github.com/iqlusioninc/tmkms/pull/181
[#186]: https://github.com/iqlusioninc/tmkms/pull/186
[#186]: https://github.com/iqlusioninc/tmkms/pull/186
[#184]: https://github.com/iqlusioninc/tmkms/pull/184
[#183]: https://github.com/iqlusioninc/tmkms/pull/183
[#178]: https://github.com/iqlusioninc/tmkms/pull/178
[#177]: https://github.com/iqlusioninc/tmkms/pull/177
[#170]: https://github.com/iqlusioninc/tmkms/pull/170
[#168]: https://github.com/iqlusioninc/tmkms/pull/168
[#167]: https://github.com/iqlusioninc/tmkms/pull/167
[#165]: https://github.com/iqlusioninc/tmkms/pull/165
[#164]: https://github.com/iqlusioninc/tmkms/pull/164
[#154]: https://github.com/iqlusioninc/tmkms/pull/154
[#152]: https://github.com/iqlusioninc/tmkms/pull/152
[#148]: https://github.com/iqlusioninc/tmkms/pull/148
[#146]: https://github.com/iqlusioninc/tmkms/pull/146
[#122]: https://github.com/iqlusioninc/tmkms/pull/122
[#121]: https://github.com/iqlusioninc/tmkms/pull/121
[#115]: https://github.com/iqlusioninc/tmkms/pull/115
[#104]: https://github.com/iqlusioninc/tmkms/pull/104

## 0.8.0 (2020-07-02)

This release adds initial support for [tendermint v0.33].

### Added
- yubihsm: show labels when listing keys ([#102])
- yubihsm: add account key support to `yubihsm keys generate` ([#101])
- Transaction Signer (`tx-signer`) documentation ([#98])
- `tmkms init` subcommand ([#89])
- Initial ECDSA support ([#76], [#86])
- Transaction signer ([#78])
- Support both the Tendermint legacy and v0.33 secret connection handshake ([#58])

### Changed
- Minimum Supported Rust Version: 1.41.0
- Bump `prost-amino` to v0.6 ([#92])
- Replace `atomicwrites` dependency with `tempfile` ([#62])
- Refactor locking; add more debug locking ([#60])

[tendermint v0.33]: https://github.com/tendermint/tendermint/blob/master/CHANGELOG.md#v033
[#102]: https://github.com/iqlusioninc/tmkms/pull/102
[#101]: https://github.com/iqlusioninc/tmkms/pull/101
[#98]: https://github.com/iqlusioninc/tmkms/pull/98
[#92]: https://github.com/iqlusioninc/tmkms/pull/92
[#89]: https://github.com/iqlusioninc/tmkms/pull/89
[#86]: https://github.com/iqlusioninc/tmkms/pull/86
[#78]: https://github.com/iqlusioninc/tmkms/pull/78
[#76]: https://github.com/iqlusioninc/tmkms/pull/76
[#62]: https://github.com/iqlusioninc/tmkms/pull/62
[#60]: https://github.com/iqlusioninc/tmkms/pull/60
[#58]: https://github.com/iqlusioninc/tmkms/pull/58

## 0.7.3 (2020-05-12)

- Bump `tendermint` crate to v0.13 ([#36])
- Bump `signatory` to v0.19 ([#36])
- Bump `yubihsm` crate to v0.33 ([#36])

[#36]: https://github.com/iqlusioninc/tmkms/pull/36

## 0.7.2 (2020-03-03)

- Upgrade `hkdf` to v0.8 ([#13])
- Move repository to `iqlusioninc/tmkms` ([#10])
- Upgrade `yubihsm` to v0.32 ([#6])

[#13]: https://github.com/iqlusioninc/tmkms/pull/13
[#10]: https://github.com/iqlusioninc/tmkms/pull/10
[#6]: https://github.com/iqlusioninc/tmkms/pull/6

## 0.7.1 (2020-01-23)

- Remove explicit dependency on the `log` crate
- Remove `byteorder` dependency
- Replace `tiny-bip39` with the equivalent `hkd32` functionality
- Replace `lazy_static` with `once_cell`
- Update `rpassword` requirement from 3.0 to 4.0
- Upgrade `x25519-dalek` to v0.6; remove `rand_os`
- Remove `failure`
- Update to `tendermint-rs` 0.12.0-rc0; `prost-amino` v0.5; `signatory v0.18`

## 0.7.0 (2019-12-16)

- Upgrade to `abscissa` v0.5
- Validate chains are registered on startup
- Use an initial height of 0 in default chain state
- Upgrade `tendermint-rs` to v0.11
- Upgrade to `signatory` v0.16; `yubihsm` v0.29.0
- Use the `chacha20poly1305` crate for Secret Connection
- Vendor Secret Connection impl back from `tendermint-rs`
- Add timeout to TCP socket
- Double signing detection and logging improvements
- Log signing message type during attempted double sign events

## 0.6.3 (2019-08-07)

- Detect and don't attempt to recover from PoisonError

## 0.6.2 (2019-08-07)

- chain/state: Avoid panicking in update_consensus_state

## 0.6.1 (2019-08-06)

- [`abscissa` crate v0.3]
- Refactor `Session` to remove code duplication
- Remove signal handlers
- Double signing - allow some block ID switches
- Consider signed `<nil>` votes to be double signs

[`abscissa` crate v0.3]: https://github.com/iqlusioninc/abscissa/pull/127

## 0.6.0 (2019-07-30)

This release is tested against [tendermint v0.31] and known to be compatible
with [tendermint v0.32].

### Upgrade Notes

#### `state_file` syntax changes

The validator state files use an incompatible syntax from Tendermint KMS v0.5.
It has been changed to match the conventions used by the rest of Tendermint,
where integer values are stored in strings rather than JSON integers.

When upgrading, you will need to either *delete existing state files* 
(they will be recreated automatically), or ensure the integer `height` and
`round` fields contained within these files are quoted in strings, e.g.
`{"height":"123456","round":"0",...}`.

#### Unknown fields now disallowed in `tmkms.toml`

The previous parser for `tmkms.toml` ignored unknown attributes in the
config file. This means it would often ignore syntax errors, spelling mistakes,
or attributes in the wrong location when parsing files.

This has been changed to explicitly reject such fields, however please be aware
if your config file contained invalid syntax, it will now be rejected by the
parser and the KMS will no longer boot.

We suggest validating the configuration in a staging or other noncritical
deployment of the KMS in order to ensure your configuration does not contain
accidental misconfigurations which were previously uncaught.

#### YubiHSM improvements

This release contains many improvements for users of the `yubihsm` backend:

- New `yubihsm-server` feature: this release includes support for the KMS
  exposing an HTTP service which is compatible with Yubico's
  `yubihsm-connector` service. This allows for concurrently administering
  a YubiHSM2 while the KMS is running, either through `tmkms yubihsm`
  (see additional notes below) or via Yubico's `yubihsm-shell`.
- Loopback support for `tmkms yubihsm`: the CLI functionality in the KMS for
  administering YubiHSMs can now be configured to connect to the KMS's
  own `yubihsm-server`. Additionally it can also be configured to use a
  different authentication key, and to prompt for a password as opposed to
  using one in the configuration file.

For more information on these changes, please see the "yubihsm-server feature"
section in the Tendermint KMS YubiHSM docs:

<https://github.com/iqlusioninc/tmkms/blob/main/README.yubihsm.md>

### Detailed Changes

- [`tendermint` crate v0.10.0]
- Double signing logging improvements
- Log `tendermint::consensus::State` height/round/step
- `yubihsm keys import`: base64 support
- `yubihsm`: Support for reading password from a file
- `softsign`: Fix private key decoding + `import` command
- `softsign`: Add subcommand; move `keygen` under it
- `yubihsm setup`: use `hkd32` crate to derive key hierarchy
- `yubihsm setup`: Collect 256-bits entropy from both RNGs
- [`abscissa` crate v0.2]
- Log durations for each signing operation
- Add `serde(deny_unknown_fields)` to all config structs
- `tmkms yubihsm keys list`: Use chain-specific formatters
- `yubihsm-server`: Allow CLI commands to use loopback connection
- `yubihsm-server`: Optional `yubihsm-connector` compatibility
- Send `RemoteSignerError` response to validator on double sign
- Logging improvements
- yubihsm: Mark imported `priv_validator.json` keys as re-exportable
- ledger: Add init commands
- Add `max_height` support for stopping chains at specific heights
- Chain-specific keyrings / multitenancy
- ledger: Use `ledger-tendermint` backend

[tendermint v0.31]: https://github.com/tendermint/tendermint/blob/master/CHANGELOG.md#v0316
[tendermint v0.32]: https://github.com/tendermint/tendermint/blob/master/CHANGELOG.md#v0320
[`abscissa` crate v0.2]: https://github.com/iqlusioninc/abscissa/pull/98
[`tendermint` crate v0.10.0]: https://crates.io/crates/tendermint/0.10.0

## 0.5.0 (2019-03-13)

- [`tendermint` crate v0.5.0]
- Optional peer ID verification
- Bump subtle-encoding dependency to v0.3.3
- Allow setting config path via `TMKMS_CONFIG_FILE` env var
- yubihsm: Add back HTTP connector support
- Initial Tendermint `[chain]` registry in tmkms.toml
- Disable 'softsign' backend by default
- State tracking for double sign protection (thanks [@zmanian]!)

[`tendermint` crate v0.5.0]: https://crates.io/crates/tendermint/0.5.0

## 0.4.0 (2019-03-05)

- [`tendermint` crate v0.3.0]
- yubihsm: Support for exporting/importing wrapped (encrypted) keys
- yubihsm setup
- Ledger integration

[`tendermint` crate v0.3.0]: https://crates.io/crates/tendermint/0.3.0

## 0.3.0 (2019-01-23)

- Add ability to terminate on SIGTERM or SIGINT
- Remove `PoisonPillMsg` 

## 0.2.4 (2019-01-18)

- Refactor client/tests to always dial out to tendermint/gaiad
- Migrate to rust 2018 edition

## 0.2.3 (2018-12-08)

- Lower reconnect delay to 1s

## 0.2.2 (2018-12-03)

- Allow empty BlockIds in validation method

## 0.2.1 (2018-11-27)

- Encode node (and softwign) private keys as Base64
- Add integration tests for yubihsm subcommands
- Fix `tmkms yubihsm keys import` command

## 0.2.0 (2018-11-20)

- Add `tmkms yubihsm keys import` command
- Simplify `tmkms.toml` syntax
- Minor clarifications/fixes

## 0.1.0 (2018-11-13)

- Initial validator signing support
- Extract `tendermint` crate as a reusable Rust library
- Support for Bech32-formatted Cosmos keys/addresses
- Validator signing via Unix domain socket IPC

## 0.0.1 (2018-10-16)

- Initial "preview" release
