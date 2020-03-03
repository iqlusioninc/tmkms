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

<https://github.com/iqlusioninc/tmkms/blob/develop/README.yubihsm.md>

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
