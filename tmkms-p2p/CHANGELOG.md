# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.4.0 (2025-08-22)
### Added
- `MAX_MSG_LEN` constant (#1053)

### Changed
- Drop `tendermint-proto` dependency (#1047)
- Move `ReadMsg`/`WriteMsg` generic to trait (#1050)

### Removed
- `Error::BufferOverflow` (#1051)
- `Error::Internal` (#1052)
- `SecretConnection::split` (#1054)
- Explicit low order point check (#1055)

## 0.3.0 (2025-08-20)
### Added
- Re-export `IdentitySecret` (#1032)
- `Error::Internal` (#1037)

### Changed
- Rename `Error::MessageOversized` to `MessageTooBig` (#1037)
- Replace `Error::UnsupportedKey` with a `CryptoError` (#1037)

### Removed
- `Error::MissingKey` (#1037)
- `Error::MissingSecret` (#1037)
- `Error::TransportClone` (#1034)
- `Error::UnsupportedKey` (#1037)

## 0.2.0 (2025-08-20)
### Added
- `ReadMsg`/`WriteMsg` traits (#1018)

### Changed
- Replace crypto `Error` variants with opaque `CryptoError` (#1021)

### Removed
- `transport` module (#1011)
- `tendermint` crate dependency (#1015)
- `DATA_MAX_SIZE` constant (#1022)

## 0.1.0 (2025-08-19)
- Initial release
