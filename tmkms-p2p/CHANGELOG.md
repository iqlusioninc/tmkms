# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
