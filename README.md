# meka-dev/tmkms

This fork of [iqlusion/tmkms](https://github.com/iqlusion/tmkms)
includes patches to support signing of requests needed by the
[Mekatek builder API](https://api.mekatek.xyz).

| iqlusioninc/tmkms  | meka-dev/tmkms                         |
|:-------------------|:---------------------------------------|
| [v0.12.2][v0.12.2] | [v0.12.2-mekatek.1][v0.12.2-mekatek.1] |

[v0.12.2]:           https://github.com/iqlusioninc/tmkms/releases/tag/v0.12.2
[v0.12.2-mekatek.1]: https://github.com/meka-dev/tmkms/releases/tag/v0.12.2-mekatek.1

```shell
git clone https://github.com/meka-dev/tmkms
cd tmkms
git checkout v0.12.2-mekatek.1
cargo build --release --features=softsign # or yubihsm, ledger, etc.
target/release/tmkms version
```
