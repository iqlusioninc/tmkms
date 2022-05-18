# Fortanix DSM + Tendermint KMS

Fortanix Data Security Manager (DSM) provides integrated data security with encryption, multicloud key management, tokenization, and other capabilities from one platform. 

This document describes how to configure Fortanix DSM for production use with Tendermint KMS.

## Compiling `tmkms` with Fortanix DSM support

Refer the main README.md for compiling `tmkms`
from source code. You will need the prerequisities mentioned as indicated above.

There are two ways to install `tmkms` with Fortanix DSM, you need to pass the `--features=fortanixdsm` parameter to cargo.

### Compiling from source code (via git)

`tmkms` can be compiled directly from the git repository source code using the
following method.

```
$ git clone https://github.com/iqlusioninc/tmkms.git && cd tmkms
[...]
$ cargo build --release --features=fortanixdsm
```

If successful, this will produce a `tmkms` executable located at
`./target/release/tmkms`

### Installing with the `cargo install` command

With Rust (1.40+) installed, you can install tmkms with the following:

```
cargo install tmkms --features=fortanixdsm
```

Or to install a specific version (recommended):

```
cargo install tmkms --features=fortanixdsm --version=0.4.0
```

This command installs `tmkms` directly from packages hosted on Rust's
[crates.io] service. Package authenticity is verified via the
[crates.io index] (itself a git repository) and by SHA-256 digests of
released artifacts.

However, if newer dependencies are available, it may use newer versions
besides the ones which are "locked" in the source code repository. We
cannot verify those dependencies do not contain malicious code. If you would
like to ensure the dependencies in use are identical to the main repository,
please build from source code instead.

## Production Fortanix DSM setup

`tmkms` contains support for Fortanix DSM backend, which enables tmkms to access the secure keys on DSM. This requires creation of the keys on the DSM which can be done by referring to this [guide](https://support.fortanix.com/hc/en-us/articles/360038354592-User-s-Guide-Fortanix-Data-Security-Manager-Key-Lifecycle-Management). Creating, enabling and marking the key for signing and export should enable tmkms to use the keys on DSM.

### Configuring `tmkms` for initial setup

In order to perform setup, `tmkms` needs a  configuration file which
contains the authentication details needed to authenticate to the DSM with an API key.

This configuration should be placed in a file called: `tmkms.toml`.
You can specifty the path to the config with either `-c /path/to/tmkms.toml` or else tmkms will look in the current working directory for the same file.

example: 

```toml
[[providers.fortanixdsm]]
api_endpoint = "https://sdkms.fortanix.com"
api_key = "Nzk5MDQ3ZGUtN2Q2NS00OTRjLTgzMDMtNjQwMTlhYzdmOGUzOlF1SU93ZXJsOFU4VUdEWEdQMmx1dFJOVjlvMTRSd3lhNnVDNVNhVkpZOVhzYVgyc0pOVGRQVGJ0RjZJdmVLMy00X05iTEhxMkowamF3UGVPaXJEWEd3"
signing_keys = [
    { chain_ids = ["$CHAIN_ID"], type = "account", key_id = "72e9ed9e-9eb4-46bd-a135-e78ed9bfd611" },
    { chain_ids = ["$CHAIN_ID"], type = "consensus", key_name = "My Key" },
]
```
You can get the api key from the app that holds the security object(key) in DSM. Key can be identified by either using the key-id or the key name, which are available in the details of the security object created on DSM. If you already have the key, you can import the key on DSM following the same DSM user guide mentioned above.

### Generating keys on DSM
1. Create a security group on DSM, example 'TMKMS group'.
2. Create a APP under the same security group on DSM, example 'TMKMS'. Select Authentication method to be 'API Key' and copy the API key for use in config fie (tmkms.toml).

3. Create a security Object under the same group in DSM, so that the API key for the app can be used to access the key under the same group. The type of key must be `EC CurveEd25519` for consensus key and `Secp256k1` for account key. Proceed with creation of these keys on DSM and the required key ID has to be passed in the config file, this can be obtained from the details on the security object section on DSM.
4. To import an existing tendermint key use the following script to convert a tendermint key to Fortanix DSM accepted key format.
```
#!/bin/bash
# Usage: tendermint-ed25519.sh <input-tendermint> <output-private-p8der> <output-public-p8der>

gokey=$(jq -r .priv_key.value $1 | base64 -d| xxd -p -c 64)
echo 302e 0201 0030 0506 032b 6570 0422 0420 "${gokey:0:64}" | xxd -p -r > $2
echo 302a 3005 0603 2b65 7003 2100 "${gokey:64}" | xxd -p -r > $3
```
