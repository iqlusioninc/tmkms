# HashiCorp Vault + TMKMS

HashiCorp Vault's `transit` engine mainly designed for data-in-transit encryption, it also provides additional features (sign and verify data, generate hashes and HMACs of data, and act as a source of random bytes).

This implementation will use Vault as `signer as a service` where private key will not ever leave Vault


This document describes how to configure HashiCorp Vault for production use with Tendermint KMS.

## Setting up Vault for `signer-as-service`
Start vault instance as per Hashicorp tutorial

following script sets up Vault's configuration. Script designed for single chain signing... Extend it with additional keys+policies for additional chains. These are steps for `admin`
```
#!/bin/bash
#login with root token 
vault login

echo "\nenabling transit engine..."
vault secrets enable transit
echo "\nenabling transit's engine sign path..."
vault secrets enable -path=sign transit

echo "\ncreating cosmoshub signing key..."
vault write transit/keys/cosmoshub-sign-key type=ed25519

echo "\ncreating policy..."
cat <<EOF | vault policy write tmkms-transit-sign-policy -
path "transit/sign/cosmoshub-sign-key" {
  capabilities = [ "update" ]
}
EOF

echo "\ncreating policy's token..."
vault token create -policy=tmkms-transit-sign-policy
```
Last step creates token that will be used for all interactios with Vault (not the root token)
```
Key                  Value
---                  -----
token                hvs.CAESIPb9syz_Rso8tLcXIjKc9_mHHwxWXVuHsdC7Fo02OyiSGh4KHGh2cy5pNmtSdTZFUmxWZ0xGa1ByWkFlSFV4ZTY
token_accessor       xNGZ1xuhzDHIuvuwnsvwO2h6
token_duration       768h
token_renewable      true
token_policies       ["default" "tmkms-transit-sign-policy"]
identity_policies    []
policies             ["default" "tmkms-transit-sign-policy"]

```
this is the token example to be used onward
`hvs.CAESIPb9syz_Rso8tLcXIjKc9_mHHwxWXVuHsdC7Fo02OyiSGh4KHGh2cy5pNmtSdTZFUmxWZ0xGa1ByWkFlSFV4ZTY`
to get policy token and verify that signing works
```
VAULT_TOKEN=<...> vault write transit/sign/<...sign key...> plaintext=$(base64 <<< "some-data")
```


## Compiling `tmkms` with HashiCorp Vault support

Refer the main README.md for compiling `tmkms`
from source code. You will need the prerequisities mentioned as indicated above.

There are two ways to install `tmkms` with HashiCorp Vault, you need to pass the `--features=hashicorp` parameter to cargo.

### Compiling from source code (via git)

`tmkms` can be compiled directly from the git repository source code using the
following method.

```
$ git clone https://github.com/iqlusioninc/tmkms.git && cd tmkms
[...]
$ cargo build --release --features=hashicorp
```

If successful, this will produce a `tmkms` executable located at
`./target/release/tmkms`

### Installing with the `cargo install` command

With Rust (1.40+) installed, you can install tmkms with the following:

```
cargo install tmkms --features=hashicorp
```

Or to install a specific version (recommended):

```
cargo install tmkms --features=hashicorp --version=0.4.0
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


to run
```
cargo run --features=hashicorp -- -c /path/to/tmkms.toml 
```

## Production HashiCorp Vault setup

`tmkms` contains support for HashiCorp Vault service, which enables tmkms to access the secure keys, stored in HashiCorp Vault's transit engine. This requires creation of the keys in Vault which can be done by referring to this [guide](https://www.vaultproject.io/docs/secrets/transit). Creating the key for signing and export should enable tmkms to use the keys on HashiCorp Vault.

### Configuring `tmkms` for initial setup

In order to perform setup, `tmkms` needs a  configuration file which
contains the authentication details needed to authenticate to the HashiCorp Vault with an access token.

This configuration should be placed in a file called: `tmkms.toml`.
You can specifty the path to the config with either `-c /path/to/tmkms.toml` or else tmkms will look in the current working directory for the same file.

example: 
```toml
[[providers.hashicorp]]

[[providers.hashicorp.keys]]
chain_id = "<...chain id...>"
key = "<...ed25519 signing key...>"

[providers.hashicorp.adapter]
vault_addr = "https://<...host...>:8200"

[providers.hashicorp.auth]
access_token="<...token...>"
```

You can [get](https://learn.hashicorp.com/tutorials/vault/tokens) the access token from the HashiCorp Vault.

### Generating keys in HashiCorp Vault, transit engine
1. Enable transit engine 
```bash
vault secrets enable transit
```
2. Enable sign path on transit engine 
```bash
vault secrets enable -path=sign transit
```
3. Create a key 
```bash
vault write transit/keys/<..key-name...> type=ed25519
```
4. Create a policy for the key 
 ```bash
vault policy write tmkms-transit-sign-policy -
path "transit/sign/<...key name...>" {
  capabilities = [ "update"]
}
#used by HashiCorp API to verify connectivity on startup
path "auth/token/lookup-self" {
  capabilities = [ "read" ]
}
```
5. Create access token for the policy above
```bash
vault token create \
 -policy=tmkms-transit-sign-policy \
 -no-default-policy  \
 -non-interactive \
 -renewable=false \
 -period=0 
```
6.  To import an existing tendermint key (this is TODO).
```
