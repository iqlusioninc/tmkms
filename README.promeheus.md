# Prometheus exporter 

Prometheus is a free software application used for event monitoring and alerting. It records real-time metrics in a time series database (allowing for high dimensionality) built using a HTTP pull model, with flexible queries and real-time alerting.   


## Compiling `tmkms` with Prometheus support

Refer the main README.md for compiling `tmkms`
from source code. You will need the prerequisities mentioned as indicated above.

There are two ways to install `tmkms` with Prometheus, you need to pass the `--features=prometheus,<signer-feature, i.e. softsign, etc>` parameter to cargo.  


### Compiling from source code (via git)

`tmkms` can be compiled directly from the git repository source code using the
following method.

```
$ git clone https://github.com/iqlusioninc/tmkms.git && cd tmkms
[...]
$ cargo build --release --features=prometheus,softsign
```

If successful, this will produce a `tmkms` executable located at
`./target/release/tmkms`

### Installing with the `cargo install` command

With Rust (1.40+) installed, you can install tmkms with the following:

```
cargo install tmkms --features=prometheus,softsign
```

Or to install a specific version (recommended):

```
cargo install tmkms --features=prometheus,softsign --version=0.4.0
```

This command installs `tmkms` directly from packages hosted on Rust's
[crates.io] service. Package authenticity is verified via the
[crates.io index] (itself a git repository) and by SHA-256 digests of
released artifacts.

### Configuring `tmkms` for initial setup

In order to perform setup, `tmkms` needs a  configuration with desired endpoint url and port.

This configuration should be placed in a file called: `tmkms.toml`.
You can specifty the path to the config with either `-c /path/to/tmkms.toml` or else tmkms will look in the current working directory for the same file.

example: 

```toml

...
[prometheus]
bind_address="127.0.0.1:9100"
...


```

with the above configuration, metrics can be read with 

```
curl http://localhost:9100


# HELP proposal Counts proposals, per chain.
# TYPE proposal counter
# HELP pre-vote Counts pre-votes, per chain.
# TYPE pre-vote counter
# HELP pre-commit Counts pre-commits, per chain.
# TYPE pre-commit counter
# HELP double-sign Counts double-signs, local knowledge, per chain.
# TYPE double-sign counter
# EOF

```