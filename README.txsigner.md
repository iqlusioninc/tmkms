# Transaction Signer (alpha)

Tendermint KMS implements support for signing transactions in [StdTx]
format, supporting user-defined schemas that allow support for any
Tendermint-based chain which uses this format. This is useful for
implementing services which require an online account signing key,
such as price oracles.

Transactions to be signed are presently specified in a simple JSON format
exposed as an HTTP endpoint from a service you provide (this will likely
migrate to Protocol Buffers in future versions).

The transaction signer supports the following signature providers:

- [YubiHSM 2]
- Soft Sign

NOTE: please open an issue if you are interested in Ledger support.

## Status

This feature is *alpha quality* and many aspects of it are likely to change
(e.g. after the [Stargate] upgrade).

We suggest you only use it if you are an eager early adopter willing to
tolerate breaking changes until it stabilizes.

If you are interested in the future evolution of this feature, please
subscribe to the [Post-Stargate roadmap (tmkms#96)][Roadmap] issue for updates.

## Getting Help

If you are trying to follow this document to deploy the transaction signer
and are having any problems, please open an issue on the GitHub issue tracker:

<https://github.com/iqlusioninc/tmkms/issues>

## Installation

Transaction signing support is gated under the `tx-signer` feature, which
you'll need to supply when installing Tendermint KMS.

NOTE: replace `yubihsm` with `softsign` to use the Soft Sign backend.

### Building from `git`

```
$ git clone https://github.com/iqlusioninc/tmkms.git && cd tmkms
[...]
$ cargo build --release --features=tx-signer,yubihsm
```

### Installing with `cargo install`

```
cargo install tmkms --features=tx-signer,yubihsm
```

## Architecture

![Diagram](https://raw.githubusercontent.com/iqlusioninc/tmkms/develop/img/tx-signer.svg)

Tendermint KMS polls a microservice you provide at an interval you specify to
obtain transactions to be signed. After signing them, it automatically submits
them to a Tendermint full node, meaning that the microservice generating the
transactions need only handle constructing them, and the KMS handles the rest.

The KMS initiates a "webhook"-style HTTP request to the Transaction Microservice
at specified intervals (i.e. a block height interval), requesting a batch of
transactions to be signed, then submits them to a Tendermint Node for broadcast:

1. Transaction Microservice generates batch of transactions to be signed, e.g.
   for an oracle service, making requests to several exchanges and computing
   average price pairs, then producing a JSON document (presently Amino JSON)
   describing the transaction to be signed.
2. KMS retrieves the batch of transactions to be signed from Transaction
   Microservice. If it's non-empty, it parses the JSON, checks it against
   a specified schema for a given network's transaction format, vets the
   proposed transactions against an Access Control List to ensure the
   transactions are authorized to be signed, computes signatures using
   a specified account key ([ECDSA]/[secp256k1]), then serializes the transactions
   in a binary format (presently Amino, soon to be [Protobuf]).
3. Signed transactions are then submitted to a specified Tendermint node for
   broadcast to the P2P network and inclusion into the blockchain.

## Transaction JSON format

The KMS is configured to poll a particular HTTP endpoint for a JSON-formatted
response containing a batch of Amino JSON transactions.
(NOTE: HTTPS support forthcoming)

The request must be an **HTTP POST**.

Below is an example of the (tentative!) JSON format:

### Success

```json
{
  "status": "ok",
  "tx": [
    {
      "chain_id": "columbus-3",
      "fee": {
        "amount": [],
        "gas": "200000"
      },
      "memo": "oracle vote",
      "msgs": [
        {
          "type": "oracle/MsgExchangeRatePrevote",
          "value": {
            "denom": "ukrw",
            "feeder": "terra1t9et8wjeh8d0ewf4lldchterxsmhpcgg5auy47",
            "hash": "14bc5a27dda9af35872bf768d12d0d976cabc52b",
            "validator": "terravaloper1grgelyng2v6v3t8z87wu3sxgt9m5s03x2mfyu7"
          }
        }
      ]
    }
  ]
}
```

### Error

```json
{
  "status": "error",
  "msg": "couldn't connect to x.y.z: ..."
}
```

### JSON Object Keys

- `status`: either `"ok"` on success, or `"error"` on error
- `tx`: array of Amino JSON encoded transaction objects:
  - `chain_id`: the chain ID of the destination Tendermint network
  - `fee`: amount to spend on the given transaction
  - `memo`: string comment field
  - `msg`: array of messages to include in the transaction (format will vary
    network-by-network and must match the provided schema)
- `msg`: when `status` is `"error"`, a message describing the error

(NOTE: we expect this format to change considerably after the [Stargate] upgrade,
including potentially moving to [Protobufs and gRPC][Roadmap])

## Creating transaction signing (i.e. account) keys

In order to use the transaction signer, you must first create one or more
transaction signing keys, i.e. Tendermint account keys.

### Backround

Tendermint account keys are [secp256k1] secret keys used for creating digital
signatures using the [Elliptic Curve Digital Signature Algorithm (ECDSA)][ECDSA].

Note that this is a different algorithm than the Ed25519 signature system used for
Tendermint consensus.

### `yubihsm`: creating account keys

To create a new account key in a YubiHSM2 (randomly generated by the YubiHSM2's
own internal random number generator), run the following command:

```
$ tmkms yubihsm keys generate -t account -l "columbus-3 oracle signer" 0x123
```

This will generate a new account key (secp256k1) with the label
"columbus-3 oracle signer" in key slot 0x123 (chosen as an example, you can
use any key slot number you wish which isn't presently occupied by another
signing key, e.g. 0x42 will work just as well, or 0x2 if it's unoccupied).

You can also make an encrypted backup of the key at generation time by adding
the following arguments:

```
$ tmkms yubihsm keys generate -t account -l "columbus-3 oracle signer" -b columbus-oracle-key.enc 0x123
   Generated account (secp256k1) key 0x0123
```

If that succeeded, you can now add the generated key to your [`tmkms.toml`]
config file's `[[providers.yubihsm]]` section (under `keys`):

```toml
[[providers.yubihsm]]
adapter = { type = "usb" }
auth = { key = 1, password = "password" }
keys = [
    { chain_ids = ["cosmoshub-1"], key = 0x0001, type = "consensus" },
    { chain_ids = ["columbus-3"], key = 0x0123, type = "account" }
]
```

This will register the newly generated key as an account key on the provided
chain IDs (i.e. `columbus-3` in this case)

Finally, confirm you see the key listed when you run
`tmkms yubihsm keys list`, flagged as being an `[acct]` key:

```
$ tmkms yubihsm keys list
Listing keys in YubiHSM #0001234567:
- 0x0001: [cons] cosmosvalconspub...
  [...]
- 0x0123: [acct] terra13tdvxsauagu33glu74u93mdka7ahvm5a6yfr76
   label: "columbus-3 oracle signer"
```

If the newly generated account key is properly configured for the desired chain
the `list` command should display its Bech32-formatted account address. Make a
note of this as you'll need to configure it as `[[tx_signer.account_address]]`
(see below).

### `softsign`: creating account keys

To create a new "soft" account key (randomly generated using the host OS's
random number generator), run the following command:

```
$ tmkms softsign keygen -t consensus /path/to/account.key
 Generated account (secp256k1) private key at: /path/to/account.key
```

Finally, add the generated key to your [`tmkms.toml`] config file.
You will be adding a brand new `[[providers.softsign]]` section separate from
any existing ones:

```toml
[[providers.softsign]]
chain_ids = ["columbus-3"]
key_type = "account"
path = "/path/to/account.key"
```

### Verifying account keys have been loaded

Once you have generated a new account key, you can verify it's correctly being
loaded into the KMS keyring by running `tmkms start`:

```
Jul 01 14:54:40.645  INFO tmkms::commands::start: tmkms 0.8.0-rc0 starting up...
[...]
Jul 01 14:54:43.990  INFO tmkms::keyring: [keyring:yubihsm] added account ECDSA key: terra13tdvxsauagu33glu74u93mdka7ahvm5a6yfr76
```

If the key is not formatted correctly in Bech32 (e.g. `terra1...` in this example)
it means you need to configure a `[[chain]]` section for the given chain ID
in your [`tmkms.toml`], in particular adding `key_format` configuration for the chain.
Make sure this is properly configured or transaction signing won't work!

## KMS configuration: `[[tx_signer]]`

To enable the transaction signer, you'll need to add a `[[tx_signer]]` section
to your [`tmkms.toml`]. Below is an example:

```toml
[[tx_signer]]
chain_id = "columbus-3"
schema = "/path/to/terra_schema.toml" # See Schema section below
account_address = "terra13tdvxsauagu33glu74u93mdka7ahvm5a6yfr76" # must be in the keyring for this chain
account_number = 101072
acl = { msg_type = ["oracle/MsgExchangeRatePrevote", "oracle/MsgExchangeRateVote"] }
poll_interval = { blocks = 5 }
source = { protocol = "jsonrpc", uri = "http://127.0.0.1:23456/oracles/terra" }
rpc = { addr =  "tcp://10.0.0.4:26657" }
seq_file = "/path/to/terra-account-seq.json"
```

The keys of this section are as follows:

- `chain_id`: the Tendermint network's chain ID. Must match the chain ID in the
  transaction JSON, as well as the chain ID in the provider configuration.
- `schema`: path to a TOML file containing a transaction schema. See the *Schema*
  section below for more information.
- `account_address`: the address of your newly generated account key in
  Bech32 with a chain-specific prefix. See the "Verifying account keys have been
  loaded" section above for information on how to get the address of your
  newly generated account key.
- `account_number`: the account number associated with the account key.
  To get this number, you'll first need to register the newly created account
  address with your destination Tendermint network. The way in which you do
  this will vary from network-to-network, but generally involves initiating
  a transfer from an existing, funded account for an insignificant amount of
  the network's native token with the newly created `account_address` as the
  destination. See the [Cosmos Send Tokens] documentation for an example.
- `acl`: Access Control List for acceptable transactions to sign:
  - `msg_type`: array of allowable transaction message types. These types
    must exist in the `schema`. See the *Schema* section below.
- `poll_interval`: interval at which the Transaction Microservice (i.e. `source`)
  should be polled for new batches of transactions:
  - `blocks`: poll at a given block interval (i.e. every N blocks).
    The KMS will monitor chain state and initiate a "webhook" to the `source`
    service when the block height is evenly divisible by this value.
- `source`: configuration for the Transaction Microservice responsible for
  generating transactions to be signed:
  - `protocol`: presently this must be `jsonrpc` (gRPC support forthcoming!)
  - `uri`: full URI to the POST endpoint at which transaction batches will be
    returned (must be `http://`, HTTPS support forthcoming!)
- `rpc`: Tendermint RPC endpoint to use for monitoring chain state and
  broadcasting transactions:
  - `addr`: RPC address of the Tendermint node
- `seq_file`: file containing the account sequence number. This file will be
  automatically created if it doesn't exist, and contains a small JSON document
  of the form `{"sequence": 123456}`. (Future releases of the KMS will ideally
  eliminate this by querying it from the chain state)

## Transaction Schema Configuration

In order to both validate the Amino JSON generated by the Transaction
Microservice, as well as produce an Amino Binary serialization of the
signed transaction to broadcast to the network, configuration includes
a Transaction Schema file which describes the chain and the format of
its transactions.

The schema is presently defined in TOML, but will likely migrate to [Protobuf]
some time after the [Stargate] upgrade.

Below is an example schema file which defines the transaction types used for
[Terra Oracle] voting. To use the transaction signer, you will need to find
a similar description of the transaction types for a chain, then write a
similar schema description:

```toml
# Terra stablecoin project schema
# <https://terra.money/>

namespace = "core/StdTx"
acc_prefix = "terra"
val_prefix = "terravaloper"

#
# Oracle vote transactions
# <https://docs.terra.money/dev/spec-oracle.html>
#

# MsgExchangeRatePrevote
# <https://docs.terra.money/dev/spec-oracle.html#msgexchangerateprevote>
[[definition]]
type_name = "oracle/MsgExchangeRatePrevote"
fields = [
    { name = "hash",  type = "string" },
    { name = "denom", type = "string" },
    { name = "feeder", type = "sdk.AccAddress" },
    { name = "validator", type = "sdk.ValAddress" },
]

# MsgExchangeRateVote
# <https://docs.terra.money/dev/spec-oracle.html#msgexchangeratevote>
[[definition]]
type_name = "oracle/MsgExchangeRateVote"
fields = [
    { name = "exchange_rate", type = "sdk.Dec"},
    { name = "salt", type = "string" },
    { name = "denom", type = "string" },
    { name = "feeder", type = "sdk.AccAddress" },
    { name = "validator", type = "sdk.ValAddress" },
]
```

For more examples, see the schema templates directory in the KMS
GitHub repo:

<https://github.com/iqlusioninc/tmkms/tree/develop/src/commands/init/templates/schema>

## Running and Debugging

After generating account keys (and registering them with the network) as well
as configuring a `[[tx_signer]]` section in your [`tmkms.toml`], you're ready to
start the KMS!

```
$ tmkms start -c /path/to/tmkms.toml
```

Presently getting everything working will likely involve a lot of trial and
error, particularly as three different services are involved (Transaction
Microservice, KMS, and Tendermint Node). This section will help you understand
what to look for in the logs in order to determine if everything is working.
The logs are presently the only way to debug these sorts of problems, so
make sure you're keeping an eye on them!

### Ensure account key is in the keyring

When you first launch `tmkms`, you'll see the following loglines:

```
Jul  1 23:07:40  INFO tmkms::commands::start: tmkms 0.8.0 starting up...
[...]
Jul  1 23:07:40  INFO tmkms::keyring: [keyring:yubihsm] added account ECDSA key: terra13tdvxsauagu33glu74u93mdka7ahvm5a6yfr76
```

Make sure you see a key with the expected account address loaded into your
keyring!

### Ensure the transaction signer is running

If you've properly configured a `[[tx_signer]]`, you'll see a logline like
the following:

```
Jul  1 23:17:12  INFO tmkms::tx_signer: [columbus-3] waiting until block height: 2602700
```

Since the transaction signer polls your Transaction Microservice at a specified
block interval, it waits until the next block which is a multiple of that interval
(e.g. this example is using a block interval of 5).

### Ensure transactions are being signed successfully

Once the block height given above has been reached, the KMS will make an HTTP request
to your Transaction Microservice, retrieving a batch of transactions to be signed.
Make sure to keep an eye out for any errors tagged `ERROR tmkms::tx_signer`,
as there are a number of things that could go wrong at this point:

- Can't connect to the Transaction Microservice (i.e. `source`)
- HTTP errors
- Errors parsing the response JSON (e.g. malformatted, schema errors)
- Transaction is not authorized in `[[tx_signer.acl]]`

Keep an eye out for any loglines about these!

If the KMS is able to reach the Transaction Microservice, successfully parse
the JSON and validate it against the schema, and the transaction is authorized
by `[[tx_signer.acl]]`, the KMS will sign it and log the following:

```
Jul  1 23:17:46  INFO tmkms::tx_signer: [columbus-3] signed TX 1 for terra13tdvxsauagu33glu74u93mdka7ahvm5a6yfr76 (8 msgs total; types: oracle/MsgExchangeRatePrevote, oracle/MsgExchangeRateVote)
```

If you've gotten this far, congratulations, the KMS has successfully signed
a transaction! The next step is ensuring that it's successfully broadcasted
to the network.

### Ensure signed transactions are broadcast successfully

If the KMS successfully signed a transaction as described in the section above,
it will then attempt to broadcast it to the network by making a [broadcast_tx_sync]
request to the Tendermint node configured under `[[tx_signer.rpc]]` in [`tmkms.toml`].

A number of things could potentially go wrong at this point:

- RPC connection failure
- Account hasn't been created (see `account_number` section of `[[tx_signer]]` config above)
- Transaction sequence number is incorrect
- Transaction is invalid

Keep an eye out for any loglines about these!

If everything was successful, you'll see loglines like the following:

```
Jul  1 23:17:46  INFO tmkms::tx_signer: [columbus-3] broadcast TX 1: 8E2915E0BD736130C67BD800F47766597A69328F4DF7D3397B6697304B775FDA
Jul  1 23:17:46  INFO tmkms::tx_signer: [columbus-3] waiting until block height: 2602705
```

At this point, you've successfully generated a valid transaction, signed it,
and broadcast it to the network! Congratulations! It's working!

The `8E2915E0...` value is the transaction ID/hash. The next step is to look up
the transaction in a block explorer for the particular Tendermint network you're
interacting with and make sure it achieved the desired outcome.

[StdTx]: https://godoc.org/github.com/cosmos/cosmos-sdk/x/auth/types#StdTx
[YubiHSM 2]: https://github.com/iqlusioninc/tmkms/blob/develop/README.yubihsm.md
[Stargate]: https://blog.cosmos.network/cosmos-stargate-upgrade-overview-8939475fe673
[Roadmap]: https://github.com/iqlusioninc/tmkms/issues/96
[Protobuf]: https://github.com/iqlusioninc/crates/issues/459
[secp256k1]: https://en.bitcoin.it/wiki/Secp256k1
[ECDSA]: https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
[`tmkms.toml`]: https://github.com/iqlusioninc/tmkms/blob/develop/tmkms.toml.example
[Cosmos Send Tokens]: https://hub.cosmos.network/master/resources/gaiacli.html#send-tokens
[Terra Oracle]: https://docs.terra.money/dev/spec-oracle.html#message-types
[broadcast_tx_sync]: https://docs.tendermint.com/master/rpc/#/Tx/broadcast_tx_sync
