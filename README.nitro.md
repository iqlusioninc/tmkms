# AWS Nitro Enclaves + Tendermint KMS
[AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/) (AWS NE) is a recent functionality for data processing
isolation on AWS. There are no additional charges on top of the cost of running supported EC2 instance types (with 4 vCPUs and above).
In this document, we describe a basic setup where:

1. a validator signing key is encrypted by [AWS KMS](https://aws.amazon.com/kms/);
2. Tendermint KMS (tmkms) is executed inside a Nitro Enclave;
3. and the enclave with tmkms can decrypt (during initialization) the validator signing key via AWS KMS.

Note that this is still work in progress and this document only describes a basic setup, so it is not yet ready for the production use.
We recommend looking at other materials for additional setups, such as the 
[Security best practices for AWS KMS](https://d0.awsstatic.com/whitepapers/aws-kms-best-practices.pdf) whitepaper.

## Prerequisites
You need to install Docker + Nitro Enclaves CLI:
https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html

## Compiling tmkms for AWS NE
At the time of writing, only [C SDK](https://github.com/aws/aws-nitro-enclaves-sdk-c) is available for AWS NE, so one will
need to link against several C dependencies. The build environment is captured in [Dockerfile.nitro]
which is extracted from the [AWS Certificate Manager for Nitro Enclaves](https://github.com/aws/aws-nitro-enclaves-acm) repository.
You can prepare the build environment e.g. with:

```
docker build -t "aws-ne-build" \                            
        --build-arg USER=$(whoami) \
        --build-arg USER_ID=$(id -u) \
        --build-arg GROUP_ID=$(id -g) \
        --build-arg RUST_TOOLCHAIN="1.46.0" \
        --build-arg CTR_HOME="$CTR_HOME" -f Dockerfile.nitro .
```

Inside the build environment, you can mount the tmkms directory and build it with the following flags:
```
cargo build --features=aws-ne-sys,nitro-enclave,softsign --target=x86_64-unknown-linux-musl --release
```

### Building enclave image file with tmkms
Once you have the tmkms binary built, you need to prepare the enclave image file.
The first step is to prepare the Docker deployment image -- you could possibly use the build environment,
but it is somewhat heavy and you will need to allocate at least 4x image size to the enclave memory
(e.g. if the image size is 1 GB, you will need to allocate at least 4 GB memory). Thus, it is recommended
to prepare a slimmed down image for deployment. You can either use the build environment image as base and remove
unneeded parts from it, e.g. with:
- find out the needed library dependencies: `ldd "<path to tmkms>" | grep -Eo "/.*lib.*/[^ ]+"`;
- remove the unneeded symbols `strip --strip-unneeded "<needed library path>"`.
Or you can start a new image (based on Alpine Linux distribution) and copy the needed libraries from the build environment image
with `COPY --from=aws-ne-build <some lib> <lib path>`.

In any case, in your Dockerfile, you should have:
```
...
COPY target/x86_64-unknown-linux-musl/release/tmkms .
CMD ./tmkms nitro start
```

You can optionally supply flags to the final start command: `-p` if you want to choose a different vsock port to listen on
for pushing the tmkms config (the default is 5050) and `-v` for verbose logging.

Once you build the Docker image, you can convert it to the enclave image file with:
```
nitro-cli build-enclave --docker-dir ./ --docker-uri tmkms --output-file tmkms.eif
```

After building the enclave image, you should obtain 3 measurement values: PCR0 (SHA384 hash of the image),
PCR1 (SHA384 hash of the OS kernel and the bootstrap process), and PCR2 (SHA384 hash of the application).
Take a note of the PCR0 value.

## Preparing AWS KMS policy and encrypted validator key
There are two basic actions with "customer master keys" (CMK) that one will need to configure with AWS KMS policy:
`kms:Encrypt` and `kms:Decrypt`.
For the encryption action, it depends case-by-case:
- if you are starting from scratch, you may want to generate the validator key inside another enclave using `kms:GenerateRandom` API
and then encrypting it (so in that case, grant `kms:Encrypt` to that enclave);
- if you plan to use an existing validator signing key, you may grant `kms:Encrypt` to the administrator for one-off encryption of the validator key.

For the decryption action, you should set it in "Statement" as:
```
    {
      "Sid" : "Enable decrypt from tmkms enclave",
      "Effect" : "Allow",
      "Principal" : { "AWS" : "<parent instance IAM role ARN>" },
      "Action" : "kms:Decrypt",
      "Resource" : "*",
      "Condition": {
          "StringEqualsIgnoreCase": {
            "kms:RecipientAttestation:ImageSha384": "<PCR0 value obtained in the enclave image file building step>"
          }
      }
    }
```

If you plan to run the tmkms enclave in the debug mode, set the recipient attestation value to:
"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
(instead of the PCR0 value).

Once you have your policy prepared, you can e.g. create the key using AWS CLI:

```
aws kms create-key --description "tmkms" --policy file://<your policy>.json --query KeyMetadata.Arn --output text
```

Take a note of the key ARN and prepare the encrypted validator key. For example, you can take directly the base64 raw
key material (output of `tmkms softsign keygen -t consensus`) or json, and get the ciphertext with AWS CLI:
```
aws kms encrypt --key-id "<key ARN>" --plaintext fileb://... --query CiphertextBlob --output text
```


## tmkms.toml configuration
The configuration file is modified from the standard one due to the fact that one cannot access host files or networking
directly in NE, and must do so via "vsock" connection proxies.


```
[[chain]]
id = "..."
key_format = { type = "bech32", account_key_prefix = "...", consensus_key_prefix = "..." }
state_vsock_port = <vsock port for state persistence proxy>

[[providers.softsign]]
chain_ids = [...]
key_type = "consensus"
encrypted_key_b64 = "<the key encrypted with AWS KMS>"
aws_region = "<AWS region to use>"
## You can also specify AWS credentials, but if you don't, they will be obtained from IAM role on the host instance

[[validator]]
chain_id = "..."
addr = { port = <port for proxy to Tendermint "privval" connection> }
# you can also specify whether to use the secret connection (if "privval" over proxy is listening on TCP)
# in which case you'd need to bundle the identity key in the deployment Docker/enclave image
# (retrieving this from AWS KMS is a TODO item)
protocol_version = "..."
reconnect = true
```

## Launching tmkms enclave and related proxy tools
### Compiling tmkms for the host instance
Unless you have all the AWS C dependencies and musl ready on the host instance,
you may not be able to run the tmkms binary previously compiled for the enclave image.
In that case, you can compile the tmkms on the host as follows:
```
cargo build --features=nitro-enclave,softsign --release
```

### Run it
You can launch the tmkms enclave using Nitro CLI:

```
nitro-cli run-enclave --eif-path tmkms.eif --memory <memory size in MB> --cpu-count 2 [--debug-mode]
```

If you launch it in the debug mode, you can connect to the (read-only) console as follows:

```
nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r .[0].EnclaveID)
```

You will need to open a proxy to AWS KMS:

```
vsock-proxy 8000 kms.<AWS REGION>.amazonaws.com 443
```

And a proxy to save the tmkms state in the host instance:
```
./tmkms nitro persist -s path/to/consensus/state.json -p <persistence vsock port> 
```

If you configured Tendermint to use TCP for the privval connection, you can use the `vsock-proxy` tool
(note that you may need to update its allowlist) as with AWS KMS. If you configured it to use
the Unix domain socket, you can use this tmkms command to forward the traffic:
```
./tmkms nitro proxy -p <vsock proxy port> -u path/to/privval/unix/domain/socket
```

Lastly, when launching the Tendermint process (configured to listen on the correct privval connection),
push the config to the tmkms enclave:

```
./tmkms nitro push-config -c path/to/tmkms.toml -i <tmkms enclave cid> -p <vsock port / default: 5050>
```


