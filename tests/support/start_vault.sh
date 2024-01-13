#!/bin/bash

set -eu

# kill everything in the process group
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

PROTO="http"
TLS_DIR=""
if [ $# -gt 0  ]; then
    PROTO="https"
    TLS_DIR="$(mktemp -d)"
    trap 'rm -rf -- "$TLS_DIR"' EXIT

    export VAULT_CA_CERT="$TLS_DIR/vault-ca.pem"
    export VAULT_SKIP_VERIFY="true"

    echo "\nTLS DIR: $TLS_DIR"
    echo "\ncert file"
    echo "$VAULT_CA_CERT"
fi

PORT="8400"
export VAULT_ADDR="$PROTO://127.0.0.1:$PORT"
export VAULT_API_ADDR="$PROTO://127.0.0.1:$PORT"
export VAULT_TOKEN="test"

if [[ "$TLS_DIR" -eq "" ]]; then
    vault server -dev -dev-listen-address="127.0.0.1:$PORT" -dev-root-token-id="$VAULT_TOKEN" -dev-no-store-token &
else
    vault server -dev -dev-listen-address="127.0.0.1:$PORT" -dev-root-token-id="$VAULT_TOKEN" -dev-no-store-token -dev-tls -dev-tls-cert-dir="$TLS_DIR" &
fi

sleep 2

echo "\nenabling transit engine..."
vault secrets enable transit

echo "\nenabling transit's engine sign path..."
vault secrets enable -path=sign transit

sleep infinity
