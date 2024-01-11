#!/bin/bash

set -eu

# kill everything in the process group
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

PORT="8400"
export VAULT_ADDR="http://127.0.0.1:$PORT"
vault server -dev -dev-listen-address="127.0.0.1:$PORT" -dev-root-token-id="test" -dev-no-store-token &

sleep 1

echo "\nenabling transit engine..."
vault secrets enable transit

echo "\nenabling transit's engine sign path..."
vault secrets enable -path=sign transit

sleep infinity
