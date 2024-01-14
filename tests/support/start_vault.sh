#!/bin/bash

set -eum

# kill everything in the process group
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

export VAULT_TOKEN="test"

# pre setup
TLS_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TLS_DIR"' EXIT

export VAULT_CA_CERT="$TLS_DIR/vault-ca.pem"
export VAULT_SKIP_VERIFY="true"

retry() {
  local retries="$1"
  local command="$2"
  local options="$-"

  if [[ $options == *e* ]]; then
    set +e
  fi

  $command
  local exit_code=$?

  if [[ $options == *e* ]]; then
    set -e
  fi

  if [[ $exit_code -ne 0 && $retries -gt 0 ]]; then
    sleep 1
    retry $(($retries - 1)) "$command"
  else
    return $exit_code
  fi
}

function start_vault() {
    PROTO="$2"
    PORT="$3"
    TERMINATE_TIMEOUT="$4"
    TLS_ARGS=""

    pkill -9 -x vault || true

    if [[ "$PROTO" == "https" ]]; then
        TLS_ARGS="-dev-tls -dev-tls-cert-dir=$TLS_DIR"
    fi

    if [[ "$1" == "foreground" ]]; then
        vault server -dev -dev-listen-address="127.0.0.1:$PORT" -dev-root-token-id="$VAULT_TOKEN" -dev-no-store-token $TLS_ARGS
    fi

    if [[ "$1" == "background" ]]; then
        vault server -dev -dev-listen-address="127.0.0.1:$PORT" -dev-root-token-id="$VAULT_TOKEN" -dev-no-store-token $TLS_ARGS &
        VAULT_PID=$!

        if [[ $TERMINATE_TIMEOUT -gt 0 ]]; then
            sleep $TERMINATE_TIMEOUT
            kill $VAULT_PID
        fi
    fi
}

function setup_vault() {
    PROTO="$1"
    PORT="$2"

    export VAULT_ADDR="$PROTO://127.0.0.1:$PORT"
    export VAULT_API_ADDR="$PROTO://127.0.0.1:$PORT"

    echo "enabling transit engine..."
    retry 5 "vault secrets enable transit"

    echo "enabling transit's engine sign path..."
    retry 5 "vault secrets enable -path=sign transit"
}

case "$1" in

'start')
    start_vault $2 $3 $4 $5
    ;;
'setup')
    setup_vault $2 $3
    ;;
'all')
    start_vault "background" $2 $3 0
    setup_vault $2 $3
    fg
    ;;
*) echo "Unrecognized option $1"
   ;;
esac
