#!/bin/bash

# Test script for the HTTP server functionality

echo "Testing TMKMS HTTP Server..."

# Start the server in the background (this would normally be done with the start command)
echo "Starting TMKMS with HTTP server..."
# Note: In a real test, you would run: cargo run --features softsign start -c example_config.toml

# Wait a moment for server to start
sleep 2

# Test health check endpoint
echo "Testing health check endpoint..."
curl -s http://127.0.0.1:8080/health | jq .

# Test list chains endpoint
echo "Testing list chains endpoint..."
curl -s http://127.0.0.1:8080/api/v1/chains | jq .

# Test adding a new chain
echo "Testing add chain endpoint..."
curl -s -X POST http://127.0.0.1:8080/api/v1/chains \
  -H "Content-Type: application/json" \
  -d '{
    "chain": {
      "id": "test-chain-1",
      "key_format": {
        "type": "bech32",
        "account_key_prefix": "testpub",
        "consensus_key_prefix": "testvalconspub"
      },
      "sign_extensions": false
    },
    "validator": {
      "addr": "tcp://test@localhost:26658",
      "chain_id": "test-chain-1",
      "reconnect": true
    },
    "provider": {
      "softsign": [{
        "chain_ids": ["test-chain-1"],
        "key_type": "consensus",
        "path": "test-key.key"
      }]
    }
  }' | jq .

# Test listing chains again to see the new chain
echo "Testing list chains endpoint again..."
curl -s http://127.0.0.1:8080/api/v1/chains | jq .

echo "Test completed!"
