# TMKMS HTTP Server

This is a proof of concept implementation of an HTTP server for dynamic chain and validator management in TMKMS.

## Features

- **Dynamic Chain Addition**: Add new chains via REST API
- **Atomic Configuration Updates**: Configuration file updates are atomic to prevent corruption
- **No Authentication**: Simplified for proof of concept (not recommended for production)
- **Health Check**: Basic health monitoring endpoint

## Configuration

Add the following section to your `tmkms.toml` configuration file:

```toml
[http_server]
bind_address = "127.0.0.1"
port = 8080
```

## API Endpoints

### Health Check
- **GET** `/health`
- Returns server status

### List Chains
- **GET** `/api/v1/chains`
- Returns list of registered chain IDs

### Add Chain
- **POST** `/api/v1/chains`
- Adds a new chain with validator and provider configuration
- Request body:
```json
{
  "chain": {
    "id": "chain-id",
    "key_format": {
      "type": "bech32",
      "account_key_prefix": "prefix",
      "consensus_key_prefix": "valconsprefix"
    },
    "sign_extensions": false
  },
  "validator": {
    "addr": "tcp://validator@host:port",
    "chain_id": "chain-id",
    "reconnect": true
  },
  "provider": {
    "softsign": [{
      "chain_ids": ["chain-id"],
      "key_type": "consensus",
      "path": "path/to/key"
    }]
  }
}
```

## Usage

1. **Start TMKMS with HTTP server**:
   ```bash
   cargo run --features softsign start -c your_config.toml
   ```

2. **Test the API**:
   ```bash
   # Health check
   curl http://127.0.0.1:8080/health
   
   # List chains
   curl http://127.0.0.1:8080/api/v1/chains
   
   # Add a new chain (see example above)
   curl -X POST http://127.0.0.1:8080/api/v1/chains \
     -H "Content-Type: application/json" \
     -d @chain_request.json
   ```

## Implementation Details

### Atomic Configuration Updates

The HTTP server uses atomic file operations to prevent configuration corruption:

1. Load current configuration
2. Apply changes in memory
3. Write to temporary file (`tmkms.toml.tmp`)
4. Atomically rename temporary file to `tmkms.toml`
5. Update in-memory registry

This ensures that either the entire operation succeeds or fails, preventing partial updates.

### Error Handling

- **400 Bad Request**: Invalid request data
- **500 Internal Server Error**: Configuration or registry errors
- **201 Created**: Successful chain addition

## Limitations

This is a proof of concept with the following limitations:

- **No Authentication**: API is open (not suitable for production)
- **Add Only**: No deletion or modification of existing chains
- **Simplified Provider Handling**: Provider configuration is replaced rather than merged
- **No Validation**: Limited input validation
- **Single Provider Type**: Only supports softsign provider in requests

## Future Enhancements

- Authentication and authorization
- Delete/modify chain endpoints
- Better provider configuration merging
- Input validation
- Support for multiple provider types
- Configuration backup and rollback
- Rate limiting
- Audit logging

## Testing

Use the provided test script:
```bash
./test_http_server.sh
```

Make sure to have `jq` installed for JSON formatting.
