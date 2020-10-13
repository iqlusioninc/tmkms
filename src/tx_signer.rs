//! Transaction signer.
//!
//! Connects to a remote service to obtain transactions to sign, and if they
//! meet a prescribed policy, signs them.

pub mod jsonrpc;
pub mod request;
pub mod sequence_file;

pub use request::TxSigningRequest;

use crate::{
    chain,
    config::tx_signer::{PollInterval, TxAcl, TxSignerConfig, TxSource},
    error::{Error, ErrorKind},
    prelude::*,
};
use abscissa_tokio::tokio;
use sequence_file::SequenceFile;
use std::{collections::BTreeSet as Set, process};
use stdtx::{StdSignature, StdTx};
use subtle_encoding::hex;
use tokio::time;

/// Frequency at which to retry after failures
// TODO(tarcieri): make this configurable?
pub const RETRY_DELAY: time::Duration = time::Duration::from_secs(5);

/// RPC polling interval
// TODO(tarcieri): use websocket instead of polling? make this configurable?
pub const RPC_POLL_INTERVAL: time::Duration = time::Duration::from_millis(500);

/// Transaction signer
pub struct TxSigner {
    /// Chain ID of the Tendermint network this validator is part of
    chain_id: tendermint::chain::Id,

    /// Transaction builder
    tx_builder: stdtx::Builder,

    /// Account address
    address: stdtx::Address,

    /// Access Control List for authorized transaaction types to sign
    acl: TxAcl,

    /// Polling interval
    poll_interval: PollInterval,

    /// Transaction source (JSONRPC)
    // TODO(tarcieri): gRPC
    source: jsonrpc::Client,

    /// Tendermint RPC client
    rpc_client: tendermint_rpc::Client,

    /// Sequence file
    seq_file: SequenceFile,
}

impl TxSigner {
    /// Create a new transaction signer
    pub fn new(config: &TxSignerConfig) -> Result<Self, Error> {
        let schema = stdtx::Schema::load_toml(&config.schema).unwrap_or_else(|e| {
            status_err!(
                "couldn't read TX schema from `{}`: {}",
                config.schema.display(),
                e
            );
            process::exit(1);
        });

        let tx_builder =
            stdtx::Builder::new(schema, config.chain_id.to_string(), config.account_number);

        let source = match &config.source {
            TxSource::JsonRpc { uri } => jsonrpc::Client::new(uri.clone()),
        };

        let tendermint_rpc = tendermint_rpc::Client::new(config.rpc.addr.clone());

        let seq_file = SequenceFile::open(&config.seq_file)?;

        Ok(Self {
            chain_id: config.chain_id,
            tx_builder,
            address: config.account_address,
            acl: config.acl.clone(),
            poll_interval: config.poll_interval.clone(),
            source,
            rpc_client: tendermint_rpc,
            seq_file,
        })
    }

    /// Run the transaction signer
    pub async fn run(&mut self) {
        // Fetch the block height via RPC and use that to synchronize the
        // block interval to the block height count
        let mut next_block = loop {
            match self.get_block_height().await {
                Ok(height) => break self.next_block_after(height),
                Err(e) => {
                    warn!(
                        "[{}] error getting initial block height: {}",
                        self.chain_id, e
                    );
                    time::delay_for(RETRY_DELAY).await
                }
            }
        };

        loop {
            info!(
                "[{}] waiting until block height: {}",
                &self.chain_id, next_block
            );

            let current_block = match self.wait_until_block_height(next_block).await {
                Ok(height) => height,
                Err(e) => {
                    error!(
                        "[{}] couldn't get current block height via RPC: {}",
                        &self.chain_id, e
                    );
                    time::delay_for(RETRY_DELAY).await;
                    continue;
                }
            };

            next_block = self.next_block_after(current_block);

            // Request batch of transactions from source
            let tx_reqs = match self.source.request().await {
                Ok(req) => req,
                Err(e) => {
                    error!(
                        "[{}] couldn't fetch TXes from `{}`: {}",
                        &self.chain_id,
                        self.source.uri(),
                        e
                    );
                    time::delay_for(RETRY_DELAY).await;
                    continue;
                }
            };

            // Process batch of transactions
            for req in tx_reqs.into_iter() {
                // Sign transaction
                let signed_tx = match self.sign_tx(req) {
                    Ok(tx) => tx,
                    Err(e) => {
                        error!("[{}] error signing transaction: {}", &self.chain_id, e);
                        continue;
                    }
                };

                // Broadcast transaction to Tendermint P2P network via RPC
                if let Err(e) = self.broadcast_tx(signed_tx).await {
                    error!("[{}] {}", &self.chain_id, e);
                    continue;
                }

                // Increment value in state file
                if let Err(e) = self.seq_file.increment() {
                    status_err!("couldn't persist sequence file: {}", e);
                }
            }
        }
    }

    /// Get the current block height for this chain
    async fn get_block_height(&mut self) -> Result<u64, Error> {
        let response = self.rpc_client.status().await?;
        Ok(response.sync_info.latest_block_height.value())
    }

    /// Wait until the chain is at the given block height
    async fn wait_until_block_height(&mut self, target_height: u64) -> Result<u64, Error> {
        let (block_interval, min_secs) = match self.poll_interval {
            PollInterval::Block { blocks, min_secs } => (blocks, min_secs),
        };

        let min_deadline = time::Instant::now() + time::Duration::from_secs(min_secs);

        loop {
            let current_height = self.get_block_height().await?;
            debug!(
                "[{}] current block height is: {}",
                &self.chain_id, current_height
            );

            if current_height >= target_height {
                if time::Instant::now() < min_deadline {
                    warn!(
                        "[{}] target height {} reached before min_secs deadline ({}s)! \
                        sleeping... (is node catching up?)",
                        &self.chain_id, target_height, min_secs
                    );

                    time::delay_until(min_deadline).await;
                }

                return Ok(current_height);
            } else if target_height.checked_sub(current_height).unwrap() > block_interval {
                warn!(
                    "block wait sanity check failed: current={} target={} interval={}",
                    current_height, target_height, block_interval
                );

                // Hopefully returning the current height will sync us back up if this ever happens
                return Ok(current_height);
            }

            time::delay_for(RPC_POLL_INTERVAL).await
        }
    }

    /// Get the next block we should wait for after the provided block height
    /// according ot the internally configured block interval
    fn next_block_after(&self, block_height: u64) -> u64 {
        let block_interval = match self.poll_interval {
            PollInterval::Block { blocks, .. } => blocks,
        };

        block_height
            .checked_sub(block_height % block_interval)
            .unwrap()
            .checked_add(block_interval)
            .unwrap()
    }

    /// Sign the given transaction signing request
    fn sign_tx(&self, req: TxSigningRequest) -> Result<StdTx, Error> {
        if self.chain_id.as_str() != req.chain_id {
            fail!(
                ErrorKind::ChainIdError,
                "expected `{}`, got `{}`",
                self.chain_id,
                req.chain_id
            );
        }

        // TODO(tarcieri): check fee
        // if req.fee != ...

        let mut msgs = vec![];
        let mut msg_types = Set::new();

        for msg_value in req.msgs {
            let msg = stdtx::Msg::from_json_value(self.tx_builder.schema(), msg_value)?;
            msg_types.insert(msg.type_name().clone());
            msgs.push(msg);
        }

        // Ensure message types are authorized in the ACL
        for msg_type in &msg_types {
            if !self.acl.msg_type.contains(&msg_type) {
                fail!(
                    ErrorKind::AccessError,
                    "unauthorized request to sign `{}` message",
                    msg_type
                );
            }
        }

        let sign_msg = self.tx_builder.create_sign_msg(
            self.seq_file.sequence(),
            &req.fee,
            &req.memo,
            msgs.as_slice(),
        );

        debug!("[{}] acquiring chain registry", &self.chain_id);

        let registry = chain::REGISTRY.get();

        debug!(
            "[{}] acquiring read-only shared lock on chain",
            &self.chain_id
        );

        let chain = registry.get_chain(&self.chain_id).unwrap_or_else(|| {
            panic!("chain '{}' missing from registry!", &self.chain_id);
        });

        debug!("[{}] performing signature", &self.chain_id);

        let account_id = tendermint::account::Id::new(self.address.0);

        let mut signature =
            StdSignature::from(chain.keyring.sign_ecdsa(account_id, sign_msg.as_bytes())?);

        signature.pub_key = chain
            .keyring
            .get_account_pubkey(account_id)
            .expect("missing account key")
            .to_bytes();

        let msg_type_info = msg_types
            .iter()
            .map(|ty| ty.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let address = self
            .address
            .to_bech32(self.tx_builder.schema().acc_prefix());

        info!(
            "[{}] signed TX {} for {} ({} msgs total; types: {})",
            self.chain_id,
            self.seq_file.sequence(),
            address,
            msgs.len(),
            msg_type_info,
        );

        Ok(StdTx::new(&msgs, req.fee, vec![signature], req.memo))
    }

    /// Broadcast signed transaction to the Tendermint P2P network via RPC
    async fn broadcast_tx(&mut self, tx: StdTx) -> Result<(), Error> {
        let amino_tx = tendermint::abci::Transaction::new(
            tx.to_amino_bytes(self.tx_builder.schema().namespace()),
        );

        let amino_tx_hex =
            String::from_utf8(hex::encode(amino_tx.as_ref())).expect("hex should always be UTF-8");

        info!(
            "[{}] broadcasting TX: {}",
            self.chain_id,
            amino_tx_hex.to_ascii_uppercase()
        );

        let response = self.rpc_client.broadcast_tx_sync(amino_tx).await?;

        if response.code.is_ok() {
            info!(
                "[{}] successfully broadcast TX {} (hash: {})",
                self.chain_id,
                self.seq_file.sequence(),
                response.hash
            );
            Ok(())
        } else {
            let msg = response
                .log
                .parse_json()
                .ok()
                .and_then(|obj| {
                    obj.get("message")
                        .and_then(|m| m.as_str().map(ToOwned::to_owned))
                })
                .unwrap_or_default();

            fail!(
                ErrorKind::TendermintError,
                "error broadcasting TX: {} (code={})",
                msg,
                response.code.value()
            );
        }
    }
}
