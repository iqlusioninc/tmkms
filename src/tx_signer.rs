//! Transaction signer.
//!
//! Connects to a remote service to obtain transactions to sign, and if they
//! meet a prescribed policy, signs them.

pub mod jsonrpc;
pub mod last_tx;
pub mod sequence_file;
pub mod sign_msg;
pub mod tx_request;

pub use tx_request::TxSigningRequest;

use self::{last_tx::LastTx, sign_msg::SignMsg};
use crate::{
    chain,
    config::tx_signer::{PollInterval, TxAcl, TxSignerConfig, TxSource},
    error::{Error, ErrorKind},
    prelude::*,
};
use abscissa_tokio::tokio;
use sequence_file::SequenceFile;
use std::process;
use stdtx::amino;
use subtle_encoding::hex;
use tendermint_rpc::{endpoint::status, Client};
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
    tx_builder: amino::Builder,

    /// Account address
    address: stdtx::Address,

    /// Arbitrary context string to pass to transaction source
    context: String,

    /// Access Control List for authorized transaaction types to sign
    acl: TxAcl,

    /// Polling interval
    poll_interval: PollInterval,

    /// Transaction source (JSONRPC)
    // TODO(tarcieri): gRPC
    source: jsonrpc::Client,

    /// Tendermint RPC client
    rpc_client: tendermint_rpc::HttpClient,

    /// Sequence file
    seq_file: SequenceFile,

    /// State of the last broadcasted transaction
    last_tx: LastTx,
}

impl TxSigner {
    /// Create a new transaction signer
    pub fn new(config: &TxSignerConfig) -> Result<Self, Error> {
        let schema = amino::Schema::load_toml(&config.schema).unwrap_or_else(|e| {
            status_err!(
                "couldn't read TX schema from `{}`: {}",
                config.schema.display(),
                e
            );
            process::exit(1);
        });

        let tx_builder =
            amino::Builder::new(schema, config.chain_id.to_string(), config.account_number);

        let source = match &config.source {
            TxSource::JsonRpc { uri } => jsonrpc::Client::new(uri.clone()),
        };

        let tendermint_rpc = tendermint_rpc::HttpClient::new(config.rpc.addr.clone())?;

        let seq_file = SequenceFile::open(&config.seq_file)?;

        Ok(Self {
            chain_id: config.chain_id.clone(),
            tx_builder,
            address: config.account_address,
            context: config.context.clone(),
            acl: config.acl.clone(),
            poll_interval: config.poll_interval.clone(),
            source,
            rpc_client: tendermint_rpc,
            seq_file,
            last_tx: LastTx::default(),
        })
    }

    /// Run the transaction signer
    pub async fn run(&mut self) {
        // Fetch the block height via RPC and use that to synchronize the
        // block interval to the block height count
        let mut next_block = loop {
            match self.rpc_client.status().await {
                Ok(status) => {
                    break self.next_block_after(status.sync_info.latest_block_height.value())
                }
                Err(e) => {
                    warn!(
                        "[{}] error getting initial block height: {}",
                        self.chain_id, e
                    );
                    time::sleep(RETRY_DELAY).await
                }
            }
        };

        loop {
            info!(
                "[{}] waiting until block height: {}",
                &self.chain_id, next_block
            );

            let status = match self.wait_until_block_height(next_block).await {
                Ok(status) => status,
                Err(e) => {
                    error!(
                        "[{}] couldn't get current block height via RPC: {}",
                        &self.chain_id, e
                    );
                    time::sleep(RETRY_DELAY).await;
                    continue;
                }
            };

            let current_block_height = status.sync_info.latest_block_height.value();
            next_block = self.next_block_after(current_block_height);

            if let Err(e) = self.request_and_sign_tx(status).await {
                error!("[{}] {} - {}", &self.chain_id, self.source.uri(), e);
            }
        }
    }

    /// Wait until the chain is at the given block height
    async fn wait_until_block_height(
        &mut self,
        target_height: u64,
    ) -> Result<status::Response, Error> {
        let (block_interval, min_secs) = match self.poll_interval {
            PollInterval::Block { blocks, min_secs } => (blocks, min_secs),
        };

        let min_deadline = time::Instant::now() + time::Duration::from_secs(min_secs);

        loop {
            let status = self.rpc_client.status().await?;
            let current_height = status.sync_info.latest_block_height.value();

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

                    time::sleep_until(min_deadline).await;
                }

                return Ok(status);
            } else if target_height.checked_sub(current_height).unwrap() > block_interval {
                warn!(
                    "block wait sanity check failed: current={} target={} interval={}",
                    current_height, target_height, block_interval
                );

                // Hopefully returning the current status will sync us back up if this ever happens
                return Ok(status);
            }

            time::sleep(RPC_POLL_INTERVAL).await
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

    /// Request a transaction to be signed from the transaction source
    async fn request_and_sign_tx(&mut self, status: status::Response) -> Result<(), Error> {
        let params = jsonrpc::Request {
            network: self.chain_id.clone(),
            context: self.context.clone(),
            status: status.sync_info,
            last_tx_response: Option::from(&self.last_tx),
        };

        let tx_req = match self.source.request(params).await? {
            Some(req) => req,
            None => return Ok(()),
        };

        if self.chain_id.as_str() != tx_req.chain_id {
            fail!(
                ErrorKind::ChainIdError,
                "expected `{}`, got `{}`",
                self.chain_id,
                tx_req.chain_id
            );
        }

        let seq = self.seq_file.sequence();
        let sign_msg = SignMsg::new(&tx_req, &self.tx_builder, seq)?;

        // If no transaction broadcasted successfully before, retry with a
        // higher sequence number to see if we're out-of-sync
        // TODO(tarcieri): handle these errors by querying sequence number via RPC
        let retry_on_failure = !self.last_tx.is_response();

        if let Err(e) = self.broadcast_tx(sign_msg, seq).await {
            error!("[{}] {} - {}", &self.chain_id, self.source.uri(), e);

            // If the last transaction errored, speculatively try the next
            // sequence number, as the previous transaction may have been
            // successfully broadcast but we never got a response.
            // TODO(tarcieri): replace this by resynchronizing the sequence number
            if retry_on_failure {
                let seq = seq.checked_add(1).unwrap();

                warn!(
                    "[{}] {} - retrying transaction at sequence {}",
                    &self.chain_id,
                    self.source.uri(),
                    seq
                );

                let sign_msg = SignMsg::new(&tx_req, &self.tx_builder, seq)?;
                if let Err(e) = self.broadcast_tx(sign_msg, seq).await {
                    error!("[{}] {} - {}", &self.chain_id, self.source.uri(), e);

                    // Try a third time for good measure
                    // If we wanted to generalize this, it could use a loop,
                    // but instead of that it'd be better to implement
                    // self-healing by consulting the sequence from the chain
                    // itself once we can use e.g. gRPC to do to that.
                    let seq = seq.checked_add(1).unwrap();

                    warn!(
                        "[{}] {} - retrying transaction at sequence {}",
                        &self.chain_id,
                        self.source.uri(),
                        seq
                    );

                    let sign_msg = SignMsg::new(&tx_req, &self.tx_builder, seq)?;
                    self.broadcast_tx(sign_msg, seq).await?;
                }
            }
        }

        Ok(())
    }

    /// Broadcast signed transaction to the Tendermint P2P network via RPC
    async fn broadcast_tx(&mut self, sign_msg: SignMsg, sequence: u64) -> Result<(), Error> {
        let tx = self.sign_tx(&sign_msg)?;

        let amino_tx = tendermint_rpc::abci::Transaction::from(
            tx.to_amino_bytes(self.tx_builder.schema().namespace()),
        );

        let amino_tx_hex =
            String::from_utf8(hex::encode(amino_tx.as_ref())).expect("hex should always be UTF-8");

        info!(
            "[{}] broadcasting TX: {}",
            self.chain_id,
            amino_tx_hex.to_ascii_uppercase()
        );

        let response = match self.rpc_client.broadcast_tx_commit(amino_tx).await {
            Ok(resp) => {
                self.last_tx = LastTx::Response(Box::new(resp.clone()));
                resp
            }
            Err(e) => {
                self.last_tx = LastTx::Error(e.clone());
                return Err(e.into());
            }
        };

        if response.check_tx.code.is_err() {
            fail!(
                ErrorKind::TendermintError,
                "TX broadcast failed: {} (CheckTx code={})",
                response.check_tx.log,
                response.check_tx.code.value(),
            );
        }

        // If CheckTx succeeds the sequence number always needs to be
        // incremented, even if DeliverTx subsequently fails
        self.seq_file.persist(sequence.checked_add(1).unwrap())?;

        if response.deliver_tx.code.is_err() {
            fail!(
                ErrorKind::TendermintError,
                "TX broadcast failed: {} (DeliverTx code={}, hash={})",
                response.deliver_tx.log,
                response.deliver_tx.code.value(),
                response.hash
            );
        }

        info!(
            "[{}] successfully broadcast TX {} (shash={})",
            self.chain_id,
            self.seq_file.sequence(),
            response.hash
        );

        Ok(())
    }

    fn sign_tx(&self, sign_msg: &SignMsg) -> Result<amino::StdTx, Error> {
        sign_msg.authorize(&self.acl)?;

        let registry = chain::REGISTRY.get();

        let chain = registry.get_chain(&self.chain_id).unwrap_or_else(|| {
            panic!("chain '{}' missing from registry!", &self.chain_id);
        });

        debug!("[{}] performing signature", &self.chain_id);

        let account_id = tendermint::account::Id::new(self.address.0);

        let mut signature = amino::StdSignature::from(
            chain
                .keyring
                .sign_ecdsa(account_id, sign_msg.sign_bytes())?,
        );

        signature.pub_key = chain
            .keyring
            .get_account_pubkey(account_id)
            .expect("missing account key")
            .to_bytes();

        let msg_type_info = sign_msg
            .msg_types()
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
            sign_msg.msgs().len(),
            msg_type_info,
        );

        Ok(sign_msg.to_stdtx(signature))
    }
}
