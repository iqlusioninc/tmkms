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
    config::tx_signer::{TxAcl, TxSignerConfig, TxSource},
    error::{Error, ErrorKind},
    prelude::*,
};
use abscissa_tokio::tokio;
use sequence_file::SequenceFile;
use std::{collections::BTreeSet as Set, process, time::Duration};
use stdtx::{StdSignature, StdTx};

/// Frequency at which to retry after failures
pub const RETRY_DELAY: Duration = Duration::from_secs(5);

/// Transaction signer
pub struct TxSigner {
    /// Chain ID of the Tendermint network this validator is part of
    chain_id: tendermint::chain::Id,

    /// Transaction builder
    tx_builder: stdtx::Builder,

    /// Access Control List for authorized transaaction types to sign
    acl: TxAcl,

    /// Account address
    address: stdtx::Address,

    /// Transaction source (JSONRPC)
    // TODO(tarcieri): gRPC
    source: jsonrpc::Client,

    /// Tendermint RPC client
    // TODO(tarcieri): use RPC client
    #[allow(dead_code)]
    tendermint_rpc: tendermint_rpc::Client,

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
            TxSource::JsonRpc { uri, poll_secs } => {
                jsonrpc::Client::new(uri.clone(), Duration::from_secs(*poll_secs))
            }
        };

        let tendermint_rpc = tendermint_rpc::Client::new(config.rpc_addr.clone());

        let seq_file = SequenceFile::open(&config.seq_file)?;

        Ok(Self {
            chain_id: config.chain_id,
            tx_builder,
            acl: config.acl.clone(),
            address: config.account_address,
            source,
            tendermint_rpc,
            seq_file,
        })
    }

    /// Run the transaction signer
    pub async fn run(&mut self) {
        let mut poll_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + self.source.poll_interval(),
            self.source.poll_interval(),
        );

        loop {
            // Request batch of transactions from source
            let tx_reqs = match self.source.request().await {
                Ok(req) => req,
                Err(e) => {
                    error!("couldn't fetch TXes from `{}`: {}", self.source.uri(), e);
                    tokio::time::delay_for(RETRY_DELAY).await;
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

            poll_interval.tick().await;
        }
    }

    /// Sign the given transaction signing request
    pub fn sign_tx(&self, req: TxSigningRequest) -> Result<StdTx, Error> {
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

        let signature =
            StdSignature::from(chain.keyring.sign_ecdsa(account_id, sign_msg.as_bytes())?);

        let msg_type_info = msg_types
            .iter()
            .map(|ty| ty.to_string())
            .collect::<Vec<_>>()
            .join(",");

        info!(
            "[{}] signed `{}` TX with {}",
            self.chain_id,
            msg_type_info,
            self.address
                .to_bech32(self.tx_builder.schema().acc_prefix())
        );

        Ok(StdTx::new(&msgs, req.fee, vec![signature], req.memo))
    }

    /// Broadcast signed transaction to the Tendermint P2P network via RPC
    pub async fn broadcast_tx(&mut self, tx: StdTx) -> Result<(), Error> {
        let amino_tx = tendermint::abci::Transaction::new(
            tx.to_amino_bytes(self.tx_builder.schema().namespace()),
        );

        let response = self.tendermint_rpc.broadcast_tx_sync(amino_tx).await?;

        if response.code.is_ok() {
            info!("[{}] broadcast TX: {:?}", self.chain_id, response);
            Ok(())
        } else {
            fail!(
                ErrorKind::TendermintError,
                "error broadcasting TX: {:?}",
                response
            );
        }
    }
}
