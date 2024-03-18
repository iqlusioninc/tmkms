//! A session with a validator node

use crate::{
    chain::{self, state::StateErrorKind, Chain},
    config::ValidatorConfig,
    connection::{tcp, unix::UnixConnection, Connection},
    error::{Error, ErrorKind::*},
    prelude::*,
    privval::SignableMsg,
    rpc::{Request, Response},
};
use std::{os::unix::net::UnixStream, time::Instant};
use tendermint::{consensus, TendermintKey};
use tendermint_config::net;
use tendermint_proto as proto;

/// Encrypted session with a validator node
pub struct Session {
    /// Validator configuration options
    config: ValidatorConfig,

    /// TCP connection to a validator node
    connection: Box<dyn Connection>,
}

impl Session {
    /// Open a session using the given validator configuration
    pub fn open(config: ValidatorConfig) -> Result<Self, Error> {
        let connection: Box<dyn Connection> = match &config.addr {
            net::Address::Tcp {
                peer_id,
                host,
                port,
            } => {
                debug!(
                    "[{}@{}] connecting to validator...",
                    &config.chain_id, &config.addr
                );

                let conn = tcp::open_secret_connection(
                    host,
                    *port,
                    &config.secret_key,
                    peer_id,
                    config.timeout,
                    config.protocol_version.into(),
                )?;

                info!(
                    "[{}@{}] connected to validator successfully",
                    &config.chain_id, &config.addr
                );

                if peer_id.is_none() {
                    // TODO(tarcieri): make peer verification mandatory
                    warn!(
                        "[{}@{}]: unverified validator peer ID! ({})",
                        &config.chain_id,
                        &config.addr,
                        conn.remote_pubkey().peer_id()
                    );
                }

                Box::new(conn)
            }
            net::Address::Unix { path } => {
                if let Some(timeout) = config.timeout {
                    warn!("timeouts not supported with Unix sockets: {}", timeout);
                }

                debug!(
                    "{}: Connecting to socket at {}...",
                    &config.chain_id, &config.addr
                );

                let socket = UnixStream::connect(path)?;
                let conn = UnixConnection::new(socket);

                info!(
                    "[{}@{}] connected to validator successfully",
                    &config.chain_id, &config.addr
                );

                Box::new(conn)
            }
        };

        Ok(Self { config, connection })
    }

    /// Main request loop
    pub fn request_loop(&mut self) -> Result<(), Error> {
        while self.handle_request()? {}
        Ok(())
    }

    /// Handle an incoming request from the validator
    fn handle_request(&mut self) -> Result<bool, Error> {
        let request = Request::read(&mut self.connection, &self.config.chain_id)?;
        debug!(
            "[{}@{}] received request: {:?}",
            &self.config.chain_id, &self.config.addr, &request
        );

        let response = match request {
            Request::SignProposal(_) | Request::SignVote(_) => {
                self.sign(request.into_signable_msg()?)?
            }
            // non-signable requests:
            Request::PingRequest => Response::Ping(proto::privval::PingResponse {}),
            Request::ShowPublicKey => self.get_public_key()?,
        };

        debug!(
            "[{}@{}] sending response: {:?}",
            &self.config.chain_id, &self.config.addr, &response
        );

        let response_bytes = response.encode()?;
        self.connection.write_all(&response_bytes)?;

        Ok(true)
    }

    /// Perform a digital signature operation
    fn sign(&mut self, mut signable_msg: SignableMsg) -> Result<Response, Error> {
        self.check_max_height(&signable_msg)?;

        let registry = chain::REGISTRY.get();

        let chain = registry
            .get_chain(&self.config.chain_id)
            .unwrap_or_else(|| {
                panic!("chain '{}' missing from registry!", &self.config.chain_id);
            });

        if let Some(remote_err) = self.update_consensus_state(chain, &signable_msg)? {
            // In the event of double signing we send a response to notify the validator
            return Ok(Response::error(signable_msg, remote_err));
        }

        // TODO(tarcieri): support for non-default public keys
        let public_key = None;
        let chain_id = self.config.chain_id.clone();
        let canonical_msg = signable_msg.canonical_bytes(chain_id.clone())?;

        let started_at = Instant::now();
        let consensus_sig = chain.keyring.sign(public_key, &canonical_msg)?;
        signable_msg.add_consensus_signature(consensus_sig);
        self.log_signing_request(&signable_msg, started_at).unwrap();

        // Add extension signature if the message is a precommit for a non-empty block ID.
        if chain.sign_extensions {
            if let Some(extension_msg) = signable_msg.extension_bytes(chain_id)? {
                let started_at = Instant::now();
                let extension_sig = chain.keyring.sign(public_key, &extension_msg)?;
                signable_msg.add_extension_signature(extension_sig)?;

                info!(
                    "[{}@{}] signed vote extension ({} ms)",
                    &self.config.chain_id,
                    &self.config.addr,
                    started_at.elapsed().as_millis(),
                );
            }
        }

        Ok(signable_msg.into())
    }

    /// If a max block height is configured, ensure the block we're signing
    /// doesn't exceed it
    fn check_max_height(&mut self, signable_msg: &SignableMsg) -> Result<(), Error> {
        if let Some(max_height) = self.config.max_height {
            let height = signable_msg.height();

            if height > max_height {
                fail!(
                    ExceedMaxHeight,
                    "attempted to sign at height {} which is greater than {}",
                    height,
                    max_height,
                );
            }
        }

        Ok(())
    }

    /// Update our local knowledge of the chain's consensus state, detecting
    /// attempted double signing and sending a response in the event it happens
    fn update_consensus_state(
        &mut self,
        chain: &Chain,
        signable_msg: &SignableMsg,
    ) -> Result<Option<proto::privval::RemoteSignerError>, Error> {
        let msg_type = signable_msg.msg_type();
        let request_state = signable_msg.consensus_state();
        let mut chain_state = chain.state.lock().unwrap();

        match chain_state.update_consensus_state(request_state.clone()) {
            Ok(()) => Ok(None),
            Err(e) if e.kind() == StateErrorKind::DoubleSign => {
                // Report double signing error back to the validator
                let original_block_id = chain_state.consensus_state().block_id_prefix();

                error!(
                    "[{}@{}] attempted double sign {:?} at h/r/s: {} ({} != {})",
                    &self.config.chain_id,
                    &self.config.addr,
                    msg_type,
                    request_state,
                    original_block_id,
                    request_state.block_id_prefix()
                );

                let remote_err = double_sign(request_state);
                Ok(Some(remote_err))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Get the public key for (the only) public key in the keyring
    fn get_public_key(&mut self) -> Result<Response, Error> {
        let registry = chain::REGISTRY.get();

        let chain = registry
            .get_chain(&self.config.chain_id)
            .unwrap_or_else(|| {
                panic!("chain '{}' missing from registry!", &self.config.chain_id);
            });

        let pub_key = match chain.keyring.default_pubkey()? {
            TendermintKey::AccountKey(pk) => pk,
            TendermintKey::ConsensusKey(pk) => pk,
        };

        Ok(Response::PublicKey(proto::privval::PubKeyResponse {
            pub_key: Some(pub_key.into()),
            error: None,
        }))
    }

    /// Write an INFO logline about a signing request
    fn log_signing_request(
        &self,
        signable_msg: &SignableMsg,
        started_at: Instant,
    ) -> Result<(), Error> {
        let msg_type = signable_msg.msg_type();
        let request_state = signable_msg.consensus_state();

        info!(
            "[{}@{}] signed {:?}:{} at h/r/s {} ({} ms)",
            &self.config.chain_id,
            &self.config.addr,
            msg_type,
            request_state.block_id_prefix(),
            request_state,
            started_at.elapsed().as_millis(),
        );

        Ok(())
    }
}

/// Double signing handler.
fn double_sign(consensus_state: consensus::State) -> proto::privval::RemoteSignerError {
    /// Double signing error code.
    const DOUBLE_SIGN_ERROR: i32 = 2;

    proto::privval::RemoteSignerError {
        code: DOUBLE_SIGN_ERROR,
        description: format!(
            "double signing requested at height: {}",
            consensus_state.height
        ),
    }
}
