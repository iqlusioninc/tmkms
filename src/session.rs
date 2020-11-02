//! A session with a validator node

use crate::{
    amino_types::{
        PingResponse, PubKeyRequest, PubKeyResponse, RemoteError, SignedMsgType, TendermintRequest,
    },
    chain::{self, state::StateErrorKind, Chain},
    config::ValidatorConfig,
    connection::{tcp, unix::UnixConnection, Connection},
    error::{Error, ErrorKind::*},
    prelude::*,
    rpc::{Request, Response},
};
use std::{fmt::Debug, os::unix::net::UnixStream, time::Instant};
use tendermint::{consensus, net};

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
                    config.protocol_version,
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
        let request = Request::read(&mut self.connection, self.config.protocol_version)?;
        debug!(
            "[{}@{}] received request: {:?}",
            &self.config.chain_id, &self.config.addr, &request
        );

        let response = match request {
            Request::SignProposal(req) => self.sign(req)?,
            Request::SignVote(req) => self.sign(req)?,
            // non-signable requests:
            Request::ReplyPing(_) => Response::Ping(PingResponse {}),
            Request::ShowPublicKey(ref req) => self.get_public_key(req)?,
        };

        debug!(
            "[{}@{}] sending response: {:?}",
            &self.config.chain_id, &self.config.addr, &response
        );

        let response_bytes = response.encode(self.config.protocol_version)?;
        self.connection.write_all(&response_bytes)?;

        Ok(true)
    }

    /// Perform a digital signature operation
    fn sign<R>(&mut self, mut request: R) -> Result<Response, Error>
    where
        R: TendermintRequest + Debug,
    {
        request
            .validate()
            .map_err(|e| format_err!(SigningError, "failed to validate request: {}", e))?;

        self.check_max_height(&mut request)?;

        let registry = chain::REGISTRY.get();

        let chain = registry
            .get_chain(&self.config.chain_id)
            .unwrap_or_else(|| {
                panic!("chain '{}' missing from registry!", &self.config.chain_id);
            });

        if let Some(remote_err) = self.update_consensus_state(chain, &request)? {
            // In the event of double signing we send a response to notify the validator
            return Ok(request.build_response(Some(remote_err)));
        }

        let mut to_sign = vec![];
        request.sign_bytes(self.config.chain_id, &mut to_sign)?;

        let started_at = Instant::now();

        // TODO(ismail): figure out which key to use here instead of taking the only key
        let signature = chain.keyring.sign_ed25519(None, &to_sign)?;

        self.log_signing_request(&request, started_at).unwrap();
        request.set_signature(&signature);

        Ok(request.build_response(None))
    }

    /// If a max block height is configured, ensure the block we're signing
    /// doesn't exceed it
    fn check_max_height<R>(&mut self, request: &mut R) -> Result<(), Error>
    where
        R: TendermintRequest + Debug,
    {
        if let Some(max_height) = self.config.max_height {
            if let Some(height) = request.height() {
                if height > max_height.value() as i64 {
                    fail!(
                        ExceedMaxHeight,
                        "attempted to sign at height {} which is greater than {}",
                        height,
                        max_height,
                    );
                }
            }
        }

        Ok(())
    }

    /// Update our local knowledge of the chain's consensus state, detecting
    /// attempted double signing and sending a response in the event it happens
    fn update_consensus_state<R>(
        &mut self,
        chain: &Chain,
        request: &R,
    ) -> Result<Option<RemoteError>, Error>
    where
        R: TendermintRequest + Debug,
    {
        let (msg_type, request_state) = parse_request(request)?;

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

                let remote_err = RemoteError::double_sign(request_state.height.into());
                Ok(Some(remote_err))
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Get the public key for (the only) public key in the keyring
    fn get_public_key(&mut self, _request: &PubKeyRequest) -> Result<Response, Error> {
        let registry = chain::REGISTRY.get();

        let chain = registry
            .get_chain(&self.config.chain_id)
            .unwrap_or_else(|| {
                panic!("chain '{}' missing from registry!", &self.config.chain_id);
            });

        Ok(Response::PublicKey(PubKeyResponse::from(
            *chain.keyring.default_ed25519_pubkey()?,
        )))
    }

    /// Write an INFO logline about a signing request
    fn log_signing_request<R>(&self, request: &R, started_at: Instant) -> Result<(), Error>
    where
        R: TendermintRequest + Debug,
    {
        let (msg_type, request_state) = parse_request(request)?;

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

/// Parse the consensus state from an incoming request
// TODO(tarcieri): fix the upstream Amino parser to do this correctly for us
fn parse_request<R>(request: &R) -> Result<(SignedMsgType, consensus::State), Error>
where
    R: TendermintRequest + Debug,
{
    let msg_type = request
        .msg_type()
        .ok_or_else(|| format_err!(ProtocolError, "no message type for this request"))?;

    let mut consensus_state = request
        .consensus_state()
        .ok_or_else(|| format_err!(ProtocolError, "no consensus state in request"))?;

    consensus_state.step = match msg_type {
        SignedMsgType::Proposal => 0,
        SignedMsgType::PreVote => 1,
        SignedMsgType::PreCommit => 2,
    };

    Ok((msg_type, consensus_state))
}
