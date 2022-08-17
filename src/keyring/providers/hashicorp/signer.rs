use std::sync::Arc;
use std::sync::Mutex;

use crate::keyring::providers::hashicorp::client::TendermintValidatorApp;

/// ed25519 signature provider for the Ledger Tendermint Validator app
pub(super) struct Ed25519HashiCorpAppSigner {
    app: Arc<Mutex<TendermintValidatorApp>>,
}
