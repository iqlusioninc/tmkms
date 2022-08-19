use std::sync::Arc;
use std::sync::Mutex;

use crate::keyring::ed25519::Signature;
use crate::keyring::providers::hashicorp::client::TendermintValidatorApp;
use signature::{Error, Signer};

/// ed25519 signature provider for the Ledger Tendermint Validator app
pub(super) struct Ed25519HashiCorpAppSigner {
    app: Arc<Mutex<TendermintValidatorApp>>,
}

impl Ed25519HashiCorpAppSigner {
    pub fn new(app: TendermintValidatorApp) -> Self {
        Ed25519HashiCorpAppSigner {
            app: Arc::new(Mutex::new(app)),
        }
    }
}

impl Signer<Signature> for Ed25519HashiCorpAppSigner {
    /// c: Compute a compact, fixed-sized signature of the given amino/json vote
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let app = self.app.lock().unwrap();
        let sig = app.sign(msg).map_err(Error::from_source)?;
        Ok(Signature::from(sig))
    }
}
