//! Signing keyring. Presently specialized for Ed25519.

pub mod ecdsa;
pub mod ed25519;
pub mod format;
pub mod providers;

pub use self::{format::Format, providers::SigningProvider};
use crate::{
    chain,
    config::provider::ProviderConfig,
    error::{Error, ErrorKind::*},
    prelude::*,
    Map,
};
use tendermint::{account, TendermintKey};

/// File encoding for software-backed secret keys
pub type SecretKeyEncoding = subtle_encoding::Base64;

/// Signing keyring
pub struct KeyRing {
    /// ECDSA keys in the keyring
    ecdsa_keys: Map<TendermintKey, ecdsa::Signer>,

    /// Ed25519 keys in the keyring
    ed25519_keys: Map<TendermintKey, ed25519::Signer>,

    /// Formatting configuration when displaying keys (e.g. bech32)
    format: Format,
}

impl KeyRing {
    /// Create a new keyring
    pub fn new(format: Format) -> Self {
        Self {
            ecdsa_keys: Map::new(),
            ed25519_keys: Map::new(),
            format,
        }
    }

    /// Add na ECDSA key to the keyring, returning an error if we already have a
    /// signer registered for the given public key
    pub fn add_ecdsa(&mut self, signer: ecdsa::Signer) -> Result<(), Error> {
        let provider = signer.provider();
        let public_key = signer.public_key();
        let public_key_serialized = self.format.serialize(public_key);
        let key_type = match public_key {
            TendermintKey::AccountKey(_) => "account",
            TendermintKey::ConsensusKey(_) => unimplemented!(
                "ECDSA consensus keys unsupported: {:?}",
                public_key_serialized
            ),
        };

        info!(
            "[keyring:{}] added {} ECDSA key: {}",
            provider, key_type, public_key_serialized
        );

        if let Some(other) = self.ecdsa_keys.insert(public_key, signer) {
            fail!(
                InvalidKey,
                "[keyring:{}] duplicate key {} already registered as {}",
                provider,
                public_key_serialized,
                other.provider(),
            )
        } else {
            Ok(())
        }
    }

    /// Add a key to the keyring, returning an error if we already have a
    /// signer registered for the given public key
    pub fn add_ed25519(&mut self, signer: ed25519::Signer) -> Result<(), Error> {
        let provider = signer.provider();
        let public_key = signer.public_key();
        let public_key_serialized = self.format.serialize(public_key);
        let key_type = match public_key {
            TendermintKey::AccountKey(_) => unimplemented!(
                "Ed25519 account keys unsupported: {:?}",
                public_key_serialized
            ),
            TendermintKey::ConsensusKey(_) => "consensus",
        };

        info!(
            "[keyring:{}] added {} Ed25519 key: {}",
            provider, key_type, public_key_serialized
        );

        if let Some(other) = self.ed25519_keys.insert(public_key, signer) {
            fail!(
                InvalidKey,
                "[keyring:{}] duplicate key {} already registered as {}",
                provider,
                public_key_serialized,
                other.provider(),
            )
        } else {
            Ok(())
        }
    }

    /// Get the default Ed25519 (i.e. consensus) public key for this keyring
    pub fn default_ed25519_pubkey(&self) -> Result<TendermintKey, Error> {
        let mut keys = self.ed25519_keys.keys();

        if keys.len() == 1 {
            Ok(*keys.next().unwrap())
        } else {
            fail!(InvalidKey, "expected only one key in keyring");
        }
    }

    /// Get ECDSA public key bytes for a given account ID
    pub fn get_account_pubkey(&self, account_id: account::Id) -> Option<tendermint::PublicKey> {
        for key in self.ecdsa_keys.keys() {
            if let TendermintKey::AccountKey(pk) = key {
                if account_id == account::Id::from(*pk) {
                    return Some(*pk);
                }
            }
        }

        None
    }

    /// Sign a message using ECDSA
    pub fn sign_ecdsa(
        &self,
        account_id: account::Id,
        msg: &[u8],
    ) -> Result<ecdsa::Signature, Error> {
        for (key, signer) in &self.ecdsa_keys {
            if let TendermintKey::AccountKey(pk) = key {
                if account_id == account::Id::from(*pk) {
                    return signer.sign(msg);
                }
            }
        }

        fail!(
            InvalidKey,
            "no ECDSA key in keyring for account ID: {}",
            account_id
        )
    }

    /// Sign a message using the secret key associated with the given public key
    /// (if it is in our keyring)
    pub fn sign_ed25519(
        &self,
        public_key: Option<&TendermintKey>,
        msg: &[u8],
    ) -> Result<ed25519::Signature, Error> {
        let signer = match public_key {
            Some(public_key) => self.ed25519_keys.get(public_key).ok_or_else(|| {
                format_err!(InvalidKey, "not in keyring: {}", public_key.to_bech32(""))
            })?,
            None => {
                let mut vals = self.ed25519_keys.values();

                if vals.len() > 1 {
                    fail!(SigningError, "expected only one key in keyring");
                } else {
                    vals.next()
                        .ok_or_else(|| format_err!(InvalidKey, "keyring is empty"))?
                }
            }
        };

        signer.sign(msg)
    }
}

/// Initialize the keyring from the configuration file
pub fn load_config(registry: &mut chain::Registry, config: &ProviderConfig) -> Result<(), Error> {
    #[cfg(feature = "softsign")]
    providers::softsign::init(registry, &config.softsign)?;

    #[cfg(feature = "yubihsm")]
    providers::yubihsm::init(registry, &config.yubihsm)?;

    #[cfg(feature = "ledger")]
    providers::ledgertm::init(registry, &config.ledgertm)?;

    #[cfg(feature = "fortanixdsm")]
    providers::fortanixdsm::init(registry, &config.fortanixdsm)?;

    Ok(())
}
