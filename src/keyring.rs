//! Signing keyring. Presently specialized for Ed25519 and ECDSA.

pub mod ecdsa;
pub mod ed25519;
pub mod format;
pub mod providers;
pub mod signature;

pub use self::{format::Format, providers::SigningProvider, signature::Signature};
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
    pub fn default_pubkey(&self) -> Result<TendermintKey, Error> {
        if !self.ed25519_keys.is_empty() {
            let mut keys = self.ed25519_keys.keys();

            if keys.len() == 1 {
                Ok(*keys.next().unwrap())
            } else {
                fail!(InvalidKey, "expected only one ed25519 key in keyring");
            }
        } else if !self.ecdsa_keys.is_empty() {
            let mut keys = self.ecdsa_keys.keys();

            if keys.len() == 1 {
                Ok(*keys.next().unwrap())
            } else {
                fail!(InvalidKey, "expected only one ecdsa key in keyring");
            }
        } else {
            fail!(InvalidKey, "keyring is empty");
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
    pub fn sign(&self, public_key: Option<&TendermintKey>, msg: &[u8]) -> Result<Signature, Error> {
        if self.ed25519_keys.len() > 1 || self.ecdsa_keys.len() > 1 {
            fail!(SigningError, "expected only one key in keyring");
        }

        if !self.ed25519_keys.is_empty() {
            let signer = match public_key {
                Some(public_key) => self.ed25519_keys.get(public_key).ok_or_else(|| {
                    format_err!(
                        InvalidKey,
                        "not in keyring: {}",
                        match public_key {
                            TendermintKey::AccountKey(pk) => pk.to_bech32(""),
                            TendermintKey::ConsensusKey(pk) => pk.to_bech32(""),
                        }
                    )
                }),
                None => self
                    .ed25519_keys
                    .values()
                    .next()
                    .ok_or_else(|| format_err!(InvalidKey, "ed25519 keyring is empty")),
            }?;

            Ok(Signature::Ed25519(signer.sign(msg)?))
        } else if !self.ecdsa_keys.is_empty() {
            let signer = match public_key {
                Some(public_key) => self.ecdsa_keys.get(public_key).ok_or_else(|| {
                    format_err!(
                        InvalidKey,
                        "not in keyring: {}",
                        match public_key {
                            TendermintKey::AccountKey(pk) => pk.to_bech32(""),
                            TendermintKey::ConsensusKey(pk) => pk.to_bech32(""),
                        }
                    )
                }),
                None => self
                    .ecdsa_keys
                    .values()
                    .next()
                    .ok_or_else(|| format_err!(InvalidKey, "ecdsa keyring is empty")),
            }?;

            Ok(Signature::Ecdsa(signer.sign(msg)?))
        } else {
            Err(format_err!(InvalidKey, "keyring is empty").into())
        }
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

    #[cfg(feature = "hashicorp")]
    providers::hashicorp::init(registry, &config.hashicorp)?;

    Ok(())
}
