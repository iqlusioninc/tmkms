//! Fortanix DSM signing provider

use crate::{
    chain,
    config::provider::fortanixdsm::{FortanixDsmConfig, KeyDescriptor, SigningKeyConfig},
    config::provider::KeyType,
    error::{Error, ErrorKind::*},
    keyring::{self, ed25519, SigningProvider},
    prelude::*,
};
use elliptic_curve::pkcs8::{
    spki::Error as SpkiError, DecodePublicKey, ObjectIdentifier, SubjectPublicKeyInfoRef,
};
use elliptic_curve::PublicKey as EcPublicKey;
use k256::ecdsa::{Error as SignError, Signature as EcdsaSignature};
use sdkms::api_model::{
    DigestAlgorithm, EllipticCurve, ObjectType, SignRequest, SignResponse, SobjectDescriptor,
};
use sdkms::{Error as SdkmsError, SdkmsClient};
use signature::Signer;
use std::sync::Arc;
use tendermint::public_key::{Ed25519, Secp256k1};
use tendermint::{PublicKey, TendermintKey};
use url::Url;

/// Create Fortanix DSM backed signer objects from the given configuration
pub fn init(registry: &mut chain::Registry, configs: &[FortanixDsmConfig]) -> Result<(), Error> {
    if configs.is_empty() {
        return Ok(());
    }
    for config in configs {
        let client = make_sdkms_client(config)?;
        for key in &config.signing_keys {
            add_key(registry, key, client.clone())?;
        }
    }
    Ok(())
}

fn make_sdkms_client(config: &FortanixDsmConfig) -> Result<Arc<SdkmsClient>, Error> {
    let api_endpoint = Url::parse(&config.api_endpoint)
        .map_err(|e| format_err!(FortanixDsmError, "`api_endpoint` is not a valid URL: {}", e))?;
    if api_endpoint.scheme() != "https" {
        fail!(
            FortanixDsmError,
            "`api_endpoint` must be an `https` URL, found: `{}`",
            api_endpoint.scheme()
        );
    }
    if api_endpoint.path() != "/" {
        fail!(FortanixDsmError, "`api_endpoint` must not have a path");
    }
    if api_endpoint.query().is_some() || api_endpoint.fragment().is_some() {
        fail!(
            FortanixDsmError,
            "`api_endpoint` must not have query parameters or fragment"
        );
    }
    let client = SdkmsClient::builder()
        .with_api_endpoint(&config.api_endpoint)
        .with_api_key(&config.api_key)
        .build()
        .map_err(|e| map_dsm_error("failed to create DSM client", e))?;

    Ok(Arc::new(client))
}

fn map_dsm_error(ctx: &str, e: SdkmsError) -> Error {
    format_err!(FortanixDsmError, "{}: {}", ctx, e).into()
}

struct SigningKey {
    client: Arc<SdkmsClient>,
    descriptor: SobjectDescriptor,
    elliptic_curve: EllipticCurve,
}

impl SigningKey {
    fn new(
        client: Arc<SdkmsClient>,
        descriptor: KeyDescriptor,
        key_type: KeyType,
    ) -> Result<(Self, TendermintKey), Error> {
        let descriptor: SobjectDescriptor = descriptor.into();
        let key = client
            .get_sobject(None, &descriptor)
            .map_err(|e| map_dsm_error("failed to get security object", e))?;

        let required_curve = match key_type {
            KeyType::Account => EllipticCurve::SecP256K1,
            KeyType::Consensus => EllipticCurve::Ed25519,
        };

        if key.obj_type != ObjectType::Ec {
            fail!(FortanixDsmError, "expected an EC found {:?}", key.obj_type);
        }
        if key.elliptic_curve != Some(required_curve) {
            fail!(
                FortanixDsmError,
                "expected elliptic curve {:?}, found {:?}",
                required_curve,
                key.elliptic_curve
            );
        }

        let public_key = key.pub_key.ok_or_else(|| {
            format_err!(
                FortanixDsmError,
                "could not find security object's public key"
            )
        })?;

        let public_key = match key_type {
            KeyType::Account => {
                let pub_key: Secp256k1 = EcPublicKey::from_public_key_der(&public_key)
                    .map_err(|e| {
                        format_err!(
                            FortanixDsmError,
                            "failed to parse secp256k1 public key: {}",
                            e
                        )
                    })?
                    .into();
                TendermintKey::AccountKey(PublicKey::from(pub_key))
            }
            KeyType::Consensus => {
                let pub_key = Ed25519PublicKey::from_public_key_der(&public_key).map_err(|e| {
                    format_err!(
                        FortanixDsmError,
                        "failed to parse ed25519 public key: {}",
                        e
                    )
                })?;
                TendermintKey::ConsensusKey(PublicKey::from(pub_key.0))
            }
        };

        Ok((
            SigningKey {
                client,
                descriptor,
                elliptic_curve: required_curve,
            },
            public_key,
        ))
    }

    fn sign(&self, msg: &[u8], hash_alg: DigestAlgorithm) -> Result<SignResponse, SignError> {
        let req = SignRequest {
            key: Some(self.descriptor.clone()),
            data: Some(msg.to_owned().into()),
            hash_alg,
            hash: None,
            mode: None,
            deterministic_signature: None,
        };
        self.client.sign(&req).map_err(SignError::from_source)
    }
}

impl Signer<EcdsaSignature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<EcdsaSignature, SignError> {
        assert_eq!(self.elliptic_curve, EllipticCurve::SecP256K1);
        let resp = self.sign(msg, DigestAlgorithm::Sha256)?;
        EcdsaSignature::from_der(&resp.signature)
    }
}

impl Signer<ed25519::Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<ed25519::Signature, SignError> {
        assert_eq!(self.elliptic_curve, EllipticCurve::Ed25519);
        let resp = self.sign(msg, DigestAlgorithm::Sha512)?;
        ed25519::Signature::from_slice(&resp.signature)
    }
}

fn add_key(
    registry: &mut chain::Registry,
    config: &SigningKeyConfig,
    client: Arc<SdkmsClient>,
) -> Result<(), Error> {
    let (signing_key, public_key) =
        SigningKey::new(client, config.key.clone(), config.key_type.clone())?;

    match config.key_type {
        KeyType::Account => {
            let signer = keyring::ecdsa::Signer::new(
                SigningProvider::FortanixDsm,
                public_key,
                Box::new(signing_key),
            );
            for chain_id in &config.chain_ids {
                registry.add_account_key(chain_id, signer.clone())?;
            }
        }
        KeyType::Consensus => {
            let signer = ed25519::Signer::new(
                SigningProvider::FortanixDsm,
                public_key,
                Box::new(signing_key),
            );
            for chain_id in &config.chain_ids {
                registry.add_consensus_key(chain_id, signer.clone())?;
            }
        }
    }

    Ok(())
}

// See RFC 8410 section 3
const ED_25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

struct Ed25519PublicKey(Ed25519);

impl<'a> TryFrom<SubjectPublicKeyInfoRef<'a>> for Ed25519PublicKey {
    type Error = SpkiError;

    fn try_from(spki: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
        spki.algorithm.assert_algorithm_oid(ED_25519_OID)?;

        if spki.algorithm.parameters.is_some() {
            // TODO: once/if https://github.com/RustCrypto/formats/issues/354 is addressed we should use that error variant.
            return Err(SpkiError::KeyMalformed);
        }

        Ed25519::try_from(spki.subject_public_key.as_bytes().unwrap())
            .map_err(|_| SpkiError::KeyMalformed)
            .map(Ed25519PublicKey)
    }
}
