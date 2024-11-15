use abscissa_core::prelude::*;
use std::collections::{BTreeMap, HashMap};
use std::sync;

use super::error::Error;

use std::time::Duration;
use ureq::Agent;

use crate::config::provider::hashicorp::VaultEndpointConfig;
use crate::keyring::ed25519;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// Vault message envelop
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root<T> {
    #[serde(rename = "request_id")]
    pub request_id: String,
    #[serde(rename = "lease_id")]
    pub lease_id: String,
    pub renewable: bool,
    #[serde(rename = "lease_duration")]
    pub lease_duration: i64,
    pub data: Option<T>,
    #[serde(rename = "wrap_info")]
    pub wrap_info: Value,
    pub warnings: Value,
    pub auth: Value,
}

/// Sign Request Struct
#[derive(Debug, Serialize)]
pub(crate) struct SignRequest {
    pub input: String, // Base64 encoded
}

/// Sign Response Struct
#[derive(Debug, Deserialize)]
pub(crate) struct SignResponse {
    pub signature: String, // Base64 encoded
}

#[derive(Debug, Serialize)]
pub(crate) struct ImportRequest {
    pub r#type: String,
    pub ciphertext: String,
    pub hash_function: String,
    pub exportable: bool,
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum ExportKeyType {
    Encryption,
    Signing,
    Hmac,
}
impl std::fmt::Display for ExportKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportKeyType::Encryption => write!(f, "encryption-key"),
            ExportKeyType::Signing => write!(f, "signing-key"),
            ExportKeyType::Hmac => write!(f, "hmac-key"),
        }
    }
}
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum CreateKeyType {
    /// AES-128 wrapped with GCM using a 96-bit nonce size AEAD (symmetric, supports derivation and convergent encryption)
    Aes128Gcm96,
    /// AES-256 wrapped with GCM using a 96-bit nonce size AEAD (symmetric, supports derivation and convergent encryption, default)
    Aes256Gcm96,
    /// ChaCha20-Poly1305 AEAD (symmetric, supports derivation and convergent encryption)
    Chacha20Poly1305,
    /// ED25519 (asymmetric, supports derivation). When using derivation, a sign operation with the same context will derive the same key and signature; this is a signing analogue to convergent_encryption.
    Ed25519,
    /// ECDSA using the P-256 elliptic curve (asymmetric)
    EcdsaP256,
    /// ECDSA using the P-384 elliptic curve (asymmetric)
    EcdsaP384,
    /// ECDSA using the P-521 elliptic curve (asymmetric)
    EcdsaP521,
    /// RSA with bit size of 2048 (asymmetric)
    Rsa2048,
    /// RSA with bit size of 3072 (asymmetric)
    Rsa3072,
    /// RSA with bit size of 4096 (asymmetric)
    Rsa4096,
}

impl std::fmt::Display for CreateKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CreateKeyType::Aes128Gcm96 => write!(f, "aes128-gcm96"),
            CreateKeyType::Aes256Gcm96 => write!(f, "aes256-gcm96"),
            CreateKeyType::Chacha20Poly1305 => write!(f, "chacha20-poly1305"),
            CreateKeyType::Ed25519 => write!(f, "ed25519"),
            CreateKeyType::EcdsaP256 => write!(f, "ecdsa-p256"),
            CreateKeyType::EcdsaP384 => write!(f, "ecdsa-p384"),
            CreateKeyType::EcdsaP521 => write!(f, "ecdsa-p521"),
            CreateKeyType::Rsa2048 => write!(f, "rsa-2048"),
            CreateKeyType::Rsa3072 => write!(f, "rsa-3072"),
            CreateKeyType::Rsa4096 => write!(f, "rsa-4096"),
        }
    }
}

#[derive(Debug)]
struct NoVerification;

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[derive(Debug)]
pub(crate) struct VaultClient {
    agent: Agent,
    api_endpoint: String,
    endpoints: VaultEndpointConfig,
    token: String,
}

pub const VAULT_TOKEN: &str = "X-Vault-Token";
pub const CONSENUS_KEY_TYPE: &str = "ed25519";

impl VaultClient {
    pub fn new(
        api_endpoint: &str,
        token: &str,
        endpoints: Option<VaultEndpointConfig>,
        ca_cert: Option<String>,
        skip_verify: Option<bool>,
    ) -> Self {
        // this call performs token self lookup, to fail fast
        // let mut client = Client::new(host, token)?;

        // default conect timeout is 30s, this should be ok, since we block
        let mut agent_builder = ureq::AgentBuilder::new()
            .timeout_read(Duration::from_secs(5))
            .timeout_write(Duration::from_secs(5))
            .user_agent(&format!(
                "{}/{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            ));

        if ca_cert.is_some() || skip_verify.is_some() {
            // see https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html#method.install_default
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("Failed to install rustls crypto provider");

            let tls_config_builder = rustls::ClientConfig::builder();

            if skip_verify.is_some_and(|x| x) {
                let tls_config = tls_config_builder
                    .dangerous()
                    .with_custom_certificate_verifier(sync::Arc::new(NoVerification))
                    .with_no_client_auth();

                agent_builder = agent_builder.tls_config(sync::Arc::new(tls_config));
            } else if let Some(ca_cert) = ca_cert {
                let mut roots = rustls::RootCertStore::empty();

                let certs: Vec<_> = CertificateDer::pem_file_iter(ca_cert).unwrap().collect();
                for cert in certs {
                    roots.add(cert.unwrap()).unwrap();
                }

                let tls_config = tls_config_builder
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                agent_builder = agent_builder.tls_config(sync::Arc::new(tls_config));
            }
        }

        let agent: Agent = agent_builder.build();

        VaultClient {
            api_endpoint: api_endpoint.into(),
            endpoints: endpoints.unwrap_or_default(),
            agent,
            token: token.into(),
        }
    }

    pub fn public_key(
        &self,
        key_name: &str,
    ) -> Result<[u8; ed25519::VerifyingKey::BYTE_SIZE], Error> {
        /// Response struct
        #[derive(Debug, Deserialize)]
        struct PublicKeyResponse {
            keys: BTreeMap<usize, HashMap<String, String>>,
        }

        // https://developer.hashicorp.com/vault/api-docs/secret/transit#read-key
        let data = if let Some(data) = self
            .agent
            .get(&format!(
                "{}{}/{}",
                self.api_endpoint, self.endpoints.keys, key_name
            ))
            .set(VAULT_TOKEN, &self.token)
            .call()?
            .into_json::<Root<PublicKeyResponse>>()?
            .data
        {
            data
        } else {
            return Err(Error::InvalidPubKey(
                "Public key: Vault response unavailable".into(),
            ));
        };

        // latest key version
        let key_data = data.keys.iter().last();

        let pubk = if let Some((version, map)) = key_data {
            debug!("public key vetion:{}", version);
            if let Some(pubk) = map.get("public_key") {
                if let Some(key_type) = map.get("name") {
                    if CONSENUS_KEY_TYPE != key_type {
                        return Err(Error::InvalidPubKey(format!(
                            "Public key \"{}\": expected key type:{}, received:{}",
                            key_name, CONSENUS_KEY_TYPE, key_type
                        )));
                    }
                } else {
                    return Err(Error::InvalidPubKey(format!(
                        "Public key \"{}\": expected key type:{}, unable to determine type",
                        key_name, CONSENUS_KEY_TYPE
                    )));
                }
                pubk
            } else {
                return Err(Error::InvalidPubKey(
                    "Public key: unable to retrieve - \"public_key\" key is not found!".into(),
                ));
            }
        } else {
            return Err(Error::InvalidPubKey(
                "Public key: unable to retrieve last version - not available!".into(),
            ));
        };

        debug!("Public key: fetched {}={}...", key_name, pubk);

        let pubk = base64::decode(pubk)?;

        debug!(
            "Public key: base64 decoded {}, size:{}",
            key_name,
            pubk.len()
        );

        let mut array = [0u8; ed25519::VerifyingKey::BYTE_SIZE];
        array.copy_from_slice(&pubk[..ed25519::VerifyingKey::BYTE_SIZE]);

        Ok(array)
    }

    pub fn handshake(&self) -> Result<(), Error> {
        let _ = self
            .agent
            .get(&format!(
                "{}{}",
                self.api_endpoint, self.endpoints.handshake,
            ))
            .set(VAULT_TOKEN, &self.token)
            .call()
            .map_err(|e| {
                Error::Combined(
                    "Is \"access_token\" value correct?".into(),
                    Box::new(e.into()),
                )
            })?;
        Ok(())
    }

    // vault write transit/sign/cosmoshub-sign-key plaintext=$(base64 <<< "some-data")
    // "https://127.0.0.1:8200/v1/transit/sign/cosmoshub-sign-key"
    /// Sign message
    pub fn sign(
        &self,
        key_name: &str,
        message: &[u8],
    ) -> Result<[u8; ed25519::Signature::BYTE_SIZE], Error> {
        debug!("signing request: received");
        if message.is_empty() {
            return Err(Error::InvalidEmptyMessage);
        }

        let body = SignRequest {
            input: base64::encode(message),
        };

        debug!("signing request: base64 encoded and about to submit for signing...");

        let data = if let Some(data) = self
            .agent
            .post(&format!(
                "{}{}/{}",
                self.api_endpoint, self.endpoints.sign, key_name
            ))
            .set(VAULT_TOKEN, &self.token)
            .send_json(body)?
            .into_json::<Root<SignResponse>>()?
            .data
        {
            data
        } else {
            return Err(Error::NoSignature);
        };

        let parts = data.signature.split(':').collect::<Vec<&str>>();
        if parts.len() != 3 {
            return Err(Error::InvalidSignature(format!(
                "expected 3 parts, received:{} full:{}",
                parts.len(),
                data.signature
            )));
        }

        // signature: "vault:v1:/bcnnk4p8Uvidrs1/IX9s66UCOmmfdJudcV1/yek9a2deMiNGsVRSjirz6u+ti2wqUZfG6UukaoSHIDSSRV5Cw=="
        let base64_signature = if let Some(sign) = parts.last() {
            sign.to_owned()
        } else {
            // this should never happen
            return Err(Error::InvalidSignature("last part is not available".into()));
        };

        let signature = base64::decode(base64_signature)?;
        if signature.len() != 64 {
            return Err(Error::InvalidSignature(format!(
                "invalid signature length! 64 == {}",
                signature.len()
            )));
        }

        let mut array = [0u8; ed25519::Signature::BYTE_SIZE];
        array.copy_from_slice(&signature[..ed25519::Signature::BYTE_SIZE]);
        Ok(array)
    }

    pub fn wrapping_key_pem(&self) -> Result<String, Error> {
        debug!("getting wraping key...");
        #[derive(Debug, Deserialize)]
        struct PublicKeyResponse {
            public_key: String,
        }

        let data = if let Some(data) = self
            .agent
            .get(&format!(
                "{}{}",
                self.api_endpoint, self.endpoints.wrapping_key
            ))
            .set(VAULT_TOKEN, &self.token)
            .call()?
            .into_json::<Root<PublicKeyResponse>>()?
            .data
        {
            data
        } else {
            return Err(Error::InvalidPubKey("Error getting wrapping key!".into()));
        };

        Ok(data.public_key.trim().to_owned())
    }

    pub fn import_key(
        &self,
        key_name: &str,
        key_type: CreateKeyType,
        ciphertext: &str,
        exportable: bool,
    ) -> Result<(), Error> {
        let body = ImportRequest {
            r#type: key_type.to_string(),
            ciphertext: ciphertext.into(),
            hash_function: "SHA256".into(),
            exportable,
        };

        let _ = self
            .agent
            .post(&format!(
                "{}{}/{}/import",
                self.api_endpoint, self.endpoints.keys, key_name
            ))
            .set(VAULT_TOKEN, &self.token)
            .send_json(body)?;

        Ok(())
    }
}
