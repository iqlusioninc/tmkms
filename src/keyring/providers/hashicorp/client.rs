use abscissa_core::prelude::*;
use std::collections::{BTreeMap, HashMap};
use std::{fs, sync};

use super::error::Error;

use std::time::Duration;
use ureq::Agent;

use crate::keyring::ed25519;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CONSENUS_KEY_TYPE: &str = "ed25519";
const VAULT_TOKEN: &str = "X-Vault-Token";

pub(crate) struct TendermintValidatorApp {
    agent: Agent,
    api_endpoint: String,
    token: String,
    key_name: String,
    public_key_value: Option<[u8; ed25519::VerifyingKey::BYTE_SIZE]>,
}

// TODO(tarcieri): check this is actually sound?! :-)
#[allow(unsafe_code)]
unsafe impl Send for TendermintValidatorApp {}

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
struct SignRequest {
    input: String, // Base64 encoded
}

/// Sign Response Struct
#[derive(Debug, Deserialize)]
struct SignResponse {
    signature: String, // Base64 encoded
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

impl TendermintValidatorApp {
    pub fn connect(
        api_endpoint: &str,
        token: &str,
        key_name: &str,
        ca_cert: Option<String>,
        skip_verify: Option<bool>,
    ) -> Result<Self, Error> {
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

        if let Some(ca_cert) = ca_cert {
            let cert_bytes = fs::read(ca_cert).expect("Failed to read cert file");
            let root_cert = native_tls::Certificate::from_pem(&cert_bytes)
                .expect("Failed to parse PEM certificate");
            let mut builder = native_tls::TlsConnector::builder();
            builder.add_root_certificate(root_cert);

            if skip_verify.is_some_and(|x| x) {
                builder.danger_accept_invalid_certs(true);
            }

            let connector = builder.build().expect("failed to construct TLS connector");
            agent_builder = agent_builder.tls_connector(sync::Arc::new(connector))
        }

        let agent: Agent = agent_builder.build();

        let app = TendermintValidatorApp {
            agent,
            api_endpoint: api_endpoint.to_owned(),
            token: token.to_owned(),
            key_name: key_name.to_owned(),
            public_key_value: None,
        };

        debug!("Initialized with Vault host at {}", api_endpoint);
        app.hand_shake()?;

        Ok(app)
    }

    fn hand_shake(&self) -> Result<(), Error> {
        let _ = self
            .agent
            .get(&format!("{}/v1/auth/token/lookup-self", self.api_endpoint))
            .set(VAULT_TOKEN, &self.token)
            .call()
            .map_err(|e| {
                super::error::Error::Combined(
                    "Is \"access_token\" value correct?".into(),
                    Box::new(e.into()),
                )
            })?;
        Ok(())
    }

    // vault read transit/keys/cosmoshub-sign-key
    // GET http://0.0.0.0:8200/v1/transit/keys/cosmoshub-sign-key
    /// Get public key
    pub fn public_key(&mut self) -> Result<[u8; ed25519::VerifyingKey::BYTE_SIZE], Error> {
        if let Some(v) = self.public_key_value {
            debug!("using cached public key {}...", self.key_name);
            return Ok(v);
        }

        debug!("fetching public key for {}...", self.key_name);

        /// Response struct
        #[derive(Debug, Deserialize)]
        struct PublicKeyResponse {
            keys: BTreeMap<usize, HashMap<String, String>>,
        }

        // TODO - explore "latest"
        let data = if let Some(data) = self
            .agent
            .get(&format!(
                "{}/v1/transit/keys/{}",
                self.api_endpoint, self.key_name
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
                            self.key_name, CONSENUS_KEY_TYPE, key_type
                        )));
                    }
                } else {
                    return Err(Error::InvalidPubKey(format!(
                        "Public key \"{}\": expected key type:{}, unable to determine type",
                        self.key_name, CONSENUS_KEY_TYPE
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

        debug!("Public key: fetched {}={}...", self.key_name, pubk);

        let pubk = base64::decode(pubk)?;

        debug!(
            "Public key: base64 decoded {}, size:{}",
            self.key_name,
            pubk.len()
        );

        let mut array = [0u8; ed25519::VerifyingKey::BYTE_SIZE];
        array.copy_from_slice(&pubk[..ed25519::VerifyingKey::BYTE_SIZE]);

        // cache it...
        self.public_key_value = Some(array);
        debug!("Public key: value cached {}", self.key_name,);

        Ok(array)
    }

    // vault write transit/sign/cosmoshub-sign-key plaintext=$(base64 <<< "some-data")
    // "https://127.0.0.1:8200/v1/transit/sign/cosmoshub-sign-key"
    /// Sign message
    pub fn sign(&self, message: &[u8]) -> Result<[u8; ed25519::Signature::BYTE_SIZE], Error> {
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
                "{}/v1/transit/sign/{}",
                self.api_endpoint, self.key_name
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

    /// fetch RSA wraping key from Vault/Transit. Returned key will be a 4096-bit RSA public key.
    pub fn wrapping_key_pem(&self) -> Result<String, Error> {
        debug!("getting wraping key...");
        #[derive(Debug, Deserialize)]
        struct PublicKeyResponse {
            public_key: String,
        }

        let data = if let Some(data) = self
            .agent
            .get(&format!("{}/v1/transit/wrapping_key", self.api_endpoint))
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
                "{}/v1/transit/keys/{}/import",
                self.api_endpoint, key_name
            ))
            .set(VAULT_TOKEN, &self.token)
            .send_json(body)?;

        Ok(())
    }
}

#[cfg(feature = "hashicorp")]
#[cfg(test)]
mod tests {
    use super::*;
    use base64;
    use mockito::{mock, server_address};

    const TEST_TOKEN: &str = "test-token";
    const TEST_KEY_NAME: &str = "test-key-name";
    const TEST_PUB_KEY_VALUE: &str = "ng+ab41LawVupIXX3ocMn+AfV2W1DEMCfjAdtrwXND8="; // base64
    const TEST_PAYLOAD_TO_SIGN_BASE64: &str = "cXFxcXFxcXFxcXFxcXFxcXFxcXE="; // $(base64 <<< "qqqqqqqqqqqqqqqqqqqq") => "cXFxcXFxcXFxcXFxcXFxcXFxcXEK", 'K' vs "=" ????
    const TEST_PAYLOAD_TO_SIGN: &[u8] = b"qqqqqqqqqqqqqqqqqqqq";

    const TEST_SIGNATURE:&str = /*vault:v1:*/ "pNcc/FAUu+Ta7itVegaMUMGqXYkzE777y3kOe8AtdRTgLbA8eFnrKbbX/m7zoiC+vArsIUJ1aMCEDRjDK3ZsBg==";

    #[test]
    fn hashicorp_connect_ok() {
        // setup
        let lookup_self = mock("GET", "/v1/auth/token/lookup-self")
            .match_header(VAULT_TOKEN, TEST_TOKEN)
            .with_body(TOKEN_DATA)
            .create();

        // test
        let app = TendermintValidatorApp::connect(
            &format!("http://{}", server_address()),
            TEST_TOKEN,
            TEST_KEY_NAME,
            None,
            None,
        );

        assert!(app.is_ok());
        lookup_self.assert();
    }

    #[test]
    fn hashicorp_public_key_ok() {
        // setup
        let lookup_self = mock("GET", "/v1/auth/token/lookup-self")
            .match_header("X-Vault-Token", TEST_TOKEN)
            .with_body(TOKEN_DATA)
            .create();

        // app
        let mut app = TendermintValidatorApp::connect(
            &format!("http://{}", server_address()),
            TEST_TOKEN,
            TEST_KEY_NAME,
            None,
            None,
        )
        .expect("Failed to connect");

        // Vault call
        let read_key = mock(
            "GET",
            format!("/v1/transit/keys/{}", TEST_KEY_NAME).as_str(),
        )
        .match_header("X-Vault-Token", TEST_TOKEN)
        .with_body(READ_KEY_RESP)
        .expect_at_most(1) // one call only
        .create();

        // server call
        let res = app.public_key();
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            base64::decode(TEST_PUB_KEY_VALUE).unwrap().as_slice()
        );

        // cached value
        let res = app.public_key();
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            base64::decode(TEST_PUB_KEY_VALUE).unwrap().as_slice()
        );

        read_key.assert();
        lookup_self.assert();
    }

    #[test]
    fn hashicorp_sign_ok() {
        // setup
        let lookup_self = mock("GET", "/v1/auth/token/lookup-self")
            .match_header("X-Vault-Token", TEST_TOKEN)
            .with_body(TOKEN_DATA)
            .create();

        // app
        let app = TendermintValidatorApp::connect(
            &format!("http://{}", server_address()),
            TEST_TOKEN,
            TEST_KEY_NAME,
            None,
            None,
        )
        .expect("Failed to connect");

        let body = serde_json::to_string(&SignRequest {
            input: TEST_PAYLOAD_TO_SIGN_BASE64.into(),
        })
        .unwrap();

        let sign_mock = mock(
            "POST",
            format!("/v1/transit/sign/{}", TEST_KEY_NAME).as_str(),
        )
        .match_header("X-Vault-Token", TEST_TOKEN)
        .match_body(body.as_str())
        .with_body(SIGN_RESPONSE)
        .create();

        // server call
        let res = app.sign(TEST_PAYLOAD_TO_SIGN);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap(),
            base64::decode(TEST_SIGNATURE).unwrap().as_slice()
        );

        lookup_self.assert();
        sign_mock.assert();
    }

    #[test]
    fn hashicorp_sign_empty_payload_should_fail() {
        // setup
        let lookup_self = mock("GET", "/v1/auth/token/lookup-self")
            .match_header("X-Vault-Token", TEST_TOKEN)
            .with_body(TOKEN_DATA)
            .create();

        // app
        let app = TendermintValidatorApp::connect(
            &format!("http://{}", server_address()),
            TEST_TOKEN,
            TEST_KEY_NAME,
            None,
            None,
        )
        .expect("Failed to connect");

        let body = serde_json::to_string(&SignRequest {
            input: TEST_PAYLOAD_TO_SIGN_BASE64.into(),
        })
        .unwrap();

        let sign_mock = mock(
            "POST",
            format!("/v1/transit/sign/{}", TEST_KEY_NAME).as_str(),
        )
        .match_header("X-Vault-Token", TEST_TOKEN)
        .match_body(body.as_str())
        .with_body(SIGN_RESPONSE)
        .create();

        // server call
        let res = app.sign(&[]);
        assert!(res.is_err());

        lookup_self.assert();
        sign_mock.expect(0);
    }

    // curl --header "X-Vault-Token: hvs.<...valid.token...>>" http://127.0.0.1:8200/v1/auth/token/lookup-self
    const TOKEN_DATA: &str = r#"
    {"request_id":"119fcc9e-85e2-1fcf-c2a2-96cfb20f7446","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"k1g6PqNWVIlKK9NDCWLiTvrG","creation_time":1661247016,"creation_ttl":2764800,"display_name":"token","entity_id":"","expire_time":"2022-09-24T09:30:16.898359776Z","explicit_max_ttl":0,"id":"hvs.CAESIEzWRWLvyYLGlYsCRI_Vt653K26b-cx_lrxBlFo3_2GBGh4KHGh2cy5GVzZ5b25nMVFpSkwzM1B1eHM2Y0ZqbXA","issue_time":"2022-08-23T09:30:16.898363509Z","meta":null,"num_uses":0,"orphan":false,"path":"auth/token/create","policies":["tmkms-transit-sign-policy"],"renewable":false,"ttl":2758823,"type":"service"},"wrap_info":null,"warnings":null,"auth":null}
    "#;

    // curl --header "X-Vault-Token: $VAULT_TOKEN" "${VAULT_ADDR}/v1/transit/keys/<signing_key_name>"
    const READ_KEY_RESP: &str = r#"
    {"request_id":"9cb10d0a-1877-6da5-284b-8ece4b131ae3","lease_id":"","renewable":false,"lease_duration":0,"data":{"allow_plaintext_backup":false,"auto_rotate_period":0,"deletion_allowed":false,"derived":false,"exportable":false,"imported_key":false,"keys":{"1":{"creation_time":"2022-08-23T09:30:16.676998915Z","name":"ed25519","public_key":"ng+ab41LawVupIXX3ocMn+AfV2W1DEMCfjAdtrwXND8="}},"latest_version":1,"min_available_version":0,"min_decryption_version":1,"min_encryption_version":0,"name":"cosmoshub-sign-key","supports_decryption":false,"supports_derivation":true,"supports_encryption":false,"supports_signing":true,"type":"ed25519"},"wrap_info":null,"warnings":null,"auth":null}
    "#;

    // curl --request POST --header "X-Vault-Token: $VAULT_TOKEN" "${VAULT_ADDR}/v1/transit/sign/<..key_name...>" -d '{"input":"base64 encoded"}'
    const SIGN_RESPONSE: &str = r#"
    {"request_id":"13534911-8e98-9a0f-a701-e9a7736140e2","lease_id":"","renewable":false,"lease_duration":0,"data":{"key_version":1,"signature":"vault:v1:pNcc/FAUu+Ta7itVegaMUMGqXYkzE777y3kOe8AtdRTgLbA8eFnrKbbX/m7zoiC+vArsIUJ1aMCEDRjDK3ZsBg=="},"wrap_info":null,"warnings":null,"auth":null}
    "#;
}
