use super::error::Error;
use crate::config::provider::hashicorp::AdapterConfig;
use crate::keyring::ed25519;
use crate::keyring::providers::hashicorp::vault_client::{CreateKeyType, VaultClient};
use abscissa_core::prelude::*;

pub(crate) struct TendermintValidatorApp {
    vault_client: VaultClient,
    key_name: String,

    enable_pk_cache: Option<bool>,
    pk_cache: Option<[u8; ed25519::VerifyingKey::BYTE_SIZE]>,
}

// TODO(tarcieri): check this is actually sound?! :-)
#[allow(unsafe_code)]
unsafe impl Send for TendermintValidatorApp {}

impl TendermintValidatorApp {
    pub fn connect(
        token: &str,
        key_name: &str,
        adapter_config: &AdapterConfig,
    ) -> Result<Self, Error> {
        let vault_client = VaultClient::new(
            &adapter_config.vault_addr,
            token,
            adapter_config.endpoints.to_owned(),
            adapter_config.vault_cacert.to_owned(),
            adapter_config.vault_skip_verify.to_owned(),
            adapter_config.exit_on_error.to_owned(),
        );

        let app = TendermintValidatorApp {
            vault_client,
            key_name: key_name.to_owned(),
            enable_pk_cache: adapter_config.cache_pk,
            pk_cache: None,
        };

        debug!(
            "Initialized with Vault host at {}",
            adapter_config.vault_addr
        );
        app.handshake()?;

        Ok(app)
    }

    fn handshake(&self) -> Result<(), Error> {
        let _ = self.vault_client.handshake();
        Ok(())
    }

    pub fn public_key(&mut self) -> Result<[u8; ed25519::VerifyingKey::BYTE_SIZE], Error> {
        // if cache is enabled and we have a cached pk, return it
        if self.enable_pk_cache.is_some() && self.enable_pk_cache.unwrap() {
            if let Some(v) = self.pk_cache {
                debug!("using cached public key {}...", self.key_name);
                return Ok(v);
            }
        }

        let pk = self.vault_client.public_key(&self.key_name).unwrap();

        // if cache is enabled, store the pk
        if self.enable_pk_cache.is_some() && self.enable_pk_cache.unwrap() {
            self.pk_cache = Some(pk);
            debug!("Public key: value cached {}", self.key_name,);
        }

        Ok(pk)
    }

    pub fn sign(&self, message: &[u8]) -> Result<[u8; ed25519::Signature::BYTE_SIZE], Error> {
        self.vault_client.sign(&self.key_name, message)
    }

    /// fetch RSA wraping key from Vault/Transit. Returned key will be a 4096-bit RSA public key.
    pub fn wrapping_key_pem(&self) -> Result<String, Error> {
        self.vault_client.wrapping_key_pem()
    }

    pub fn import_key(
        &self,
        key_name: &str,
        key_type: CreateKeyType,
        ciphertext: &str,
        exportable: bool,
    ) -> Result<(), Error> {
        let _ = self
            .vault_client
            .import_key(key_name, key_type, ciphertext, exportable);

        Ok(())
    }
}

#[cfg(feature = "hashicorp")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyring::providers::hashicorp::vault_client::{SignRequest, VAULT_TOKEN};
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
            TEST_TOKEN,
            TEST_KEY_NAME,
            &AdapterConfig {
                vault_addr: format!("http://{}", server_address()),
                endpoints: None,
                vault_cacert: None,
                vault_skip_verify: None,
                exit_on_error: None,
                cache_pk: Some(false),
            },
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
            TEST_TOKEN,
            TEST_KEY_NAME,
            &AdapterConfig {
                vault_addr: format!("http://{}", server_address()),
                endpoints: None,
                vault_cacert: None,
                vault_skip_verify: None,
                exit_on_error: None,
                cache_pk: Some(true),
            },
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
            TEST_TOKEN,
            TEST_KEY_NAME,
            &AdapterConfig {
                vault_addr: format!("http://{}", server_address()),
                endpoints: Default::default(),
                vault_cacert: None,
                vault_skip_verify: None,
                exit_on_error: None,
                cache_pk: Some(false),
            },
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
    #[should_panic(expected = "PoisonError prohibited Vault HTTP response code: 403, URL: http://127.0.0.1:1234/v1/transit/sign/test-key-name, exiting...")]
    fn hashicorp_exit_on_error() {
        // setup
        let lookup_self = mock("GET", "/v1/auth/token/lookup-self")
            .match_header("X-Vault-Token", TEST_TOKEN)
            .with_body(TOKEN_DATA)
            .create();

        // app
        let app = TendermintValidatorApp::connect(
            TEST_TOKEN,
            TEST_KEY_NAME,
            &AdapterConfig {
                vault_addr: format!("http://{}", server_address()),
                endpoints: Default::default(),
                vault_cacert: None,
                vault_skip_verify: None,
                exit_on_error: Some(vec![403]),
                cache_pk: Some(false),
            },
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
        .with_status(403)
        .create();

        // server call
        let _ = app.sign(TEST_PAYLOAD_TO_SIGN);

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
            TEST_TOKEN,
            TEST_KEY_NAME,
            &AdapterConfig {
                vault_addr: format!("http://{}", server_address()),
                endpoints: Default::default(),
                vault_cacert: None,
                vault_skip_verify: None,
                exit_on_error: None,
                cache_pk: Some(false),
            },
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
