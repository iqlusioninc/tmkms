//! Test the Hashicorp is working by performing signatures successively

use crate::{config::provider::hashicorp::HashiCorpConfig, prelude::*};
use abscissa_core::{Command, Runnable};
use aes_kw;
use clap::Parser;
use serde::Serialize;
use std::{path::PathBuf, process};

use crate::keyring::providers::hashicorp::{client, error};
use rsa::{pkcs8::DecodePublicKey, PaddingScheme, PublicKey, RsaPublicKey};

///AES256 key length
const KEY_SIZE_AES256: usize = 32; //256 bits
///PKCS8 header
const PKCS8_HEADER: &[u8; 16] = b"\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20";

/// The `hashicorp test` subcommand
#[derive(Command, Debug, Default, Parser)]
pub struct UploadCommand {
    /// path to tmkms.toml
    #[clap(
        short = 'c',
        long = "config",
        value_name = "CONFIG",
        help = "/path/to/tmkms.toml"
    )]
    pub config: Option<PathBuf>,

    /// enable verbose debug logging
    #[clap(short = 'v', long = "verbose")]
    pub verbose: bool,

    ///key ID in Hashicorp Vault
    #[clap(help = "Key ID")]
    pk_name: String,

    /// base64 encoded key to upload
    #[clap(long = "payload")]
    pub payload: String,
}
///Import Secret Key Request
#[derive(Debug, Serialize)]
struct ImportRequest {
    #[serde(default = "ed25519")]
    r#type: String,

    ciphertext: String,
}

impl Runnable for UploadCommand {
    /// Perform a import using the current TMKMS configuration
    fn run(&self) {
        if self.pk_name.is_empty() {
            status_err!("pk_name cannot be empty!");
            process::exit(1);
        }

        let config = APP.config();

        //finding key in config will point to correct Vault's URL
        let config = if let Some(c) = config
            .providers
            .hashicorp
            .iter()
            .find(|c| c.pk_name == self.pk_name)
        {
            c
        } else {
            let cfg_path = if let Some(path) = self.config.as_ref() {
                path.clone()
            } else {
                PathBuf::from("./tmkms.toml")
            };
            status_err!(
                "pk_name is not configured in provided \"{}\"!",
                cfg_path.as_path().to_str().unwrap()
            );
            process::exit(1);
        };

        self.upload(config);
    }
}

impl UploadCommand {
    fn upload(&self, config: &HashiCorpConfig) {
        //https://www.vaultproject.io/docs/secrets/transit#bring-your-own-key-byok
        //https://learn.hashicorp.com/tutorials/vault/eaas-transit

        //root token or token with enough admin rights
        let vault_token = std::env::var("VAULT_TOKEN")
            .expect("root token \"VAULT_TOKEN\" is not set (confg token is NOT used)!");

        let ed25519_input_key = input_key(&self.payload)
            .expect("secret: error converting \"key-to-upload\"[ed25519] with PKCS8 wrapping");

        //create app instance
        let app = client::TendermintValidatorApp::connect(
            &config.api_endpoint,
            &vault_token,
            &self.pk_name,
        )
        .unwrap_or_else(|_| panic!("Unable to connect to Vault at {}", config.api_endpoint));

        use aes_gcm::KeyInit;
        let v_aes_key = aes_gcm::Aes256Gcm::generate_key(&mut aes_gcm::aead::OsRng);
        debug_assert_eq!(
            KEY_SIZE_AES256,
            v_aes_key.len(),
            "expected aes key length {}, actual:{}",
            KEY_SIZE_AES256,
            v_aes_key.len()
        );

        let mut aes_key = [0u8; KEY_SIZE_AES256];
        aes_key.copy_from_slice(&v_aes_key[..KEY_SIZE_AES256]);

        let kek = aes_kw::KekAes256::from(aes_key);
        let wrapped_input_key = kek
            .wrap_with_padding_vec(&ed25519_input_key)
            .expect("input key wrapping error!");

        let wrapping_key_pem = app
            .wrapping_key_pem()
            .expect("wrapping key error: fetching error!");

        let pub_key = RsaPublicKey::from_public_key_pem(&wrapping_key_pem).unwrap();

        //wrap AES256 into RSA4096
        let wrapped_aes = pub_key
            .encrypt(
                &mut rand_core::OsRng,
                PaddingScheme::new_oaep::<sha2::Sha256>(),
                &aes_key,
            )
            .expect("failed to encrypt");

        debug_assert_eq!(wrapped_aes.len(), 512);
        let wrapped_aes: Vec<u8> = [wrapped_aes.as_slice(), wrapped_input_key.as_slice()].concat();

        app.import_key(
            &self.pk_name,
            client::CreateKeyType::Ed25519,
            &base64::encode(wrapped_aes),
        )
        .expect("import key error!");
    }
}

//https://docs.rs/ed25519/latest/ed25519/pkcs8/index.html
fn input_key(input_key: &str) -> Result<Vec<u8>, error::Error> {
    let bytes = base64::decode(input_key)?;

    let secret_key = if bytes.len() == 64 {
        ed25519_dalek::Keypair::from_bytes(&bytes)?.secret
    } else {
        ed25519_dalek::SecretKey::from_bytes(&bytes)?
    };

    let mut secret_key: Vec<u8> = secret_key.to_bytes().into_iter().collect::<Vec<u8>>();

    //HashiCorp Vault Transit engine expects PKCS8
    if secret_key.len() == ed25519_dalek::SECRET_KEY_LENGTH {
        let mut pkcs8_key = Vec::from(*PKCS8_HEADER);
        pkcs8_key.extend_from_slice(&secret_key);
        secret_key = pkcs8_key;
    }

    debug_assert!(secret_key.len() == ed25519_dalek::SECRET_KEY_LENGTH + PKCS8_HEADER.len());

    Ok(secret_key)
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use super::*;

    #[test]
    fn test_input_key_32bit_ok() {
        let bytes = ed25519_dalek::SecretKey::generate(&mut rand::thread_rng()).to_bytes();
        assert_eq!(bytes.len(), ed25519_dalek::SECRET_KEY_LENGTH);

        let secret = base64::encode(bytes);

        //under test
        let bytes = input_key(&secret).unwrap();

        assert_eq!(
            bytes.len(),
            ed25519_dalek::SECRET_KEY_LENGTH + PKCS8_HEADER.len()
        );
    }

    #[test]
    fn test_input_key_48bit_ok() {
        let mut secret = PKCS8_HEADER.into_iter().cloned().collect::<Vec<u8>>();

        let bytes = ed25519_dalek::SecretKey::generate(&mut rand::thread_rng()).to_bytes();
        assert_eq!(bytes.len(), ed25519_dalek::SECRET_KEY_LENGTH);

        secret.extend_from_slice(&bytes);

        let secret = base64::encode(bytes);
        //under test
        let bytes = input_key(&secret).unwrap();

        assert_eq!(
            bytes.len(),
            ed25519_dalek::SECRET_KEY_LENGTH + PKCS8_HEADER.len()
        );
    }
    #[test]
    fn test_input_key_64bit_ok() {
        let mut secret = PKCS8_HEADER.into_iter().cloned().collect::<Vec<u8>>();

        let bytes = ed25519_dalek::SecretKey::generate(&mut rand::thread_rng()).to_bytes();
        assert_eq!(bytes.len(), ed25519_dalek::SECRET_KEY_LENGTH);

        secret.extend_from_slice(&bytes);

        let secret = base64::encode(bytes);
        //under test
        let bytes = input_key(&secret).unwrap();

        assert_eq!(
            bytes.len(),
            ed25519_dalek::SECRET_KEY_LENGTH + PKCS8_HEADER.len()
        );
    }

    const PK_NAME: &str = "upload-test";
    const VAULT_TOKEN: &str = "access-token";
    const CHAIN_ID: &str = "mock-chain-id";
    const ED25519: &str =
        "4YZKJ/pfJj42tdcl40dXz/ugRgrBR0/Pp5C2kjHL6AZhBFozq5EspBwCb44zef0cLEO/WuLf3dI+BPCNOPwxRw==";

    use mockito::{mock, server_address};

    #[test]
    fn test_upload() {
        let cmd = UploadCommand {
            verbose: false,
            pk_name: PK_NAME.into(),
            config: None,
            payload: ED25519.into(),
        };

        let config = HashiCorpConfig {
            access_token: "crazy-long-string".into(),
            api_endpoint: format!("http://{}", server_address()),
            pk_name: PK_NAME.into(),
            chain_id: tendermint::chain::Id::try_from(CHAIN_ID).unwrap(),
        };

        std::env::set_var("VAULT_TOKEN", VAULT_TOKEN);

        //init
        let lookup_self = mock("GET", "/v1/auth/token/lookup-self")
            .match_header("X-Vault-Token", VAULT_TOKEN)
            .with_body(TOKEN_DATA)
            .create();

        //upload
        let wrapping_key = mock("GET", "/v1/transit/wrapping_key")
            .match_header("X-Vault-Token", VAULT_TOKEN)
            .with_body(WRAPPING_KEY_RESPONSE)
            .create();

        let end_point = format!("/v1/transit/keys/{}/import", PK_NAME);

        //upload
        let export = mock("POST", end_point.as_str())
            .match_header("X-Vault-Token", VAULT_TOKEN)
            //.match_body(req.as_str()) //sipher string will be always different
            .create();

        //test
        cmd.upload(&config);

        lookup_self.assert();
        export.assert();
        wrapping_key.expect(1).assert();
        // }
    }

    //curl --header "X-Vault-Token: hvs.<...valid.token...>>" http://127.0.0.1:8200/v1/auth/token/lookup-self
    const TOKEN_DATA: &str = r#"
    {"request_id":"119fcc9e-85e2-1fcf-c2a2-96cfb20f7446","lease_id":"","renewable":false,"lease_duration":0,"data":{"accessor":"k1g6PqNWVIlKK9NDCWLiTvrG","creation_time":1661247016,"creation_ttl":2764800,"display_name":"token","entity_id":"","expire_time":"2022-09-24T09:30:16.898359776Z","explicit_max_ttl":0,"id":"hvs.CAESIEzWRWLvyYLGlYsCRI_Vt653K26b-cx_lrxBlFo3_2GBGh4KHGh2cy5GVzZ5b25nMVFpSkwzM1B1eHM2Y0ZqbXA","issue_time":"2022-08-23T09:30:16.898363509Z","meta":null,"num_uses":0,"orphan":false,"path":"auth/token/create","policies":["tmkms-transit-sign-policy"],"renewable":false,"ttl":2758823,"type":"service"},"wrap_info":null,"warnings":null,"auth":null}
    "#;

    const WRAPPING_KEY_RESPONSE: &str = r#"{"request_id":"1d739895-ea6d-2e18-3457-edbbf8dcd129","lease_id":"","renewable":false,"lease_duration":0,"data":{"public_key":"-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1hXp53II1GokeS6UyOvF\nbQnNgstRJ4IINjiQXL0iO+US3p5Zc/wwads6R3sTw6nwf+cXzPEkzyXXBIMgdLTH\nx/7kOuzT+mRJbKQgFXdHyEfm9T6jEKOSJFaQQxYQcMgUiMXiaXSonDnShwQ3BOxT\nzPo9TR8Z6+xMYIFTV9/kHJT2JHAX4xf5+EuRae4XsHW2yaWZzY//qVu/z0hXEeh3\nk0yK0kAULXMlzyJDpCNuWsdtB4ZpFv0eJ5ic84ZmA3B5Y/LQ0VSHLYnJOtt7hMe2\nsEEFHS7sfTbFxtBpSTySikoCLtHOAUXC0u3FQBJRta+uT82Iufdz7Qzw2xmR1WP2\nSTdqVINYci3/cql1xzEdKmieMwEwGbMOjFA7N4hBPgT9Tjod8vqCizk+Z1AH6ijd\nhfhDXlDi2owsngijdKJEoWCIC1IsqOTkZsKspw3a/9gdAkzXC8qkevCtOccC3Nwu\nAiA1Nh+FtFdvTDtwp7/G7lFLJT2E2PdtX8nZsI0TMmQg9Wh4wFP4pJfOGsYtMdNf\nN6cNVgYsTfkKIpXpxJdRf7YNKy1bvVNIPDAREuJTT8J5aSnnE/gjDiTbUDVnLulE\nYu7BaQqzE86k20MakAg1OLMftJJo0UhPxezanG43ZRW/K8OgBKnoD6UFFPzMiJ89\nQAzzkMa+CgjZr6zkIRy5FqkCAwEAAQ==\n-----END PUBLIC KEY-----\n"},"wrap_info":null,"warnings":null,"auth":null}
    "#;
}
