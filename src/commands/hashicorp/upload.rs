//! Test the Hashicorp is working by performing signatures successively

use crate::prelude::*;
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

    /// public key (true) or private key (false, default)
    #[clap(short = 'p', long = "public_key")]
    pub public_key: bool,

    /// base64 encoded key to upload
    #[clap(long = "payload")]
    pub payload: String,
}
#[derive(Debug, Serialize)]
struct ImportRequest {
    #[serde(default = "ed25519")]
    r#type: String,

    ciphertext: String,
}

impl Runnable for UploadCommand {
    /// Perform a signing test using the current HSM configuration
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
        .expect(&format!(
            "Unable to connect to Vault at {}",
            config.api_endpoint
        ));

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

        let kek = aes_kw::KekAes256::from(aes_key.clone());
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
                &mut rand::thread_rng(),
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

    //let pair = ed25519_dalek::Keypair::from_bytes(&bytes)?;
    let pair = ed25519_dalek::Keypair::generate(&mut rand_v7::rngs::OsRng {});

    let mut secret_key: Vec<u8> = pair.secret.to_bytes().into_iter().collect::<Vec<u8>>();

    if secret_key.len() == ed25519_dalek::SECRET_KEY_LENGTH {
        let mut pkcs8_key = Vec::from(*PKCS8_HEADER);
        pkcs8_key.extend_from_slice(&secret_key);
        secret_key = pkcs8_key;
    }

    debug_assert!(secret_key.len() == ed25519_dalek::SECRET_KEY_LENGTH + PKCS8_HEADER.len());

    Ok(secret_key)
}
