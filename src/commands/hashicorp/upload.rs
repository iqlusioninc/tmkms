//! Test the Hashicorp is working by performing signatures successively

use crate::prelude::*;
use abscissa_core::{Command, Runnable};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, process, time::Instant};

const EPHEMERAL_KEY_TYPE: &str = "aes256-gcm96";

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

    /// wrpping key name
    #[clap(short = 'w', long = "wrapping_key")]
    pub wrapping_key: String,

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
        println!("config:{:?}", self);

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

        let key_base64 = if let Ok(_) = base64::decode(&self.payload) {
            self.payload.clone()
        } else {
            base64::encode(&self.payload)
        };

        //https://www.vaultproject.io/docs/secrets/transit#bring-your-own-key-byok
        //https://learn.hashicorp.com/tutorials/vault/eaas-transit

        //root token or token with enough admin rights
        let vault_token = std::env::var("VAULT_TOKEN")
            .expect("root token \"ROOT_TOKEN\" is not set (confg token is NOT used)!");

        let app = crate::keyring::providers::hashicorp::client::TendermintValidatorApp::connect(
            &config.api_endpoint,
            &vault_token,
            &self.pk_name,
        )
        .expect(&format!(
            "Unable to connect to Vault at {}",
            config.api_endpoint
        ));

        //Wrap the target key using the ephemeral AES key with AES-KWP.
        //curl  --header "X-Vault-Token: ..." --request GET http://127.0.0.1:8200/v1/transit/wrapping_key

        //Wrap the AES key under the Vault wrapping key using RSAES-OAEP with MGF1 and either SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512.

        //Append the wrapped target key to the wrapped AES key.

        //Base64 encode the result.

        let started_at = Instant::now();
        println!(
            "Elapsed:{} ms. Result: {}",
            started_at.elapsed().as_millis(),
            key_base64
        );
    }
}
