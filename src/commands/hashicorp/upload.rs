//! Test the Hashicorp is working by performing signatures successively

use crate::prelude::*;
use abscissa_core::{Command, Runnable};
use aes_kw;
use clap::Parser;
use serde::Serialize;
use std::{path::PathBuf, process, time::Instant};

use crate::keyring::providers::hashicorp::client;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rsa::{pkcs8::DecodePublicKey, PaddingScheme, PublicKey, RsaPublicKey};

const KEY_SIZE_AES256: usize = 32; //256 bits

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
        let started_at = Instant::now();

        //https://www.vaultproject.io/docs/secrets/transit#bring-your-own-key-byok
        //https://learn.hashicorp.com/tutorials/vault/eaas-transit

        //root token or token with enough admin rights
        let vault_token = std::env::var("VAULT_TOKEN")
            .expect("root token \"VAULT_TOKEN\" is not set (confg token is NOT used)!");

        //println!("payload:{}", &self.payload);
        let input_key = base64::decode(&self.payload)
            .expect("input key error: imported key must be base64 encoded!");

        debug!(
            "input key length:{}, expected:{}",
            input_key.len(),
            ed25519_dalek::SECRET_KEY_LENGTH
        );

        // // // ed25519_dalek::SecretKey::
        // let expanded_secret_key: ed25519_dalek::ExpandedSecretKey =
        //     ed25519_dalek::ExpandedSecretKey::from_bytes(input_key.as_slice()).unwrap();

        let secret_key = ed25519_dalek::SecretKey::generate(&mut rand_v7::rngs::OsRng {});
        //write_to_file("ed25519.bin", &secret_key.to_bytes());
        //let secret_key = ed25519_dalek::ExpandedSecretKey::from(&secret_key);

        debug!(
            "=============>>>>>> input key length:{}, expected:{}",
            secret_key.to_bytes().len(),
            ed25519_dalek::SECRET_KEY_LENGTH
        );

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

        let ephemeral_key_name = random_name(12, "ephemeral");

        info!(
            "about to create ephemeral key:{} type:{}...",
            ephemeral_key_name,
            client::CreateKeyType::Aes256Gcm96
        );
        // //create ephemeral key
        // let _ = app
        //     .create_key(
        //         client::CreateKeyType::Aes256Gcm96,
        //         true,
        //         0,
        //         &ephemeral_key_name,
        //     )
        //     .expect("aes key error: create error!");

        // //get ephemeral key with delayed error eval
        // info!("Created! fetching...");
        // let aes_key = app.export_key(client::ExportKeyType::EncryptionKey, &ephemeral_key_name);

        // //delete ephemeral key - to delete a key, policy has to account for that...
        // info!(
        //     "Cleaning up... About to delete ephemeral key:{} [policy has to allow deleting keys]...",
        //     ephemeral_key_name
        // );
        // if let Err(e) = app.delete_key(&ephemeral_key_name) {
        //     //not critical, unique name and admin can delete afterwards
        //     warn!("aes key error: delete error! Error:{}", e);
        // }

        // info!("Evaluating ephemeral key fetch result...");
        // let aes_key = match aes_key {
        //     Ok(aes_key) => aes_key,
        //     Err(e) => {
        //         status_err!("aes key error: {}", e);
        //         process::exit(1);
        //     }
        // };

        // debug!("ephemeral aes_key (base64):{}", aes_key);

        // let aes_key =
        //     base64::decode(aes_key).expect("aes key error: imported key must be base64 encoded!");

        use aes_gcm::{
            aead::{Aead, KeyInit, OsRng},
            Aes256Gcm,
        };

        let aes_key = Aes256Gcm::generate_key(&mut OsRng);

        info!(
            "Success! Will use ephemeral key to wrap target key(\"{}\") for upload!",
            self.pk_name
        );

        assert_eq!(
            KEY_SIZE_AES256,
            aes_key.len(),
            "expected aes key length 32, actual:{}",
            aes_key.len()
        );

        // let aes_key: [u8; KEY_SIZE_AES256] = aes_key
        //     .try_into()
        //     .expect("aes wrapping key: byte array conversion error");

        let kek = aes_kw::KekAes256::from(aes_key);
        let wrapped_input_key = kek
            .wrap_vec(&secret_key.to_bytes())
            .expect("input key wrapping error!");

        // let wrapped_input_key =
        //     aes_keywrap_rs::aes_wrap_key(&aes_key, &secret_key.to_bytes()).unwrap();

        // let kek = aes_keywrap::Aes256KeyWrap::new(&aes_key);
        // let wrapped_input_key = kek.encapsulate(&secret_key.to_bytes()).unwrap();

        let wrapping_key_pem = app
            .wrapping_key_pem()
            .expect("wrapping key error: fetching error!");

        let pub_key = RsaPublicKey::from_public_key_pem(&wrapping_key_pem).unwrap();
        let mut rng = thread_rng();
        //crypto/rsa: decryption error
        let padding = PaddingScheme::new_oaep::<sha2::Sha256>();
        let mut wrapped_aes = pub_key.encrypt(&mut rng, padding, &aes_key).unwrap();
        println!("aes key:{:?}", aes_key);
        assert_eq!(
            512,
            wrapped_aes.len(),
            "expected wrapped_aes key length 512, actual:{}",
            wrapped_aes.len()
        );

        wrapped_aes.extend(wrapped_input_key);

        let ciphertext = base64::encode(&wrapped_aes.as_slice());
        //println!("{}", ciphertext);

        app.import_key(&config.pk_name, client::CreateKeyType::Ed25519, &ciphertext)
            .expect("import key error!");

        /*
        ciphertext (string: <required>) - A base64-encoded string that contains two values:
        an ephemeral 256-bit AES key wrapped using the wrapping key returned by Vault
        and
        the encryption of the import key material under the provided AES key.

        The wrapped AES key should be the first 512 bytes of the ciphertext, and the encrypted key material should be the remaining bytes.
        */

        /*
        Wrap the target key using the ephemeral AES key with AES-KWP.
        //curl  --header "X-Vault-Token: ..." --request GET http://127.0.0.1:8200/v1/transit/wrapping_key

        //Wrap the AES key under the Vault wrapping key using RSAES-OAEP with MGF1 and either SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512.

        //Append the wrapped target key to the wrapped AES key.

        //Base64 encode the result.
        */

        println!(
            "Elapsed:{} ms. Result: {}",
            started_at.elapsed().as_millis(),
            "key_base64"
        );
    }
}

///generate random string. Used for ephemeral key name generator
fn random_name(n: usize, pref: &str) -> String {
    format!(
        "{}-{}",
        pref,
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(n)
            .map(char::from)
            .collect::<String>()
    )
}

use std::io::Write;
fn write_to_file(file_name: &str, data: &[u8]) {
    // Write the modified data.
    let mut f = std::fs::File::create(format!("./{}", file_name)).unwrap();
    f.write_all(data).unwrap();
}
