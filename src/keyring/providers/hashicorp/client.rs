use abscissa_core::prelude::*;
use std::collections::HashMap;

use super::error::Error;
use hashicorp_vault::{
    client::TokenData,
    client::{EndpointResponse, HttpVerb},
    Client,
};
use serde::{Deserialize, Serialize};

const VAULT_BACKEND_NAME: &str = "transit";
const USER_MESSAGE_CHUNK_SIZE: usize = 250;
//TODO - confirm size
const PUBLIC_KEY_SIZE: usize = 32;

pub(super) struct TendermintValidatorApp {
    client: Client<TokenData>,
    key_name: String,
    public_key_value: Option<[u8; PUBLIC_KEY_SIZE]>,
}

// TODO(tarcieri): check this is actually sound?!
#[allow(unsafe_code)]
unsafe impl Send for TendermintValidatorApp {}

///
#[derive(Debug, Deserialize)]
struct PublicKeyResponse {
    //r#type: String, //ed25519
    keys: HashMap<usize, HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
struct SignRequest {
    input: String, //Base64 encoded
}

#[derive(Debug, Deserialize)]
struct SignResponse {
    signature: String, //Base64 encoded
}

impl TendermintValidatorApp {
    pub fn connect(host: &str, token: &str, key_name: &str) -> Result<Self, Error> {
        //token self lookup
        let mut client = Client::new(host, token)?;
        client.secret_backend(VAULT_BACKEND_NAME);

        let app = TendermintValidatorApp {
            client,
            key_name: key_name.to_owned(),
            public_key_value: None,
        };

        info!("Initialized with Vault host at {}", host);
        Ok(app)
    }

    //vault read transit/keys/cosmoshub-sign-key
    //GET http://0.0.0.0:8200/v1/transit/keys/cosmoshub-sign-key
    //TODO: is it possible for keys to change? should we cashe it?
    /// Get public key
    pub fn public_key(&mut self) -> Result<[u8; PUBLIC_KEY_SIZE], Error> {
        if let Some(v) = self.public_key_value {
            return Ok(v.clone());
        }

        let data = self.client.call_endpoint::<PublicKeyResponse>(
            HttpVerb::GET,
            &format!("transit/keys/{}", self.key_name),
            None,
            None,
        )?;

        //{ keys: {1: {"name": "ed25519", "public_key": "R5n8OFaknb/3sCTx/aegNzYukwVx0uNtzzK/2RclIOE=", "creation_time": "2022-08-18T12:44:02.136328217Z"}} }
        let data = if let EndpointResponse::VaultResponse(data) = data {
            if let Some(data) = data.data {
                data
            } else {
                return Err(Error::InvalidPubKey("Unavailable".into()));
            }
        } else {
            return Err(Error::InvalidPubKey("Unable to retrieve".into()));
        };

        //is it #1 version? TODO - get the last version
        let pubk = if let Some(map) = data.keys.get(&1) {
            if let Some(pubk) = map.get("public_key") {
                pubk
            } else {
                return Err(Error::InvalidPubKey(
                    "Unable to retrieve - \"public_key\" key is not found!".into(),
                ));
            }
        } else {
            return Err(Error::InvalidPubKey(
                "Unable to retrieve - version 1 is not found!".into(),
            ));
        };

        let pubk = base64::decode(pubk)?;

        let mut array = [0u8; PUBLIC_KEY_SIZE];
        array.copy_from_slice(&pubk[..PUBLIC_KEY_SIZE]);

        //cache it...
        self.public_key_value = Some(array.clone());

        Ok(array)
    }

    //vault write transit/sign/cosmoshub-sign-key plaintext=$(base64 <<< "some-data")
    //"https://127.0.0.1:8200/v1/transit/sign/cosmoshub-sign-key"
    /// Sign message
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        let body = SignRequest {
            input: base64::encode(message),
        };

        let data = self.client.call_endpoint::<SignResponse>(
            HttpVerb::POST,
            &format!("transit/sign/{}", self.key_name),
            None,
            Some(&serde_json::to_string(&body)?),
        )?;

        let data = if let EndpointResponse::VaultResponse(data) = data {
            if let Some(data) = data.data {
                data
            } else {
                return Err(Error::InvalidPubKey("Unavailable".into()));
            }
        } else {
            return Err(Error::InvalidPubKey("Unable to retrieve".into()));
        };

        //TODO: check prefix to be "vault:v", maybe regex?
        let parts = data.signature.split(":").collect::<Vec<&str>>();
        //TODO: check length == 3

        //signature: "vault:v1:/bcnnk4p8Uvidrs1/IX9s66UCOmmfdJudcV1/yek9a2deMiNGsVRSjirz6u+ti2wqUZfG6UukaoSHIDSSRV5Cw=="
        let base64_signature = if let Some(sign) = parts.last() {
            sign.to_owned()
        } else {
            return Err(Error::InvalidPubKey("Unable to retrieve".into()));
        };

        let signature = base64::decode(base64_signature)?;
        if signature.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let mut array = [0u8; 64];
        array.copy_from_slice(&signature[..64]);
        Ok(array)
    }
}
