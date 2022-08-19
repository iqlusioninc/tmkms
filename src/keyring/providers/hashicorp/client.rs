use abscissa_core::prelude::*;
use std::collections::{BTreeMap, HashMap};

use super::error::Error;
use hashicorp_vault::{
    client::TokenData,
    client::{EndpointResponse, HttpVerb},
    Client,
};
use serde::{Deserialize, Serialize};

const VAULT_BACKEND_NAME: &str = "transit";
const PUBLIC_KEY_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;

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
    keys: BTreeMap<usize, HashMap<String, String>>,
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

        debug!("Initialized with Vault host at {}", host);
        Ok(app)
    }

    //vault read transit/keys/cosmoshub-sign-key
    //GET http://0.0.0.0:8200/v1/transit/keys/cosmoshub-sign-key
    //TODO: is it possible for keys to change? should we cashe it?
    /// Get public key
    pub fn public_key(&mut self) -> Result<[u8; PUBLIC_KEY_SIZE], Error> {
        if let Some(v) = self.public_key_value {
            debug!("using cached public key {}...", self.key_name);
            return Ok(v.clone());
        }
        debug!("fetching public key for {}...", self.key_name);

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
                return Err(Error::InvalidPubKey(
                    "Public key: response \"data\" unavailable".into(),
                ));
            }
        } else {
            return Err(Error::InvalidPubKey(
                "Public key: Vault response unavailable".into(),
            ));
        };

        //is it #1 version? TODO - get the last version
        let pubk = if let Some(map) = data.keys.get(&1) {
            if let Some(pubk) = map.get("public_key") {
                pubk
            } else {
                return Err(Error::InvalidPubKey(
                    "Public key: unable to retrieve - \"public_key\" key is not found!".into(),
                ));
            }
        } else {
            return Err(Error::InvalidPubKey(
                "Public key: unable to retrieve - version 1 is not found!".into(),
            ));
        };

        debug!("Public key: fetched {}={}...", self.key_name, pubk);

        let pubk = base64::decode(pubk)?;

        debug!(
            "Public key: base64 decoded {}, size:{}",
            self.key_name,
            pubk.len()
        );

        let mut array = [0u8; PUBLIC_KEY_SIZE];
        array.copy_from_slice(&pubk[..PUBLIC_KEY_SIZE]);

        //cache it...
        self.public_key_value = Some(array.clone());
        debug!("Public key: value cached {}", self.key_name,);

        Ok(array)
    }

    //vault write transit/sign/cosmoshub-sign-key plaintext=$(base64 <<< "some-data")
    //"https://127.0.0.1:8200/v1/transit/sign/cosmoshub-sign-key"
    /// Sign message
    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIGNATURE_SIZE], Error> {
        debug!("signing request: received");
        //TODO: check for empty message...

        let body = SignRequest {
            input: base64::encode(message),
        };

        debug!("signing request: base64 encoded and about to submit for signing...");

        let data = self.client.call_endpoint::<SignResponse>(
            HttpVerb::POST,
            &format!("transit/sign/{}", self.key_name),
            None,
            Some(&serde_json::to_string(&body)?),
        )?;

        debug!("signing request: about to submit for signing...");

        let data = if let EndpointResponse::VaultResponse(data) = data {
            if let Some(data) = data.data {
                data
            } else {
                return Err(Error::InvalidPubKey("signing request: Unavailable".into()));
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

        let mut array = [0u8; SIGNATURE_SIZE];
        array.copy_from_slice(&signature[..SIGNATURE_SIZE]);
        Ok(array)
    }
}
