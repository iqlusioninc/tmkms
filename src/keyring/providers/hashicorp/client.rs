use std::collections::HashMap;

use super::error::Error;
use hashicorp_vault::{
    client::TokenData,
    client::{EndpointResponse, HttpVerb::GET},
    Client,
};
use serde::Deserialize;

const VAULT_BACKEND_NAME: &str = "transit";
const USER_MESSAGE_CHUNK_SIZE: usize = 250;

pub(super) struct TendermintValidatorApp {
    client: Client<TokenData>,
    key_name: String,
}

// TODO(tarcieri): check this is actually sound?!
#[allow(unsafe_code)]
unsafe impl Send for TendermintValidatorApp {}

#[derive(Debug, Deserialize)]
struct GetSecretResponse {
    r#type: String,
    keys: HashMap<usize, HashMap<String, String>>,
}

impl TendermintValidatorApp {
    pub fn connect(host: &str, token: &str, key_name: &str) -> Result<Self, Error> {
        //token self lookup
        let mut client = Client::new(host, token)?;
        client.secret_backend(VAULT_BACKEND_NAME);

        let app = TendermintValidatorApp {
            client,
            key_name: key_name.to_owned(),
        };
        Ok(app)
    }

    //vault read transit/keys/cosmoshub-sign-key
    //GET http://0.0.0.0:8200/v1/transit/keys/cosmoshub-sign-key
    /// Get public key
    pub fn public_key(&self) -> Result<[u8; 32], Error> {
        let data = self.client.call_endpoint::<GetSecretResponse>(
            GET,
            &format!("transit/keys/{}", self.key_name),
            None,
            None,
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

        println!("public key: {} len: {}", pubk, pubk.len());
        let pubk = pubk.as_bytes();
        println!("public key len: {} {:#?}", pubk.len(), pubk);

        let array = [0u8; 32];
        Ok(array)
    }

    //     /// Sign message
    //     pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
    //         let chunks = message.chunks(USER_MESSAGE_CHUNK_SIZE);

    //         if chunks.len() > 255 {
    //             return Err(Error::InvalidMessageSize);
    //         }

    //         if chunks.len() == 0 {
    //             return Err(Error::InvalidEmptyMessage);
    //         }

    //         let packet_count = chunks.len() as u8;
    //         let mut response: ApduAnswer = ApduAnswer {
    //             data: vec![],
    //             retcode: 0,
    //         };

    //         // Send message chunks
    //         for (packet_idx, chunk) in chunks.enumerate() {
    //             let _command = ApduCommand {
    //                 cla: CLA,
    //                 ins: INS_SIGN_ED25519,
    //                 p1: (packet_idx + 1) as u8,
    //                 p2: packet_count,
    //                 length: chunk.len() as u8,
    //                 data: chunk.to_vec(),
    //             };

    //             response = self.app.exchange(_command)?;
    //         }

    //         if response.data.is_empty() && response.retcode == 0x9000 {
    //             return Err(Error::NoSignature);
    //         }

    //         // Last response should contain the answer
    //         if response.data.len() != 64 {
    //             return Err(Error::InvalidSignature);
    //         }

    //         let mut array = [0u8; 64];
    //         array.copy_from_slice(&response.data[..64]);
    //         Ok(array)
    //     }
}
