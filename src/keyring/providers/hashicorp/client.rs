use std::collections::HashMap;

use super::error::Error;
use serde::Deserialize;
use ureq::{Agent, AgentBuilder};
use url::Url;

const VAULT_TOKEN_NAME: &str = "X-Vault-Token";

const VAULT_BACKEND_NAME: &str = "transit";
const USER_MESSAGE_CHUNK_SIZE: usize = 250;

#[derive(Clone)]
pub(super) struct TendermintValidatorApp {
    agent: Agent,
    host: Url,
    key_name: String,
    token: String,
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
        let agent = AgentBuilder::new().build();

        let app = TendermintValidatorApp {
            agent,
            host: Url::parse(host)?,
            key_name: key_name.to_owned(),
            token: token.to_owned(),
        };

        app.lookup_self()?;
        app.public_key()?;

        Ok(app)
    }

    //vault token lookup
    fn lookup_self(&self) -> Result<String, Error> {
        let response: String = self
            .agent
            //.get(Url::parse(format!("{}/auth/token/lookup-self", self.host))?)
            .get(self.host.join("v1/auth/token/lookup-self")?.as_str())
            .set(VAULT_TOKEN_NAME, &self.token)
            .set("Content-Type", "application/json")
            .call()?
            .into_string()?;

        Ok(response)
    }

    //vault read transit/keys/cosmoshub-sign-key
    //GET http://0.0.0.0:8200/v1/transit/keys/cosmoshub-sign-key
    /// Get public key
    pub fn public_key(&self) -> Result<[u8; 32], Error> {
        let data = self
            .agent
            .post(
                self.host
                    .join(&format!("v1/transit/keys/{}", self.key_name))?
                    .as_str(),
            )
            .set(VAULT_TOKEN_NAME, &self.token)
            .set("Content-Type", "application/json")
            .call()?
            .into_json::<GetSecretResponse>()?;

        println!("->{:#?}", data.keys);

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
