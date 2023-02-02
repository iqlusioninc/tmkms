/*******************************************************************************
*   (c) 2018, 2019 ZondaX GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

use super::client::TendermintValidatorApp;
use crate::keyring::ed25519::{PublicKey, Signature};
use signature::{Error, Signer};
use std::sync::{Arc, Mutex};

/// ed25519 signature provider for the Ledger Tendermint Validator app
pub(super) struct Ed25519LedgerTmAppSigner {
    app: Arc<Mutex<TendermintValidatorApp>>,
}

impl Ed25519LedgerTmAppSigner {
    /// Create a new Ed25519 signer based on Ledger Nano S - Tendermint Validator app
    pub fn connect() -> Result<Self, Error> {
        let validator_app = TendermintValidatorApp::connect().map_err(Error::from_source)?;
        let app = Arc::new(Mutex::new(validator_app));
        Ok(Ed25519LedgerTmAppSigner { app })
    }
}

impl From<&Ed25519LedgerTmAppSigner> for PublicKey {
    /// Returns the public key that corresponds to the Tendermint Validator app connected to this signer
    fn from(signer: &Ed25519LedgerTmAppSigner) -> PublicKey {
        let app = signer.app.lock().unwrap();
        PublicKey::from_bytes(&app.public_key().unwrap()).expect("invalid Ed25519 public key")
    }
}

impl Signer<Signature> for Ed25519LedgerTmAppSigner {
    /// c: Compute a compact, fixed-sized signature of the given amino/json vote
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let app = self.app.lock().unwrap();
        let sig = app.sign(msg).map_err(Error::from_source)?;
        Ok(Signature::from(sig))
    }
}

#[cfg(test)]
mod tests {
    use super::{Ed25519LedgerTmAppSigner, PublicKey};
    use signature::Signer;

    #[test]
    #[ignore]
    fn public_key() {
        let signer = Ed25519LedgerTmAppSigner::connect().unwrap();
        let pk = PublicKey::from(&signer);
        println!("PK {pk:0X?}");
    }

    #[test]
    #[ignore]
    fn sign() {
        let signer = Ed25519LedgerTmAppSigner::connect().unwrap();

        // Sign message1
        let some_message1 = [
            33, 0x8,  // (field_number << 3) | wire_type
            0x1,  // PrevoteType
            0x11, // (field_number << 3) | wire_type
            0x10, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
            0x19, // (field_number << 3) | wire_type
            0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
            0x22, // (field_number << 3) | wire_type
            // remaining fields (timestamp):
            0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
        ];

        signer.sign(&some_message1);
    }

    #[test]
    #[ignore]
    fn sign2() {
        let signer = Ed25519LedgerTmAppSigner::connect().unwrap();

        // Sign message1
        let some_message1 = [
            33, 0x8,  // (field_number << 3) | wire_type
            0x1,  // PrevoteType
            0x11, // (field_number << 3) | wire_type
            0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
            0x19, // (field_number << 3) | wire_type
            0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
            0x22, // (field_number << 3) | wire_type
            // remaining fields (timestamp):
            0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
        ];

        signer.sign(&some_message1);

        // Sign message2
        let some_message2 = [
            33, 0x8,  // (field_number << 3) | wire_type
            0x1,  // PrevoteType
            0x11, // (field_number << 3) | wire_type
            0x10, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
            0x19, // (field_number << 3) | wire_type
            0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
            0x22, // (field_number << 3) | wire_type
            // remaining fields (timestamp):
            0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
        ];

        signer.sign(&some_message2);
    }

    #[test]
    #[ignore]
    fn sign_many() {
        let signer = Ed25519LedgerTmAppSigner::connect().unwrap();

        // Get public key to initialize
        let pk = PublicKey::from(&signer);
        println!("PK {pk:0X?}");

        for index in 50u8..254u8 {
            // Sign message1
            let some_message = [
                33, 0x8,  // (field_number << 3) | wire_type
                0x1,  // PrevoteType
                0x11, // (field_number << 3) | wire_type
                0x40, 0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
                0x19, // (field_number << 3) | wire_type
                index, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
                0x22, // (field_number << 3) | wire_type
                // remaining fields (timestamp):
                0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
            ];

            signer.sign(&some_message);
        }
    }
}
