//! Ledger Tendermint signer

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

use super::error::Error;
use ledger::{ApduAnswer, ApduCommand};

const CLA: u8 = 0x56;
const INS_PUBLIC_KEY_ED25519: u8 = 0x01;
const INS_SIGN_ED25519: u8 = 0x02;

const USER_MESSAGE_CHUNK_SIZE: usize = 250;

#[allow(dead_code)]
const INS_GET_VERSION: u8 = 0x00;

pub(super) struct TendermintValidatorApp {
    app: ledger::LedgerApp,
}

// TODO(tarcieri): check this is actually sound?!
#[allow(unsafe_code)]
unsafe impl Send for TendermintValidatorApp {}

#[allow(dead_code)]
pub struct Version {
    mode: u8,
    major: u8,
    minor: u8,
    patch: u8,
}

impl TendermintValidatorApp {
    pub fn connect() -> Result<Self, Error> {
        let app = ledger::LedgerApp::new()?;
        Ok(TendermintValidatorApp { app })
    }

    /// Get version
    #[allow(dead_code)]
    pub fn version(&self) -> Result<Version, Error> {
        let command = ApduCommand {
            cla: CLA,
            ins: INS_GET_VERSION,
            p1: 0x00,
            p2: 0x00,
            length: 0,
            data: Vec::new(),
        };

        let response = self.app.exchange(command)?;

        // TODO: this is just temporary, ledger errors should check for 0x9000
        if response.retcode != 0x9000 {
            return Err(Error::InvalidVersion);
        }

        let version = Version {
            mode: response.data[0],
            major: response.data[1],
            minor: response.data[2],
            patch: response.data[3],
        };

        Ok(version)
    }

    /// Get public key
    pub fn public_key(&self) -> Result<[u8; 32], Error> {
        let command = ApduCommand {
            cla: CLA,
            ins: INS_PUBLIC_KEY_ED25519,
            p1: 0x00,
            p2: 0x00,
            length: 0,
            data: Vec::new(),
        };

        match self.app.exchange(command) {
            Ok(response) => {
                if response.retcode != 0x9000 {
                    println!("WARNING: retcode={:X?}", response.retcode);
                }

                if response.data.len() != 32 {
                    return Err(Error::InvalidPk);
                }

                let mut array = [0u8; 32];
                array.copy_from_slice(&response.data[..32]);
                Ok(array)
            }
            Err(err) => {
                // TODO: Friendly error
                Err(Error::Ledger(err))
            }
        }
    }

    /// Sign message
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], Error> {
        let chunks = message.chunks(USER_MESSAGE_CHUNK_SIZE);

        if chunks.len() > 255 {
            return Err(Error::InvalidMessageSize);
        }

        if chunks.len() == 0 {
            return Err(Error::InvalidEmptyMessage);
        }

        let packet_count = chunks.len() as u8;
        let mut response: ApduAnswer = ApduAnswer {
            data: vec![],
            retcode: 0,
        };

        // Send message chunks
        for (packet_idx, chunk) in chunks.enumerate() {
            let _command = ApduCommand {
                cla: CLA,
                ins: INS_SIGN_ED25519,
                p1: (packet_idx + 1) as u8,
                p2: packet_count,
                length: chunk.len() as u8,
                data: chunk.to_vec(),
            };

            response = self.app.exchange(_command)?;
        }

        if response.data.is_empty() && response.retcode == 0x9000 {
            return Err(Error::NoSignature);
        }

        // Last response should contain the answer
        if response.data.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let mut array = [0u8; 64];
        array.copy_from_slice(&response.data[..64]);
        Ok(array)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::ed25519::signature::Verifier;
    use once_cell::sync::Lazy;
    use std::sync::Mutex;
    use std::time::Instant;

    use super::{Error, TendermintValidatorApp};

    static APP: Lazy<Mutex<TendermintValidatorApp>> =
        Lazy::new(|| Mutex::new(TendermintValidatorApp::connect().unwrap()));

    fn get_fake_proposal(index: u64, round: i64) -> Vec<u8> {
        use byteorder::{LittleEndian, WriteBytesExt};
        let other: [u8; 12] = [
            0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
        ];

        let mut message = Vec::new();
        message.write_u8(0).unwrap(); // (field_number << 3) | wire_type

        message.write_u8(0x08).unwrap(); // (field_number << 3) | wire_type
        message.write_u8(0x01).unwrap(); // PrevoteType

        message.write_u8(0x11).unwrap(); // (field_number << 3) | wire_type
        message.write_u64::<LittleEndian>(index).unwrap();

        message.write_u8(0x19).unwrap(); // (field_number << 3) | wire_type
        message.write_i64::<LittleEndian>(round).unwrap();

        // remaining fields (timestamp, not checked):
        message.write_u8(0x22).unwrap(); // (field_number << 3) | wire_type
        message.extend_from_slice(&other);

        // Increase index
        message[0] = message.len() as u8 - 1;
        message
    }

    #[test]
    #[ignore]
    fn version() {
        let app = APP.lock().unwrap();

        let resp = app.version();

        match resp {
            Ok(version) => {
                println!("mode  {}", version.mode);
                println!("major {}", version.major);
                println!("minor {}", version.minor);
                println!("patch {}", version.patch);

                assert_eq!(version.mode, 0xFF);
                assert_eq!(version.major, 0x00);
                assert!(version.minor >= 0x04);
            }
            Err(err) => {
                eprintln!("Error: {err:?}");
            }
        }
    }

    #[test]
    #[ignore]
    fn public_key() {
        let app = APP.lock().unwrap();
        let resp = app.public_key();

        match resp {
            Ok(pk) => {
                assert_eq!(pk.len(), 32);
                println!("PK {pk:0X?}");
            }
            Err(err) => {
                eprintln!("Error: {err:?}");
                panic!()
            }
        }
    }

    #[test]
    #[ignore]
    fn sign_empty() {
        let app = APP.lock().unwrap();

        let some_message0 = b"";

        let signature = app.sign(some_message0);
        assert!(signature.is_err());
        assert!(matches!(
            signature.err().unwrap(),
            Error::InvalidEmptyMessage
        ));
    }

    #[test]
    #[ignore]
    fn sign_verify() {
        let app = APP.lock().unwrap();

        let some_message1 = get_fake_proposal(5, 0);
        app.sign(&some_message1).unwrap();

        let some_message2 = get_fake_proposal(6, 0);
        match app.sign(&some_message2) {
            Ok(sig) => {
                use ed25519_dalek::PublicKey;
                use ed25519_dalek::Signature;

                println!("{:#?}", sig.to_vec());

                // First, get public key
                let public_key_bytes = app.public_key().unwrap();
                let public_key = PublicKey::from_bytes(&public_key_bytes).unwrap();
                let signature = Signature::from_bytes(&sig).unwrap();

                // Verify signature
                assert!(public_key.verify(&some_message2, &signature).is_ok());
            }
            Err(e) => {
                println!("Err {e:#?}");
                panic!();
            }
        }
    }

    #[test]
    #[ignore]
    fn sign_many() {
        let app = APP.lock().unwrap();

        // First, get public key
        let _resp = app.public_key().unwrap();

        // Now send several votes
        for index in 50u8..254u8 {
            let some_message1 = [
                0x8,  // (field_number << 3) | wire_type
                0x1,  // PrevoteType
                0x11, // (field_number << 3) | wire_type
                index, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // height
                0x19, // (field_number << 3) | wire_type
                0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  // round
                0x22, // (field_number << 3) | wire_type
                // remaining fields (timestamp):
                0xb, 0x8, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x1,
            ];

            let signature = app.sign(&some_message1);
            match signature {
                Ok(sig) => {
                    println!("{:#?}", sig.to_vec());
                }
                Err(e) => {
                    println!("Err {e:#?}");
                    panic!();
                }
            }
        }
    }

    #[test]
    #[ignore]
    fn quick_benchmark() {
        let app = APP.lock().unwrap();

        // initialize app with a vote
        let msg = get_fake_proposal(0, 100);
        app.sign(&msg).unwrap();

        let start = Instant::now();
        // Now send several votes
        for i in 1u64..20u64 {
            app.sign(&get_fake_proposal(i, 100)).unwrap();
        }
        let duration = start.elapsed();
        println!("Elapsed {duration:?}");
    }
}
