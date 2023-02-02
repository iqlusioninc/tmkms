//! Set up a new YubiHSM2 or restore from backup

use crate::prelude::*;
use abscissa_core::{Command, Runnable};
use chrono::{SecondsFormat, Utc};
use clap::Parser;
use getrandom::getrandom;
use hkd32::{mnemonic, KeyMaterial};
use hkdf::Hkdf;
use sha2::Sha512;
use std::{
    fs::File,
    io::{self, Write},
    path::PathBuf,
    process::exit,
};
use subtle_encoding::{bech32::Bech32, hex};
use yubihsm::{
    authentication, object,
    setup::{Profile, Role},
    wrap, AuditOption, Capability, Connector, Credentials, Domain,
};
use zeroize::{Zeroize, Zeroizing};

/// Domain separation string used as "info" for HKDF
const HKDF_MNEMONIC_INFO: &[u8] = b"yubihsm setup BIP39 derivation";

/// Language used when generating the [`mnemonic::Phrase`]
const BIP39_LANGUAGE: mnemonic::Language = mnemonic::Language::English;

/// Domain separation for derivation hierarchy versions (ala BIP43's "purpose" field)
const DERIVATION_VERSION: &[u8] = b"1";

/// Key size to use for generating passwords and wrap keys (256-bits).
/// This results in a 24-word BIP39 [`mnemonic::Phrase`].
const KEY_SIZE: usize = 32;

/// Role names
const ADMIN_ROLE_NAME: &str = "admin";
const OPERATOR_ROLE_NAME: &str = "operator";
const AUDITOR_ROLE_NAME: &str = "auditor";
const VALIDATOR_ROLE_NAME: &str = "validator";

/// The `yubihsm setup` subcommand: performs initial device provisioning
/// including creation of initial authentication and wrap keys.
#[derive(Command, Debug, Default, Parser)]
pub struct SetupCommand {
    /// path to tmkms.toml
    #[clap(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// enable verbose debug logging
    #[clap(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// print derived keys ONLY - do not reinitialize HSM
    #[clap(short = 'p', long = "print-only")]
    pub print_only: bool,

    /// restore from existing 24-word mnemonic
    #[clap(short = 'r', long = "restore")]
    pub restore: bool,

    /// write report file at given path
    #[clap(short = 'w', long = "write-report")]
    pub write_report: Option<PathBuf>,
}

impl Runnable for SetupCommand {
    /// Perform initial YubiHSM dervice provisioning
    fn run(&self) {
        let hsm_connector = crate::yubihsm::connector();
        let hsm_serial_number = get_hsm_client(hsm_connector)
            .device_info()
            .expect("error getting device info")
            .serial_number;

        let mnemonic = if self.restore {
            println!("Restoring and reprovisioning YubiHSM from existing 24-word mnemonic phrase.");
            println!();

            read_mnemonic_from_stdin("*** Enter mnemonic (separate words with spaces): ")
        } else {
            generate_mnemonic_from_hsm_and_os_csprngs(hsm_connector)
        };

        let roles = derive_roles_from_mnemonic(&mnemonic);
        let wrap_key = derive_wrap_key_from_mnemonic(&mnemonic, 1);

        // TODO(tarcieri): support for enabling forced auditing
        let profile = Profile::default()
            .audit_option(AuditOption::Off)
            .roles(roles)
            .wrap_keys(vec![wrap_key]);

        let operator_password = RolePassword::derive_from_mnemonic(&mnemonic, OPERATOR_ROLE_NAME);
        let auditor_password = RolePassword::derive_from_mnemonic(&mnemonic, AUDITOR_ROLE_NAME);
        let validator_password = RolePassword::derive_from_mnemonic(&mnemonic, VALIDATOR_ROLE_NAME);

        // Re-derive wrap key for display
        // TODO(tarcieri): allow access to the underlying wrap key secret in `yubihsm` crate to avoid this
        let wrapkey_material =
            derive_secret_from_mnemonic(&mnemonic, &[b"wrap", serialize_key_id(1).as_bytes()]);

        let wrapkey_hex =
            Zeroizing::new(String::from_utf8(hex::encode(wrapkey_material.as_bytes())).unwrap());

        if self.print_only {
            if self.restore {
                println!("Below are all keys/passwords derived from your 24-word admin mnemonic:");
            } else {
                println!(
                    "Below is a randomly generated 24-word admin mnemonic and derived keys/passwords:"
                );
            }
        } else {
            println!("This process will *ERASE* the configured YubiHSM2 and reinitialize it:");
            println!();
            println!("- YubiHSM serial: {hsm_serial_number}");
            println!();
            println!("Authentication keys with the following IDs and passwords will be created:");
        }

        println!();
        println!("- key 0x0001: admin:");
        println!();
        print_mnemonic(&mnemonic);
        println!();
        println!(
            "- authkey 0x0002 [operator]:  {}",
            operator_password.as_str()
        );
        println!(
            "- authkey 0x0003 [auditor]:   {}",
            auditor_password.as_str()
        );
        println!(
            "- authkey 0x0004 [validator]: {}",
            validator_password.as_str()
        );

        println!("- wrapkey 0x0001 [primary]:   {}", wrapkey_hex.as_str());

        if self.print_only {
            exit(0);
        }

        prompt_for_user_approval("Are you SURE you want erase and reinitialize this HSM?");

        let report = yubihsm::setup::erase_device_and_init_with_profile(
            hsm_connector.clone(),
            crate::yubihsm::config().auth.credentials(),
            profile,
        )
        .unwrap_or_else(|e| hsm_error(&e));

        status_ok!(
            "Success",
            "reinitialized YubiHSM (serial: {})",
            hsm_serial_number
        );

        if let Some(ref report_path) = self.write_report {
            status_ok!(
                "Writing",
                "provisioning report to: {}",
                report_path.display()
            );

            let mut report_file = File::create(report_path).unwrap_or_else(|e| {
                panic!("couldn't create report file: {e}");
            });

            report_file
                .write_all(report.to_json().as_bytes())
                .unwrap_or_else(|e| {
                    panic!("error writing report: {e}");
                })
        }
    }
}

/// Read the mnemonic phrase from STDIN
fn read_mnemonic_from_stdin(prompt: &str) -> mnemonic::Phrase {
    print!("{prompt}");
    io::stdout().flush().unwrap();

    let mut input_string = String::new();
    io::stdin()
        .read_line(&mut input_string)
        .expect("error reading mnemonic from STDIN!");

    let input_words: Vec<_> = input_string.split_whitespace().collect();
    let input_phrase = input_words.join(" ");
    input_string.zeroize();

    let result = mnemonic::Phrase::new(input_phrase, BIP39_LANGUAGE).unwrap_or_else(|_| {
        eprintln!("*** ERROR: Couldn't decode mnemonic");
        exit(1);
    });

    println!("\nMnemonic phrase decoded/checksummed successfully!\n");

    result
}

/// Display the mnemonic as two groups of 12 words
fn print_mnemonic(mnemonic: &mnemonic::Phrase) {
    let words: Vec<&str> = mnemonic.phrase().split(' ').collect();
    let words_len = words.len();

    for word_group in &[&words[..(words_len / 2)], &words[(words_len / 2)..]] {
        let mut word_group_joined = word_group.join(" ");
        println!("    {word_group_joined}");
        word_group_joined.zeroize();
    }
}

/// Get an HSM client from the provided connector
///
/// We need to create our own client here since the global one maintains
/// a persistent connection, and we need to close this one before we can
/// reprovision the HSM
fn get_hsm_client(hsm_connector: &Connector) -> yubihsm::Client {
    yubihsm::Client::open(
        hsm_connector.clone(),
        crate::yubihsm::config().auth.credentials(),
        false,
    )
    .unwrap_or_else(|e| hsm_error(&e))
}

/// Generate entropy by combining entropy both from the host OS and from the
/// YubiHSM2 itself (which includes an internal CSPRNG).
///
/// These are both used as input key material (IKM) for a key derivation
/// function (HKDF) in order to derive the recovery passphrase, which ideally
/// ensures that the passphrase will be securely random so long as at least
/// one of the two inputs is secure.
fn generate_mnemonic_from_hsm_and_os_csprngs(hsm_connector: &Connector) -> mnemonic::Phrase {
    let hsm_client = get_hsm_client(hsm_connector);

    // Obtain half of the IKM from the YubiHSM (256-bits)
    let mut ikm = hsm_client
        .get_pseudo_random(KEY_SIZE)
        .unwrap_or_else(|e| hsm_error(&e));

    // Obtain another half of the IKM from the host OS (256-bits)
    // for a total of 512-bits IKM. This ensures we still get 256-bits
    // of good IKM even in the event one of the RNGs fails.
    ikm.extend_from_slice(&[0u8; KEY_SIZE]);
    getrandom(&mut ikm[KEY_SIZE..]).expect("RNG failure!");

    let kdf = Hkdf::<Sha512>::new(None, &ikm);

    // 32-bytes (256-bits) -> 24 BIP32 words
    let mut okm = [0u8; KEY_SIZE];
    kdf.expand(HKDF_MNEMONIC_INFO, &mut okm).unwrap();
    ikm.zeroize();

    let result = mnemonic::Phrase::from_entropy(okm, BIP39_LANGUAGE);
    okm.zeroize();

    result
}

/// Derive the default roles form the given BIP39 `mnemonic::Phrase`
fn derive_roles_from_mnemonic(mnemonic: &mnemonic::Phrase) -> Vec<Role> {
    let admin_role = derive_admin_role_from_mnemonic(mnemonic);

    // operator
    let operator_role = derive_role_from_mnemonic(mnemonic, 2, OPERATOR_ROLE_NAME)
        .capabilities(
            Capability::GENERATE_ASYMMETRIC_KEY
                | Capability::PUT_ASYMMETRIC_KEY
                | Capability::GENERATE_HMAC_KEY
                | Capability::PUT_HMAC_KEY
                | Capability::IMPORT_WRAPPED
                | Capability::EXPORT_WRAPPED
                | Capability::GET_OPAQUE
                | Capability::GET_OPTION
                | Capability::GET_LOG_ENTRIES
                | Capability::SIGN_ATTESTATION_CERTIFICATE,
        )
        .delegated_capabilities(Capability::all())
        .domains(Domain::all());

    // auditor
    let auditor_role = derive_role_from_mnemonic(mnemonic, 3, AUDITOR_ROLE_NAME)
        .capabilities(
            Capability::GET_LOG_ENTRIES
                | Capability::GET_OPTION
                | Capability::PUT_OPTION
                | Capability::GET_OPAQUE,
        )
        .delegated_capabilities(Capability::empty())
        .domains(Domain::all());

    // validator
    let validator_role = derive_role_from_mnemonic(mnemonic, 4, VALIDATOR_ROLE_NAME)
        .capabilities(
            Capability::SIGN_ECDSA
                | Capability::SIGN_EDDSA
                | Capability::SIGN_ATTESTATION_CERTIFICATE
                | Capability::GET_LOG_ENTRIES,
        )
        .delegated_capabilities(Capability::empty())
        .domains(Domain::DOM1);

    vec![admin_role, operator_role, auditor_role, validator_role]
}

/// Derive the admin role from the given mnemonic.
///
/// The admin role is somewhat different from the others and confers total
/// authority over the HSM device.
fn derive_admin_role_from_mnemonic(mnemonic: &mnemonic::Phrase) -> Role {
    let admin_credentials = Credentials::new(
        1,
        authentication::Key::derive_from_password(mnemonic.phrase().as_bytes()),
    );

    Role::new(admin_credentials)
        .authentication_key_label(create_object_label(ADMIN_ROLE_NAME))
        .capabilities(Capability::all())
        .delegated_capabilities(Capability::all())
        .domains(Domain::all())
}

/// Derive the initial settings for a role from the given mnemonic
fn derive_role_from_mnemonic(
    mnemonic: &mnemonic::Phrase,
    key_id: object::Id,
    role_name: &str,
) -> Role {
    let role_password = RolePassword::derive_from_mnemonic(mnemonic, role_name);

    let role_credentials = Credentials::new(
        key_id,
        authentication::Key::derive_from_password(role_password.as_bytes()),
    );

    Role::new(role_credentials).authentication_key_label(create_object_label(role_name))
}

/// Passwords for a given role, derived from a BIP39 `mnemonic::Phrase`.
/// These are serialized as Bech32 for compactness.
struct RolePassword(String);

impl RolePassword {
    /// Derive a role password from the given BIP39 `mnemonic::Phrase`
    pub fn derive_from_mnemonic(mnemonic: &mnemonic::Phrase, role_name: &str) -> Self {
        let mut secret_key =
            derive_secret_from_mnemonic(mnemonic, &[b"role", role_name.as_bytes()]);

        // YubiHSM authentication keys are 2 x AES-128 keys, derived using
        // PBKDF2. This means we derive no value from more than 128-bits of
        // entropy in the password, whereas shorter passwords are more
        // convenient.
        //
        // For that reason, truncate the derived secret to 16-bytes
        let truncated_secret_key = &secret_key.as_bytes()[..(KEY_SIZE / 2)];

        let result = RolePassword(
            Bech32::default().encode(format!("kms-{role_name}-password-"), truncated_secret_key),
        );
        secret_key.zeroize();

        result
    }

    /// Borrow the raw password as a `&str`
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Borrow the raw password as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Drop for RolePassword {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Derive a wrap key from the given BIP39 `mnemonic::Phrase`
fn derive_wrap_key_from_mnemonic(mnemonic: &mnemonic::Phrase, key_id: object::Id) -> wrap::Key {
    // Capabilities given to the initial wrap key:
    // wrap/unwrap both data and objects
    let wrap_key_capabilities = Capability::EXPORT_WRAPPED
        | Capability::IMPORT_WRAPPED
        | Capability::WRAP_DATA
        | Capability::UNWRAP_DATA;

    // Allow the initial wrap key to create new objects with any other
    // capabilities.
    //
    // To prevent escalation of privilege, no roles except administrators
    // will be given the capability to export other objects.
    let wrap_key_delegated_capabilities = Capability::all();

    // Make the wrap key accessible from all domains. This allows it to
    // import and export objects from any domain.
    let wrap_key_domains = Domain::all();

    // Label to put on the wrap key
    let wrap_key_label = create_object_label("primary");

    // Includes the key ID in the derivation path, which allows us to derive
    // other wrap keys from the same seed `mnemonic::Phrase` phrase in the event one
    // has been compromised.
    wrap::Key::from_bytes(
        key_id,
        derive_secret_from_mnemonic(mnemonic, &[b"wrap", serialize_key_id(key_id).as_bytes()])
            .as_bytes(),
    )
    .unwrap()
    .label(wrap_key_label)
    .capabilities(wrap_key_capabilities)
    .delegated_capabilities(wrap_key_delegated_capabilities)
    .domains(wrap_key_domains)
}

/// Serialize a key ID as bytes for use in a derivation path
fn serialize_key_id(key_id: object::Id) -> String {
    format!("0x{key_id:04x}")
}

/// Derive secrets from the given BIP39 `mnemonic::Phrase` ala a BIP32 (hardened)
/// derivation hierarchy.
// TODO(tarcieri): refactor `path` to use `impl AsRef<hkd32::Path>`
fn derive_secret_from_mnemonic(mnemonic: &mnemonic::Phrase, path: &[&[u8]]) -> KeyMaterial {
    assert!(!path.is_empty(), "cannot derive keys for the root path");

    debug!(
        "deriving secret for path: /{}",
        path.iter()
            .map(|component| String::from_utf8_lossy(component))
            .collect::<Vec<_>>()
            .join("/")
    );

    let ikm = KeyMaterial::from_bytes(mnemonic.entropy()).unwrap();
    let path_bytes = construct_derivation_path(path);
    ikm.derive_subkey(hkd32::Path::new(&path_bytes).unwrap())
}

/// Construct the derivation path
// TODO(tarcieri): switch to `hkd32::PathBuf` when `alloc` is available in CI
fn construct_derivation_path(path: &[&[u8]]) -> Vec<u8> {
    let mut result = vec![(DERIVATION_VERSION.len() - 1) as u8];
    result.extend_from_slice(DERIVATION_VERSION);

    for component in path {
        result.push((component.len() - 1) as u8);
        result.extend_from_slice(component);
    }

    result
}

/// Create a label for a newly generated object which tags it with the date
/// it was created
fn create_object_label(label_prefix: &str) -> object::Label {
    // e.g. 2019-02-26T18:03:53Z
    let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    object::Label::from([label_prefix, &timestamp].join(":").as_ref())
}

/// Prompt the user to ensure they want to proceed
fn prompt_for_user_approval(prompt: &str) {
    print!("\n*** {prompt} (y/N): ");
    io::stdout().flush().unwrap();

    let mut choice_in = String::new();
    io::stdin()
        .read_line(&mut choice_in)
        .expect("Failed to read user input");

    let choice = choice_in.trim();

    if choice != "y" && choice != "Y" {
        println!("Aborting");
        exit(1);
    }
}

/// Handler for HSM errors
fn hsm_error(e: &dyn std::error::Error) -> ! {
    status_err!("HSM error: {}", e);

    // TODO: handle exits via abscissa
    exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "HKD32" test vector derivation key
    const TEST_KEY: [u8; KEY_SIZE] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];

    /// BIP39 mnemonic::Phrase phrase corresponding to the `TEST_KEY`
    const TEST_BIP39_PHRASE: &str =
        "abandon amount liar amount expire adjust cage candy arch gather drum bullet \
         absurd math era live bid rhythm alien crouch range attend journey unaware";

    /// Test vector `mnemonic::Phrase`
    fn test_mnemonic() -> mnemonic::Phrase {
        mnemonic::Phrase::from_entropy(TEST_KEY, BIP39_LANGUAGE)
    }

    #[test]
    fn derive_test_key_from_test_mnemonic() {
        assert_eq!(test_mnemonic().entropy(), &TEST_KEY);
    }

    #[test]
    fn derive_test_key_from_test_bip39_phrase() {
        let mnemonic = mnemonic::Phrase::new(TEST_BIP39_PHRASE, BIP39_LANGUAGE).unwrap();
        assert_eq!(mnemonic.entropy(), &TEST_KEY);
    }

    struct DeriveVector<'a> {
        pub path: &'a [&'a [u8]],
        pub output: [u8; KEY_SIZE],
    }

    impl<'a> DeriveVector<'a> {
        fn new(path: &'a [&'a [u8]], output: [u8; KEY_SIZE]) -> Self {
            Self { path, output }
        }
    }

    #[test]
    fn derive_test_vectors() {
        let test_vectors = &[
            DeriveVector::new(
                &[b"1"],
                [
                    3, 76, 227, 91, 100, 247, 29, 7, 204, 76, 23, 170, 23, 160, 6, 21, 187, 233,
                    220, 6, 45, 131, 162, 9, 150, 246, 133, 244, 99, 107, 101, 78,
                ],
            ),
            DeriveVector::new(
                &[b"1", b"2"],
                [
                    236, 169, 7, 38, 98, 113, 230, 246, 200, 141, 136, 189, 189, 19, 199, 248, 21,
                    127, 94, 75, 152, 134, 94, 128, 221, 172, 217, 165, 200, 87, 162, 205,
                ],
            ),
            DeriveVector::new(
                &[b"1", b"2", b"3"],
                [
                    60, 230, 72, 98, 156, 75, 72, 142, 18, 42, 73, 177, 148, 32, 167, 226, 201, 23,
                    242, 56, 150, 23, 116, 175, 245, 118, 222, 36, 156, 143, 158, 11,
                ],
            ),
        ];

        for vector in test_vectors {
            let derived_key = derive_secret_from_mnemonic(&test_mnemonic(), vector.path);
            assert_eq!(derived_key.as_bytes(), &vector.output);
        }
    }
}
