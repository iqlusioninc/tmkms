//! Tendermint Key Management System

#![doc(html_root_url = "https://docs.rs/tmkms/0.8.0-alpha1")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[cfg(not(any(feature = "softsign", feature = "yubihsm", feature = "ledgertm")))]
compile_error!(
    "please enable one of the following backends with cargo's --features argument: \
     yubihsm, ledgertm, softsign (e.g. --features=yubihsm)"
);

pub mod application;
pub mod chain;
pub mod client;
pub mod commands;
pub mod config;
pub mod connection;
pub mod error;
pub mod keyring;
pub mod prelude;
pub mod rpc;
pub mod session;

#[cfg(feature = "tx-signer")]
pub mod tx_signer;

#[cfg(feature = "yubihsm")]
pub mod yubihsm;

pub use crate::application::KmsApplication;

// Map type used within this application
use std::collections::BTreeMap as Map;
