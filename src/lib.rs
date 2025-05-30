//! Tendermint Key Management System

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]

#[cfg(not(any(
    feature = "softsign",
    feature = "yubihsm",
    feature = "ledger",
    feature = "fortanixdsm",
    feature = "hashicorp"
)))]
compile_error!(
    "please enable one of the following backends with cargo's --features argument: \
     yubihsm, ledgertm, softsign, fortanixdsm, hashicorp (e.g. --features=yubihsm)"
);

pub mod application;
pub mod chain;
pub mod client;
pub mod commands;
pub mod config;
pub mod connection;
pub mod error;
pub mod key_utils;
pub mod keyring;
pub mod prelude;
pub mod privval;
pub mod rpc;
pub mod session;

#[cfg(feature = "yubihsm")]
pub mod yubihsm;

pub use crate::application::KmsApplication;

// Map type used within this application
use std::collections::BTreeMap as Map;
