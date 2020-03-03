//! Tendermint Key Management System

#![forbid(unsafe_code)]
#![deny(warnings, rust_2018_idioms, missing_docs, unused_qualifications)]
#![doc(html_root_url = "https://docs.rs/tmkms/0.7.2")]

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
#[cfg(feature = "yubihsm")]
pub mod yubihsm;

pub use crate::application::KmsApplication;
