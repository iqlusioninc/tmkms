//! Tendermint KMS configuration file networks

use crate::prelude::*;
use std::{
    fmt::{self, Display},
    process,
};

/// Tendermint networks we have config networks for
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Network {
    /// Terra `columbus` chain
    Columbus,

    /// Cosmos `cosmoshub` chain
    CosmosHub,

    /// Iris `irishub` chain
    IrisHub,
}

impl Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Network::Columbus => "columbus",
            Network::CosmosHub => "cosmoshub",
            Network::IrisHub => "irishub",
        })
    }
}

impl Network {
    /// Get a slice containing all known networks
    pub fn all() -> &'static [Network] {
        &[Network::Columbus, Network::CosmosHub, Network::IrisHub]
    }

    /// Parse a network name from the chain ID prefix
    pub fn parse(s: &str) -> Self {
        match s {
            "columbus" => Network::Columbus,
            "cosmoshub" => Network::CosmosHub,
            "irishub" => Network::IrisHub,
            other => {
                status_err!("unknown Tendermint network: `{}`", other);
                eprintln!("\nRegistered networks:");

                for network in Self::all() {
                    eprintln!("- {}", network);
                }

                process::exit(1);
            }
        }
    }

    /// Get the current production chain ID for this network
    pub fn chain_id(&self) -> &str {
        match self {
            Network::Columbus => "columbus-3",
            Network::CosmosHub => "cosmoshub-3",
            Network::IrisHub => "irishub",
        }
    }

    /// Get the schema file for this network
    pub fn schema_file(&self) -> &str {
        match self {
            Network::Columbus => "terra.toml",
            Network::CosmosHub => "cosmos-sdk.toml",
            Network::IrisHub => "iris.toml",
        }
    }
}
