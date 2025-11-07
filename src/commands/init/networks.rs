//! Configuration file for networks

use crate::prelude::*;
use std::{
    fmt::{self, Display},
    process,
};

/// CometBFT networks we have config networks for
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Network {
    /// Cosmos `cosmoshub` chain
    CosmosHub,

    /// Iris `irishub` chain
    IrisHub,

    /// Sentinel `sentinelhub` chain
    SentinelHub,

    /// Osmosis `osmosis` chain
    Osmosis,

    /// Persistence `core` chain
    Persistence,
}

impl Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Network::CosmosHub => "cosmoshub",
            Network::IrisHub => "irishub",
            Network::SentinelHub => "sentinelhub",
            Network::Osmosis => "osmosis",
            Network::Persistence => "core",
        })
    }
}

impl Network {
    /// Get a slice containing all known networks
    pub fn all() -> &'static [Network] {
        &[
            Network::CosmosHub,
            Network::IrisHub,
            Network::SentinelHub,
            Network::Osmosis,
            Network::Persistence,
        ]
    }

    /// Parse a network name from the chain ID prefix
    pub fn parse(s: &str) -> Self {
        match s {
            "cosmoshub" => Network::CosmosHub,
            "irishub" => Network::IrisHub,
            "sentinelhub" => Network::SentinelHub,
            "osmosis" => Network::Osmosis,
            "core" => Network::Persistence,
            other => {
                status_err!("unknown CometBFT network: `{}`", other);
                eprintln!("\nRegistered networks:");

                for network in Self::all() {
                    eprintln!("- {network}");
                }

                process::exit(1);
            }
        }
    }

    /// Get the current production chain ID for this network
    pub fn chain_id(&self) -> &str {
        match self {
            Network::CosmosHub => "cosmoshub-3",
            Network::IrisHub => "irishub",
            Network::SentinelHub => "sentinelhub-2",
            Network::Osmosis => "osmosis-1",
            Network::Persistence => "core-1",
        }
    }

    /// Get the schema file for this network
    pub fn schema_file(&self) -> &str {
        match self {
            Network::CosmosHub => "cosmos-sdk.toml",
            Network::IrisHub => "iris.toml",
            Network::SentinelHub => "sentinelhub.toml",
            Network::Osmosis => "osmosis.toml",
            Network::Persistence => "persistence.toml",
        }
    }
}
