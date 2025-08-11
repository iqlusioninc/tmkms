//! `tmkms ledger` CLI (sub)commands

use crate::{
    chain,
    config::Version,
    prelude::*,
    privval::{SignableMsg, SignedMsgType},
};
use abscissa_core::{Command, Runnable};
use clap::{Parser, Subcommand};
use cometbft::Vote;
use std::{path::PathBuf, process};

macro_rules! vote_from_proto {
    (v1, $height:expr, $round:expr) => {{
        let vote = cometbft_proto::types::v1::Vote {
            height: $height,
            round: $round as i32,
            r#type: SignedMsgType::Proposal.into(),
            ..Default::default()
        };
        Vote::try_from(vote).unwrap()
    }};
    (v0_34, $height:expr, $round:expr) => {{
        let vote = cometbft_proto::v0_34::types::Vote {
            height: $height,
            round: $round as i32,
            r#type: SignedMsgType::Proposal.into(),
            ..Default::default()
        };
        Vote::try_from(vote).unwrap()
    }};
    (v0_37, $height:expr, $round:expr) => {{
        let vote = cometbft_proto::v0_37::types::Vote {
            height: $height,
            round: $round as i32,
            r#type: SignedMsgType::Proposal.into(),
            ..Default::default()
        };
        Vote::try_from(vote).unwrap()
    }};
    (v0_38, $height:expr, $round:expr) => {{
        let vote = cometbft_proto::v0_38::types::Vote {
            height: $height,
            round: $round as i32,
            r#type: SignedMsgType::Proposal.into(),
            ..Default::default()
        };
        Vote::try_from(vote).unwrap()
    }};
}

/// `ledger` subcommand
#[derive(Command, Debug, Runnable, Subcommand)]
pub enum LedgerCommand {
    /// initialise the height/round/step
    Init(InitCommand),
}

impl LedgerCommand {
    pub(super) fn config_path(&self) -> Option<&PathBuf> {
        match self {
            LedgerCommand::Init(init) => init.config.as_ref(),
        }
    }
}

/// `ledger init` subcommand
#[derive(Command, Debug, Parser)]
pub struct InitCommand {
    /// config file path
    #[clap(short = 'c', long = "config")]
    pub config: Option<PathBuf>,

    /// block height
    #[clap(short = 'H', long = "height")]
    pub height: Option<i64>,

    /// block round
    #[clap(short = 'r', long = "round")]
    pub round: Option<i64>,
}

impl Runnable for InitCommand {
    fn run(&self) {
        let config = APP.config();

        chain::load_config(&config).unwrap_or_else(|e| {
            status_err!("error loading configuration: {}", e);
            process::exit(1);
        });

        let chain_id = config.validator[0].chain_id.clone();
        let registry = chain::REGISTRY.get();
        let chain = registry.get_chain(&chain_id).unwrap();

        let height = self.height.unwrap();
        let round = self.round.unwrap();
        let version = config.validator[0].version;
        let vote = match version {
            Version::V0_34 => vote_from_proto!(v0_34, height, round),
            Version::V0_37 => vote_from_proto!(v0_37, height, round),
            Version::V0_38 => vote_from_proto!(v0_38, height, round),
            Version::V1 => vote_from_proto!(v1, height, round),
        };
        println!("{vote:?}");
        let sign_vote_req = SignableMsg::from(vote);
        let to_sign = sign_vote_req
            .canonical_bytes(config.validator[0].chain_id.clone(), version)
            .unwrap();

        let _sig = chain.keyring.sign(None, &to_sign).unwrap();

        println!(
            "Successfully called the init command with height {}, and round {}",
            height, round
        );
    }
}
