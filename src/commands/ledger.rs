//! `tmkms ledger` CLI (sub)commands

use crate::{
    chain,
    prelude::*,
    privval::{SignableMsg, SignedMsgType},
};
use abscissa_core::{Command, Runnable};
use clap::{Parser, Subcommand};
use std::{path::PathBuf, process};
use tendermint::Vote;
use tendermint_proto as proto;

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

        let vote = proto::types::Vote {
            height: self.height.unwrap(),
            round: self.round.unwrap() as i32,
            r#type: SignedMsgType::Proposal.into(),
            ..Default::default()
        };
        println!("{vote:?}");
        let sign_vote_req = SignableMsg::from(Vote::try_from(vote).unwrap());
        let to_sign = sign_vote_req
            .canonical_bytes(config.validator[0].chain_id.clone())
            .unwrap();

        let _sig = chain.keyring.sign(None, &to_sign).unwrap();

        println!(
            "Successfully called the init command with height {}, and round {}",
            self.height.unwrap(),
            self.round.unwrap()
        );
    }
}
