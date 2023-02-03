//! `tmkms ledger` CLI (sub)commands

use crate::{
    amino_types::{
        vote::{SignVoteRequest, Vote},
        SignableMsg, SignedMsgType,
    },
    chain,
    config::validator::ProtocolVersion,
    prelude::*,
};
use abscissa_core::{Command, Runnable};
use clap::{Parser, Subcommand};
use std::{path::PathBuf, process};

/// `ledger` subcommand
#[derive(Command, Debug, Runnable, Subcommand)]
pub enum LedgerCommand {
    /// initialise the height/round/step
    Initialise(InitCommand),
}

impl LedgerCommand {
    pub(super) fn config_path(&self) -> Option<&PathBuf> {
        match self {
            LedgerCommand::Initialise(init) => init.config.as_ref(),
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
    #[clap(short = 'h', long = "height")]
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

        let vote = Vote {
            height: self.height.unwrap(),
            round: self.round.unwrap(),
            vote_type: SignedMsgType::Proposal.to_u32(),
            ..Default::default()
        };
        println!("{vote:?}");
        let sign_vote_req = SignVoteRequest { vote: Some(vote) };
        let mut to_sign = vec![];
        sign_vote_req
            .sign_bytes(
                config.validator[0].chain_id.clone(),
                ProtocolVersion::Legacy,
                &mut to_sign,
            )
            .unwrap();

        let _sig = chain.keyring.sign_ed25519(None, &to_sign).unwrap();

        println!(
            "Successfully called the init command with height {}, and round {}",
            self.height.unwrap(),
            self.round.unwrap()
        );
    }
}
