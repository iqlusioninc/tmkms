use thiserror::Error;

pub trait ConsensusMessage {
    fn validate_basic(&self) -> Result<(), Error>;
}

/// Kinds of validation errors
#[derive(Copy, Clone, Eq, PartialEq, Debug, Error)]
pub enum Error {
    #[error("invalid Type")]
    InvalidMessageType,
    #[error("consensus message is missing")]
    MissingConsensusMessage,
    #[error("negative height")]
    NegativeHeight,
    #[error("negative round")]
    NegativeRound,
    #[error("negative POLRound (exception: -1)")]
    NegativePolRound,
    #[error("negative ValidatorIndex")]
    NegativeValidatorIndex,
    #[error("expected ValidatorAddress size to be 20 bytes")]
    InvalidValidatorAddressSize,
    #[error("Wrong hash: expected Hash size to be 32 bytes")]
    InvalidHashSize,
    #[error("negative total")]
    NegativeTotal,
}
