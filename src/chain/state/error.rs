//! Error types regarding chain state (i.e. double signing)

use abscissa_core::error::{BoxError, Context};
use std::fmt::{self, Display};
use thiserror::Error;

/// Error type
#[derive(Debug)]
pub struct StateError(pub(crate) Box<Context<StateErrorKind>>);

/// Kinds of errors
#[derive(Copy, Clone, Debug, Error, Eq, PartialEq)]
pub enum StateErrorKind {
    /// Height regressed
    #[error("height regression")]
    HeightRegression,

    /// Step regressed
    #[error("step regression")]
    StepRegression,

    /// Round regressed
    #[error("round regression")]
    RoundRegression,

    /// Double sign detected
    #[error("double sign detected")]
    DoubleSign,

    /// Error syncing state to disk
    #[error("error syncing state to disk")]
    SyncError,
}

impl StateErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<StateErrorKind> {
        Context::new(self, Some(source.into()))
    }
}

impl StateError {
    /// Get the kind of error
    pub fn kind(&self) -> StateErrorKind {
        *self.0.kind()
    }
}

impl From<StateErrorKind> for StateError {
    fn from(kind: StateErrorKind) -> Self {
        Context::new(kind, None).into()
    }
}

impl From<Context<StateErrorKind>> for StateError {
    fn from(context: Context<StateErrorKind>) -> Self {
        StateError(Box::new(context))
    }
}

impl Display for StateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for StateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}
