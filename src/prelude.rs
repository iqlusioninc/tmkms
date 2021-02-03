//! Application-local prelude: conveniently import types/functions/macros
//! which are generally useful and should be available everywhere.

/// Abscissa core prelude
pub use abscissa_core::prelude::*;

/// Status macros
pub use abscissa_core::{status_attr_err, status_attr_ok};

/// Application state
pub use crate::application::APP;
