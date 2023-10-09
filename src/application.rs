//! Abscissa `Application` for the KMS

use crate::{commands::KmsCommand, config::KmsConfig};
use abscissa_core::{
    application::{self, AppCell},
    config::{self, CfgCell},
    trace, Application, FrameworkError, StandardPaths,
};

/// Application state
pub static APP: AppCell<KmsApplication> = AppCell::new();

/// The `tmkms` application
#[derive(Debug, Default)]
pub struct KmsApplication {
    /// Application configuration.
    config: CfgCell<KmsConfig>,

    /// Application state.
    state: application::State<Self>,
}

impl Application for KmsApplication {
    /// Entrypoint command for this application.
    type Cmd = KmsCommand;

    /// Application configuration.
    type Cfg = KmsConfig;

    /// Paths to resources within the application.
    type Paths = StandardPaths;

    /// Accessor for application configuration.
    fn config(&self) -> config::Reader<KmsConfig> {
        self.config.read()
    }

    /// Borrow the application state immutably.
    fn state(&self) -> &application::State<Self> {
        &self.state
    }

    /// Register all components used by this application.
    ///
    /// If you would like to add additional components to your application
    /// beyond the default ones provided by the framework, this is the place
    /// to do so.
    fn register_components(&mut self, command: &Self::Cmd) -> Result<(), FrameworkError> {
        let components = self.framework_components(command)?;
        let mut component_registry = self.state.components_mut();
        component_registry.register(components)
    }

    /// Post-configuration lifecycle callback.
    ///
    /// Called regardless of whether config is loaded to indicate this is the
    /// time in app lifecycle when configuration would be loaded if
    /// possible.
    fn after_config(&mut self, config: Self::Cfg) -> Result<(), FrameworkError> {
        let mut component_registry = self.state.components_mut();
        component_registry.after_config(&config)?;
        self.config.set_once(config);
        Ok(())
    }

    /// Get tracing configuration from command-line options
    fn tracing_config(&self, command: &KmsCommand) -> trace::Config {
        if command.verbose() {
            trace::Config::verbose()
        } else {
            trace::Config::default()
        }
    }
}
