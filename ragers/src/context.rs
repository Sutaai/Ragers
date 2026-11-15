use std::cell::RefCell;
use std::path::PathBuf;

use crate::cli::Cli;
use crate::config::{RawConfig, RecipientsFactory};
use crate::error::CmdError;

pub struct Context<'config> {
    pub cli: Cli,
    pub config: &'config RawConfig,
    pub config_path: PathBuf,
    pub recipients_factory: RecipientsFactory<'config>,
    pub stdin_guard: RefCell<age::cli_common::StdinGuard>,
}

impl<'config> Context<'config> {
    pub fn new(
        cli: Cli,
        config: &'config RawConfig,
        config_path: PathBuf,
    ) -> Result<Self, CmdError> {
        let recipients_factory = RecipientsFactory::new(&config_path, &config.recipients);

        Ok(Self {
            cli,
            config,
            config_path,
            recipients_factory,
            stdin_guard: RefCell::new(age::cli_common::StdinGuard::new(false)),
        })
    }
}
