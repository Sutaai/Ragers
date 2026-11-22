use std::cell::RefCell;

use crate::cli::Cli;
use crate::error::CmdError;
use ragers_core::config::{ConfigFile, RecipientsFactory};

pub struct Context<'config> {
    pub cli: Cli,
    pub config: &'config ConfigFile,
    pub recipients_factory: RecipientsFactory<'config>,
    pub stdin_guard: RefCell<age::cli_common::StdinGuard>,
}

impl<'config> Context<'config> {
    pub fn new(cli: Cli, config: &'config ConfigFile) -> Result<Self, CmdError> {
        let recipients_factory = RecipientsFactory::new(config);

        Ok(Self {
            cli,
            config,
            recipients_factory,
            stdin_guard: RefCell::new(age::cli_common::StdinGuard::new(false)),
        })
    }
}
