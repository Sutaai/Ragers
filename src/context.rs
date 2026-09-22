use std::cell::RefCell;

use crate::cli::Cli;
use crate::config::{RawConfig, RecipientsFactory};
use crate::error::CmdError;

pub struct Context<'config> {
    pub cli: Cli,
    pub config: &'config RawConfig,
    pub recipients_factory: RecipientsFactory<'config>,
    pub stdin_guard: RefCell<age::cli_common::StdinGuard>,
}

impl<'config> Context<'config> {
    pub fn new(cli: Cli, config: &'config RawConfig) -> Result<Self, CmdError> {
        let recipients_factory = RecipientsFactory::new(&config.recipients);

        Ok(Self {
            cli,
            config,
            recipients_factory,
            stdin_guard: RefCell::new(age::cli_common::StdinGuard::new(false)),
        })
    }

    pub fn get_identities(
        &self,
    ) -> Result<Vec<Box<dyn age::Identity>>, age::cli_common::ReadError> {
        let mut stdin_guard = age::cli_common::StdinGuard::new(true);

        let dyn_identities = age::cli_common::read_identities(
            self.cli
                .identities_file
                .iter()
                .map(|item| {
                    item.to_str()
                        .expect("path must be turned to string")
                        .to_owned()
                })
                .collect::<Vec<String>>(),
            None,
            &mut stdin_guard,
        )?;

        Ok(dyn_identities)
    }
}
