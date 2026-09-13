use std::path::PathBuf;

use log::warn;

use crate::cli::Cli;
use crate::config::{RawConfig, RecipientsFactory};
use crate::error::CmdError;

pub struct Context<'config> {
    pub cli: Cli,
    pub config: &'config RawConfig,
    pub recipients_factory: RecipientsFactory<'config>,
}

impl<'config> Context<'config> {
    pub fn new(cli: Cli, config: &'config RawConfig) -> Result<Self, CmdError> {
        let recipients_factory = RecipientsFactory::new(&config.recipients);

        Ok(Self {
            cli,
            config,
            recipients_factory,
        })
    }
}

/// Load age identities (private keys) provided directly as raw string values, rather than
/// from a file on disk. Intended for use with values sourced from an environment variable
/// or passed directly as a CLI argument.
///
/// Each value is expected to contain either one or more age identities (`AGE-SECRET-KEY-1...`
/// lines), or a single SSH private key. Both formats are attempted for every value.
pub fn load_identities_from_values(raw_identities: &[String]) -> Vec<Box<dyn age::Identity>> {
    let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();

    for (index, value) in raw_identities.iter().enumerate() {
        let label = format!("identity value #{}", index + 1);

        match age::IdentityFile::from_buffer(value.as_bytes()) {
            Ok(identity_file) => {
                let parsed = identity_file
                    .into_identities()
                    .expect(&format!("could not parse age identities from {label}"));
                identities.extend(parsed);
            }
            Err(_) => {
                match age::ssh::Identity::from_buffer(value.as_bytes(), Some(label.clone())) {
                    Ok(age::ssh::Identity::Unsupported(_)) => {
                        warn!("{label} contains an unsupported SSH key type, ignoring");
                    }
                    Ok(identity) => identities.push(Box::new(identity)),
                    Err(err) => {
                        panic!("could not parse {label} as an age or SSH identity: {err:?}")
                    }
                }
            }
        }
    }

    identities
}

pub fn load_identities(identities_paths: &[PathBuf]) -> Vec<Box<dyn age::Identity>> {
    let mut identities: Vec<Box<dyn age::Identity>> = Vec::new();

    for path in identities_paths {
        match age::IdentityFile::from_file(path.to_string_lossy().into_owned()) {
            Ok(identity_file) => {
                let parsed = identity_file.into_identities().expect(&format!(
                    "could not parse age identities from file \"{}\"",
                    path.display()
                ));
                identities.extend(parsed);
            }
            Err(_) => {
                let content = std::fs::read_to_string(path).expect(&format!(
                    "could not read identity file \"{}\"",
                    path.display()
                ));

                match age::ssh::Identity::from_buffer(
                    content.as_bytes(),
                    Some(path.display().to_string()),
                ) {
                    Ok(age::ssh::Identity::Unsupported(_)) => {
                        warn!(
                            "identity file \"{}\" contains an unsupported SSH key type, ignoring",
                            path.display()
                        );
                    }
                    Ok(identity) => identities.push(Box::new(identity)),
                    Err(err) => panic!(
                        "could not parse \"{}\" as an age or SSH identity: {err:?}",
                        path.display()
                    ),
                }
            }
        }
    }

    identities
}
