use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

use log::warn;

use crate::cli::Cli;
use crate::config::{Config, RecipientParsed, parse_age_recipient};
use crate::error::CmdError;

pub struct Context {
    pub cli: Cli,
    pub config: Config,
}

impl Context {
    pub fn new(cli: Cli) -> Result<Self, CmdError> {
        // TODO: WEWY BAWD
        let config = Config::new(&cli.config).map_err(|op| CmdError::Config(op))?;

        Ok(Self { cli, config })
    }
}

pub struct AgeRecipientsCache {
    recipients: HashMap<String, Rc<dyn age::Recipient>>,
}

impl AgeRecipientsCache {
    pub fn new() -> Self {
        Self {
            recipients: HashMap::new(),
        }
    }

    /// Obtain the age's Recipient struct from an age recipient's public key string.
    ///
    /// This method will cache the converted recipient. This is the way to obtain an
    /// `age::Recipient` from its corresponding string.
    pub fn obtain(&mut self, age_key_str: &str) -> &Rc<dyn age::Recipient> {
        self.recipients
            .entry(age_key_str.to_owned())
            .or_insert_with(|| {
                match parse_age_recipient(age_key_str).expect(&format!(
                    "could not parse age key \"{age_key_str}\", unexpected pre-condition"
                )) {
                    RecipientParsed::X25519(recipient) => Rc::new(recipient),
                    RecipientParsed::SSH(recipient) => Rc::new(recipient),
                }
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
