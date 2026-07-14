use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    str::FromStr,
};

use itertools::Itertools;
use log::{debug, error, info, trace};
use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, ConfigValidationError, NotFound, RecipientParseError};

type ConfigGroups = HashMap<String, Vec<String>>;
type ConfigDirectRecipients = HashMap<String, String>;
type ConfigFiles = HashMap<String, PathBuf>;

#[derive(Serialize, Deserialize, Debug)]
pub struct ConfigRecipients {
    /// A list of recipients that may be used to encrypt and/or decrypt files
    #[serde(flatten, rename = "recipients")]
    pub direct: ConfigDirectRecipients,
    /// A list of recipients files. These files holds a list of public keys.
    #[serde(default)]
    pub files: ConfigFiles,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ConfigFile {
    /// The path of the unencrypted file source
    pub src: PathBuf,
    /// The path to the encrypted file output
    pub out: PathBuf,
    /// The recipients of the file
    pub recipients: Vec<String>,
    /// Should this file be armored?
    #[serde(default)]
    pub armor: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    /// A list of pre-defined recipients
    pub recipients: ConfigRecipients,
    /// A list of groups
    #[serde(default)]
    pub groups: ConfigGroups,
    /// A list of files to encrypt
    #[serde(default)]
    pub files: Vec<ConfigFile>,
}

impl Config {
    pub fn new(config_path: &Path) -> Result<Self, ConfigError> {
        let builder = config::Config::builder()
            .add_source(config::File::from(config_path))
            .build()?;

        match builder.try_deserialize() {
            Ok(config) => {
                debug!("Config was deserialized, validating...");
                match ConfigValidator.validate(&config) {
                    Ok(_) => return Ok(config),
                    Err(mut errs) => {
                        error!("Config failed validation");
                        let one_err = errs.pop().unwrap();
                        return Err(ConfigError::from(one_err));
                    }
                };
            }
            Err(err) => {
                error!("Config failed to deserialize");
                Err(ConfigError::from(err))
            }
        }
    }

    /// Get a recipient from the list of direct recipients, or fail.
    fn get_direct_recipient(&self, key: &str) -> Result<&str, NotFound> {
        trace!("Obtaining {key} as direct recipient");
        let recipient = self
            .recipients
            .direct
            .get(key)
            .ok_or_else(|| NotFound(key.to_owned()))?;

        Ok(recipient)
    }

    /// Get a recipients file, or fail.
    fn get_recipients_file(&self, key: &str) -> Result<&PathBuf, NotFound> {
        trace!("Obtaining {key} as recipients file");
        let recipient = self
            .recipients
            .files
            .get(key)
            .ok_or_else(|| NotFound(key.to_owned()))?;

        Ok(recipient)
    }

    /// Get a group, or fail.
    fn get_group(&self, key: &str) -> Result<&Vec<String>, NotFound> {
        trace!("Obtaining {key} as group");
        let recipient = self
            .groups
            .get(key)
            .ok_or_else(|| NotFound(key.to_owned()))?;

        Ok(recipient)
    }

    /// Get all recipients from an alias.
    ///
    /// This function will lookup the given alias to return all age recipients public key it is
    /// assicuated. Only the string representation of the age recipient is returned, it remains to
    /// be converted into its struct representation.
    pub fn get_age_recipients_str_from_alias(&self, alias: &str) -> Result<Vec<String>, NotFound> {
        // Must be owned because we're reading from recipients files
        let mut recipients: Vec<String> = Vec::new();

        match get_alias_kind(alias) {
            AliasKind::Group(key) => {
                let group = self.get_group(&key)?;
                for alias in group {
                    trace!("From alias \"{alias}\", getting recipient and pushing");
                    let recipient = self.get_direct_recipient(&alias)?;
                    recipients.push(recipient.to_owned());
                }
            }
            AliasKind::RecipientsFile(key) => {
                let file_path = self.get_recipients_file(&key)?;
                let recipients_from_file = read_recipients_file(file_path)
                    .expect(&format!("could not open file: \"{}\"", file_path.display()));
                recipients.extend(recipients_from_file);
            }
            AliasKind::DirectRecipient(key) => {
                let recipient_key = self.get_direct_recipient(&key)?;
                recipients.push(recipient_key.to_owned());
            }
        }

        Ok(recipients)
    }
}

type ConfCheckResult = Result<(), ConfigValidationError>;
pub struct ConfigValidator;

impl ConfigValidator {
    pub fn validate(self, config: &Config) -> Result<(), Vec<ConfigValidationError>> {
        let mut all_errors: Vec<ConfigValidationError> = vec![];

        for check in [
            self.check_recipients_age_valid(config),
            self.check_recipients_value_unique(config),
            self.check_recipients_file_valid_path(config),
            self.check_groups_valid_users(config),
            self.check_files_unique_source(config),
            self.check_files_unique_destination(config),
            self.check_files_valid_recipients(config),
            self.check_files_recipients_unique(config),
        ] {
            match check {
                Ok(_) => {}
                Err(err) => all_errors.push(err),
            }
        }

        if all_errors.is_empty() {
            Ok(())
        } else {
            Err(all_errors)
        }
    }

    fn check_recipients_age_valid(&self, config: &Config) -> ConfCheckResult {
        let recipients = &config.recipients.direct;

        for (alias, raw_recipient) in recipients {
            match parse_age_recipient(raw_recipient) {
                Ok(_) => {}
                Err(err) => {
                    return Err(ConfigValidationError::InvalidRecipient {
                        key: alias.to_owned(),
                        parse_error: err,
                    });
                }
            };
        }

        Ok(())
    }

    fn check_recipients_value_unique(&self, config: &Config) -> ConfCheckResult {
        let recipients = &config.recipients.direct;
        let mut seen: HashSet<&String> = HashSet::new();

        for recipient in recipients.values() {
            if !seen.insert(recipient) {
                return Err(ConfigValidationError::DuplicatedRecipient {
                    value: recipient.to_owned(),
                });
            }
        }

        Ok(())
    }

    fn check_recipients_file_valid_path(&self, config: &Config) -> ConfCheckResult {
        let files = &config.recipients.files;

        for (alias, path) in files {
            if !path.exists() {
                return Err(ConfigValidationError::RecipientsFileNotFound {
                    key: alias.to_owned(),
                    path: path
                        .to_str()
                        .expect("Could not convert path to str")
                        .to_owned(),
                });
            }
        }

        Ok(())
    }

    fn check_groups_valid_users(&self, config: &Config) -> ConfCheckResult {
        let groups = &config.groups;
        let recipients: &Vec<&String> = &config.recipients.direct.keys().collect();

        for (group, members) in groups {
            for member in members {
                if !recipients.contains(&member) {
                    return Err(ConfigValidationError::RecipientInGroupNotFound {
                        group: group.to_owned(),
                        alias: member.to_owned(),
                    });
                }
            }
        }

        Ok(())
    }

    fn check_files_unique_source(&self, config: &Config) -> ConfCheckResult {
        let files = &config.files;
        let mut seen: HashSet<&PathBuf> = HashSet::new();

        for (index, file) in files.iter().enumerate() {
            if !seen.insert(&file.src) {
                return Err(ConfigValidationError::FileDuplicatedSource {
                    index,
                    path: file.src.clone(),
                });
            }
        }

        Ok(())
    }

    fn check_files_unique_destination(&self, config: &Config) -> ConfCheckResult {
        let files = &config.files;
        let mut seen: HashSet<&PathBuf> = HashSet::new();

        for (index, file) in files.iter().enumerate() {
            if !seen.insert(&file.out) {
                return Err(ConfigValidationError::FileDuplicatedDestination {
                    index,
                    path: file.out.clone(),
                });
            }
        }

        Ok(())
    }

    fn check_files_valid_recipients(&self, config: &Config) -> ConfCheckResult {
        for (index, file) in config.files.iter().enumerate() {
            for unparsed_recipient in &file.recipients {
                match get_alias_kind(unparsed_recipient) {
                    AliasKind::DirectRecipient(recipient) => {
                        if config.get_direct_recipient(&recipient).is_err() {
                            return Err(ConfigValidationError::FileAliasNotFound {
                                index,
                                alias: unparsed_recipient.to_owned(),
                            });
                        }
                    }
                    AliasKind::Group(group) => {
                        if config.get_group(&group).is_err() {
                            return Err(ConfigValidationError::FileAliasNotFound {
                                index,
                                alias: unparsed_recipient.to_owned(),
                            });
                        }
                    }
                    AliasKind::RecipientsFile(file) => {
                        if config.get_recipients_file(&file).is_err() {
                            return Err(ConfigValidationError::FileAliasNotFound {
                                index,
                                alias: unparsed_recipient.to_owned(),
                            });
                        }
                    }
                };
            }
        }
        Ok(())
    }

    fn check_files_recipients_unique(&self, config: &Config) -> ConfCheckResult {
        for (index, file) in config.files.iter().enumerate() {
            let mut recipients: Vec<&String> =
                file.recipients.iter().duplicates().dedup().collect();
            if !recipients.is_empty() {
                let first = recipients.swap_remove(0);
                return Err(ConfigValidationError::FileAliasDuplicated {
                    index,
                    alias: first.to_owned(),
                });
            }
        }

        Ok(())
    }
}

/// Enum of parsed age recipients. Supported recipients only.
pub(crate) enum RecipientParsed {
    X25519(age::x25519::Recipient),
    SSH(age::ssh::Recipient),
}

/// Parse a raw string age recipient. Obtains the age recipient struct.
pub(crate) fn parse_age_recipient(
    age_key_str: &str,
) -> Result<RecipientParsed, RecipientParseError> {
    if let Ok(recipient) = age::x25519::Recipient::from_str(age_key_str) {
        return Ok(RecipientParsed::X25519(recipient));
    };

    match age_key_str.parse::<age::ssh::Recipient>() {
        Ok(key) => return Ok(RecipientParsed::SSH(key)),
        Err(age::ssh::ParseRecipientKeyError::Ignore) => {
            info!("SSH key has been ignored");
            // I wonder what we should do here...
        }
        Err(age::ssh::ParseRecipientKeyError::Invalid(_)) => {
            debug!("SSH key was invalid, ignored (Would have raised error)");
            // Silently ignore
        }
        Err(err) => {
            return Err(RecipientParseError::SSH(err));
        }
    }

    debug!("Did not match any key format");
    Err(RecipientParseError::Invalid)
}

/// Indicate what kind of alias this is refering to.
///
/// The value will be the either the key it refers to for recipients files or groups, or the public
/// key for direct recipients.
pub enum AliasKind {
    DirectRecipient(String),
    RecipientsFile(String),
    Group(String),
}

pub fn get_alias_kind(alias: &str) -> AliasKind {
    if let Some(stripped) = alias.strip_prefix("file:") {
        AliasKind::RecipientsFile(stripped.to_owned())
    } else if let Some(stripped) = alias.strip_prefix("group:") {
        AliasKind::Group(stripped.to_owned())
    } else {
        AliasKind::DirectRecipient(alias.to_owned())
    }
}

/// Convert a recipients file to a list of recipients.
///
/// This function will convert a recipients file by reading it to a list of supported
/// recipients that may be used.
fn read_recipients_file(file: &PathBuf) -> Result<Vec<String>, std::io::Error> {
    let mut parsed_recipients: Vec<String> = vec![];

    let content = std::fs::read_to_string(file)?;
    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with("#") {
            continue;
        }

        parsed_recipients.push(line.to_owned());
    }

    Ok(parsed_recipients)
}
