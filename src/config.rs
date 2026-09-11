use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    rc::Rc,
    str::FromStr,
};

use itertools::Itertools;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};

use crate::error::{
    ConfigError, ConfigValidationError, NotFound, RecipientParseError, RecipientsFactoryError,
};

/// Struct representation of the Ragers config file. Used for deserialization. 
#[derive(Serialize, Deserialize, Debug)]
pub struct RawConfig {
    /// A list of pre-defined recipients
    pub recipients: RawConfigRecipients,
    /// A list of files to encrypt
    #[serde(default)]
    pub files: Vec<RawConfigFile>,
}

/// Struct representation of recipients definition in the config file. Part of `RawConfig`.
#[derive(Serialize, Deserialize, Debug)]
pub struct RawConfigRecipients {
    /// A list of recipients that may be used to encrypt and/or decrypt files
    #[serde(flatten, rename = "recipients")]
    pub direct: HashMap<String, String>,
    /// A list of groups
    #[serde(default)]
    pub groups: HashMap<String, Vec<String>>,
    /// A list of recipients files. These files holds a list of public keys.
    #[serde(default)]
    pub files: HashMap<String, PathBuf>,
}

/// Struct representation of files (to encrypt/decrypt) definition in the config file. Part of
/// `RawConfig`.
#[derive(Serialize, Deserialize, Debug)]
pub struct RawConfigFile {
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

impl RawConfig {
    /// Creates a new instance of `RawConfig` by reading the file at `config_path`.
    /// 
    /// This function will read the path it is given and attempt to deserialize it through their
    /// structs representation.
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
}

/// Type that must be returned by each validating functions in `ConfigValidator`.
type ConfCheckResult = Result<(), ConfigValidationError>;

/// Struct aiming to validate `RawConfig` values.
/// 
/// The `ConfigValidator` aims to validate a given `RawConfig` through the
/// `ConfigValidator::validate` function to ensure the file is valid and will not prompt any error
/// during the program's execution.
/// 
/// Thus, once validated, it should be safe to use `RawConfig` and references made in it should be
/// safe.
pub struct ConfigValidator;

impl ConfigValidator {
    pub fn validate(self, config: &RawConfig) -> Result<(), Vec<ConfigValidationError>> {
        let mut all_errors: Vec<ConfigValidationError> = vec![];

        for check in [
            self.check_recipients_age_valid(config),
            self.check_recipients_value_unique(config),
            self.check_recipients_file_valid_path(config),
            self.check_groups_valid_recipients(config),
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

    fn check_recipients_age_valid(&self, config: &RawConfig) -> ConfCheckResult {
        log::trace!("Checking if all recipients are valid");

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

    fn check_recipients_value_unique(&self, config: &RawConfig) -> ConfCheckResult {
        log::trace!("Checking recipients are unique");

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

    fn check_recipients_file_valid_path(&self, config: &RawConfig) -> ConfCheckResult {
        log::trace!("Checking recipients files are valid");

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

    fn check_groups_valid_recipients(&self, config: &RawConfig) -> ConfCheckResult {
        log::trace!("Checking groups contain valid recipients");

        let groups = &config.recipients.groups;
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

    fn check_files_unique_source(&self, config: &RawConfig) -> ConfCheckResult {
        log::trace!("Checking recipients files source are unique");

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

    fn check_files_unique_destination(&self, config: &RawConfig) -> ConfCheckResult {
        log::trace!("Checking files destination are unique");

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

    fn check_files_valid_recipients(&self, config: &RawConfig) -> ConfCheckResult {
        log::trace!("Checking files recipients are valid");

        let mut recipients_factory = RecipientsFactory::new(&config.recipients);

        for (index, file) in config.files.iter().enumerate() {
            for unparsed_recipient in &file.recipients {
                match recipients_factory.obtain_from_alias(unparsed_recipient) {
                    Ok(_) => {},
                    Err(_) => {
                        return Err(ConfigValidationError::FileAliasNotFound {
                            index,
                            alias: unparsed_recipient.to_owned(),
                        });
                    }
                };
            };
        }
        Ok(())
    }

    fn check_files_recipients_unique(&self, config: &RawConfig) -> ConfCheckResult {
        log::trace!("Checking files recipients are unique");

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

fn get_alias_kind(alias: &str) -> AliasKind {
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

/// The `RecipientsFactory` implement logic for looking up recipients and returning their
/// according `age::Recipient` struct.
///
/// `RecipientsFactory` is the entrypoint for managing recipients in all kind of ways throughout
/// the application's lifetime, mostly handling parsing and caching.
///
/// Caching is done to avoid re-parsing a known recipient that has already been parsed.
/// The cache has an infinite longevity and none of its element ever dies. This is an
/// assumed implementation as it is assumed the impact is not severe enough in the usage of the
/// tool to be an issue.
pub struct RecipientsFactory<'config> {
    /// Recipients part of the config file.
    config_recipients: &'config RawConfigRecipients,
    /// Cache containing age recipients. Key: age recipient as string.
    /// Value: struct age::Recipient
    direct_recipients_cache: HashMap<String, Rc<dyn age::Recipient>>,
}

impl<'config> RecipientsFactory<'config> {
    /// Return a new instance of `RecipientsFactory`.
    pub fn new(recipients: &'config RawConfigRecipients) -> Self {
        Self {
            config_recipients: recipients,
            direct_recipients_cache: HashMap::new(),
        }
    }

    fn direct_recipient(
        &mut self,
        config_key: &str,
    ) -> Result<&Rc<dyn age::Recipient>, RecipientsFactoryError> {
        let age_recipient_str = self
            .config_recipients
            .direct
            .get(config_key)
            .ok_or_else(|| NotFound(config_key.to_owned()))?;

        if !self.direct_recipients_cache.contains_key(age_recipient_str) {
            log::debug!("{age_recipient_str} is not cached, parsing");

            let struct_recipient: Rc<dyn age::Recipient> =
                match parse_age_recipient(age_recipient_str)? {
                    RecipientParsed::X25519(recipient) => Rc::new(recipient),
                    RecipientParsed::SSH(recipient) => Rc::new(recipient),
                };

            self.direct_recipients_cache
                .insert(age_recipient_str.to_owned(), struct_recipient);
        }

        log::trace!("Fetching {age_recipient_str}");

        let age_recipient = self
            .direct_recipients_cache
            .get(age_recipient_str)
            .expect(&format!(
                "expected {age_recipient_str} to exist in factory cache, but nothing was found"
            ));

        Ok(age_recipient)
    }

    fn group(
        &mut self,
        config_key: &str,
    ) -> Result<Vec<Rc<dyn age::Recipient>>, RecipientsFactoryError> {
        let mut parsed_recipients = vec![];

        let group = self
            .config_recipients
            .groups
            .get(config_key)
            .ok_or_else(|| NotFound(config_key.to_owned()))?;

        for recipient_reference_key in group {
            let recipient = self.direct_recipient(recipient_reference_key)?;
            parsed_recipients.push(Rc::clone(recipient));
        }

        Ok(parsed_recipients)
    }

    fn file(
        &mut self,
        config_key: &str,
    ) -> Result<Vec<Rc<dyn age::Recipient>>, RecipientsFactoryError> {
        let mut parsed_recipients = vec![];

        let file_path = self
            .config_recipients
            .files
            .get(config_key)
            .ok_or_else(|| NotFound(config_key.to_owned()))?;

        let file_content = read_recipients_file(file_path)?;

        for recipient_str in file_content {
            let recipient = self.direct_recipient(&recipient_str)?;
            parsed_recipients.push(Rc::clone(recipient));
        }

        Ok(parsed_recipients)
    }

    pub fn obtain_from_alias(
        &mut self,
        alias: &str,
    ) -> Result<Vec<Rc<dyn age::Recipient>>, RecipientsFactoryError> {
        let recipients = match get_alias_kind(alias) {
            AliasKind::Group(key) => self.group(&key)?,
            AliasKind::RecipientsFile(key) => self.file(&key)?,
            AliasKind::DirectRecipient(key) => {
                let recipient = self.direct_recipient(&key)?;
                vec![Rc::clone(recipient)]
            }
        };

        Ok(recipients)
    }

    pub fn obtain_for_file(
        &mut self,
        config_file: &RawConfigFile,
    ) -> Result<Vec<Rc<dyn age::Recipient>>, RecipientsFactoryError> {
        let mut fetched_recipients = vec![];

        for alias in &config_file.recipients {
            let recipients = self.obtain_from_alias(alias)?;
            fetched_recipients.extend(recipients);
        }

        Ok(fetched_recipients)
    }
}
