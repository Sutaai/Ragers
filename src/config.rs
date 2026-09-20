use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    rc::Rc
};

use age::cli_common::read_recipients;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{
    error::{
        ConfigError, ConfigValidationError, NotFound, RecipientsFactoryError,
    },
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

/// Struct representation of recipients definition in the config file. Part of [`RawConfig`].
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
/// [`RawConfig`].
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
    /// Creates a new instance of [`RawConfig`] by reading the file at [`config_path`].
    ///
    /// This function will read the path it is given and attempt to deserialize it through their
    /// structs representation.
    pub fn new(config_path: &Path) -> Result<Self, ConfigError> {
        let builder = config::Config::builder()
            .add_source(config::File::from(config_path))
            .build()?;

        match builder.try_deserialize() {
            Ok(config) => {
                log::debug!("Config was deserialized, validating...");

                match ConfigValidator.validate(&config) {
                    Ok(_) => Ok(config),
                    Err(mut errs) => {
                        log::error!("Config failed validation");
                        let one_err = errs.pop().unwrap();
                        Err(ConfigError::from(one_err))
                    }
                }
            }
            Err(err) => {
                log::error!("Config failed to deserialize");
                Err(ConfigError::from(err))
            }
        }
    }
}

/// Type that must be returned by each validating functions in `ConfigValidator`.
type ConfCheckResult = Result<(), ConfigValidationError>;

/// Struct aiming to validate [`RawConfig`] values.
///
/// The [`ConfigValidator`] aims to validate a given [`RawConfig`] through the
/// [`ConfigValidator::validate.`] function to ensure the file is valid and will not prompt any error
/// during the program's execution.
///
/// Thus, once validated, it should be safe to use [`RawConfig`] and references made in it should be
/// safe.
pub struct ConfigValidator;

impl ConfigValidator {
    pub fn validate(self, config: &RawConfig) -> Result<(), Vec<ConfigValidationError>> {
        let mut all_errors: Vec<ConfigValidationError> = Vec::new();

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
            log::trace!("Config passed validation");
            Ok(())
        } else {
            log::debug!("Validation errors: {:?}", all_errors);
            Err(all_errors)
        }
    }

    fn check_recipients_age_valid(&self, config: &RawConfig) -> ConfCheckResult {
        log::trace!("Checking if all recipients are valid");

        let mut fake_guard = age::cli_common::StdinGuard::new(false);
        let recipients = &config.recipients.direct;
        let recipients_factory = RecipientsFactory::new(&config.recipients);

        for (alias, raw_recipient) in recipients {
            match recipients_factory.get_or_store_recipient(raw_recipient, &mut fake_guard) {
                Ok(_) => {}
                Err(err) => {
                    return Err(ConfigValidationError::InvalidRecipient {
                        key: alias.to_owned(),
                        parse_error: err,
                    });
                }
            };
        }

        log::trace!("Check complete");
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

        log::trace!("Check complete");
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

        log::trace!("Check complete");
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

        log::trace!("Check complete");
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

        log::trace!("Check complete");
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

        log::trace!("Check complete");
        Ok(())
    }

    fn check_files_valid_recipients(&self, config: &RawConfig) -> ConfCheckResult {
        log::trace!("Checking files recipients are valid");

        let recipients_factory = RecipientsFactory::new(&config.recipients);
        let mut fake_guard = age::cli_common::StdinGuard::new(false);

        for (index, file) in config.files.iter().enumerate() {
            for unparsed_recipient in &file.recipients {
                match recipients_factory.obtain_for_alias(unparsed_recipient, &mut fake_guard) {
                    Ok(_) => {}
                    Err(_) => {
                        return Err(ConfigValidationError::FileAliasNotFound {
                            index,
                            alias: unparsed_recipient.to_owned(),
                        });
                    }
                };
            }
        }

        log::trace!("Check complete");
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

        log::trace!("Check complete");
        Ok(())
    }
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
    let mut parsed_recipients: Vec<String> = Vec::new();

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

/// The [`RecipientsFactory`] implement logic for looking up recipients and returning their
/// according [`age::Recipient`] struct.
///
/// [`RecipientsFactory`] is the entrypoint for managing recipients in all kind of ways throughout
/// the application's lifetime, mostly handling parsing and caching.
///
/// Caching is done to avoid re-parsing a known recipient that has already been parsed.
/// The cache has an infinite longevity and none of its element ever dies. This is an
/// assumed implementation as it is assumed the impact is not severe enough in the usage of the
/// tool to be an issue.
pub struct RecipientsFactory<'config> {
    /// Recipients part of the config file.
    config_recipients: &'config RawConfigRecipients,
    /// Cache containing age direct recipients. Key: age recipient as string.
    /// Value: struct [`age::Recipient`]
    age_recipients_cache: RefCell<HashMap<String, Rc<dyn age::Recipient>>>,
}

impl<'config> RecipientsFactory<'config> {
    /// Return a new instance of [`RecipientsFactory`].
    pub fn new(recipients: &'config RawConfigRecipients) -> Self {
        Self {
            config_recipients: recipients,
            age_recipients_cache: RefCell::new(HashMap::new()),
        }
    }

    fn get_or_store_recipient(
        &self,
        age_recipient_str: &str,
        stdin_guard: &mut age::cli_common::StdinGuard,
    ) -> Result<Rc<dyn age::Recipient>, age::cli_common::ReadError> {
        let mut cache = self.age_recipients_cache.borrow_mut();

        if !cache.contains_key(age_recipient_str) {
            log::debug!("Recipient \"{age_recipient_str}\" is not cached, parsing");

            let parsed_recipient =
                read_recipients(vec![age_recipient_str.to_owned()], vec![], vec![], None, stdin_guard)
                    .unwrap()
                    .remove(0);
            let rc_recipient: Rc<dyn age::Recipient + Send> = Rc::from(parsed_recipient);

            cache.insert(age_recipient_str.to_owned(), rc_recipient);
        }

        log::trace!("Obtaining recipient struct for \"{age_recipient_str}\"");
        let age_recipient = Rc::clone(cache.get(age_recipient_str).unwrap_or_else(|| {
            panic!("expected {age_recipient_str} to exist in factory cache, but nothing was found")
        }));

        Ok(age_recipient)
    }

    fn direct_recipient(
        &self,
        config_key: &str,
        stdin_guard: &mut age::cli_common::StdinGuard,
    ) -> Result<Rc<dyn age::Recipient>, RecipientsFactoryError> {
        let age_recipient_str = self
            .config_recipients
            .direct
            .get(config_key)
            .ok_or_else(|| NotFound(config_key.to_owned()))?;

        let age_recipient = self.get_or_store_recipient(age_recipient_str, stdin_guard)?;

        Ok(age_recipient)
    }

    fn group(
        &self,
        config_key: &str,
        stdin_guard: &mut age::cli_common::StdinGuard,
    ) -> Result<Vec<Rc<dyn age::Recipient>>, RecipientsFactoryError> {
        let mut parsed_recipients = Vec::new();

        let group = self
            .config_recipients
            .groups
            .get(config_key)
            .ok_or_else(|| NotFound(config_key.to_owned()))?;

        for recipient_reference_key in group {
            let recipient = self.direct_recipient(recipient_reference_key, stdin_guard)?;
            parsed_recipients.push(recipient);
        }

        Ok(parsed_recipients)
    }

    fn file(
        &self,
        config_key: &str,
        stdin_guard: &mut age::cli_common::StdinGuard,
    ) -> Result<Vec<Rc<dyn age::Recipient>>, RecipientsFactoryError> {
        let mut parsed_recipients = Vec::new();

        let file_path = self
            .config_recipients
            .files
            .get(config_key)
            .ok_or_else(|| NotFound(config_key.to_owned()))?;

        let file_content = read_recipients_file(file_path)?;

        for age_recipient_str in &file_content {
            let recipient = self.get_or_store_recipient(age_recipient_str, stdin_guard)?;
            parsed_recipients.push(recipient);
        }

        Ok(parsed_recipients)
    }

    pub fn obtain_for_alias(
        &self,
        alias: &str,
        stdin_guard: &mut age::cli_common::StdinGuard,
    ) -> Result<Vec<Rc<dyn age::Recipient>>, RecipientsFactoryError> {
        let recipients = match get_alias_kind(alias) {
            AliasKind::Group(key) => self.group(&key, stdin_guard)?,
            AliasKind::RecipientsFile(key) => self.file(&key, stdin_guard)?,
            AliasKind::DirectRecipient(key) => {
                let recipient = self.direct_recipient(&key, stdin_guard)?;
                vec![recipient]
            }
        };

        Ok(recipients)
    }

    pub fn obtain_for_file(
        &self,
        config_file: &RawConfigFile,
        stdin_guard: &mut age::cli_common::StdinGuard,
    ) -> Result<Vec<Rc<dyn age::Recipient>>, RecipientsFactoryError> {
        let mut fetched_recipients = Vec::new();

        for alias in &config_file.recipients {
            let recipients = self.obtain_for_alias(alias, stdin_guard)?;
            fetched_recipients.extend(recipients);
        }

        Ok(fetched_recipients)
    }
}

pub struct IdentitiesFactory {
    identities_cache: RefCell<HashMap<String, Box<dyn age::Identity>>>,
}

impl IdentitiesFactory {
    pub fn obtain_for_identity(&self) {}

    pub fn obtain_from_file(&self) {}
}
