use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use age::cli_common::read_recipients;
use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, NotFound, RecipientsFactoryError};

/// Struct representation of the Ragers config file. Used for deserialization.
#[derive(Serialize, Deserialize)]
pub struct RawConfig {
    /// A list of pre-defined recipients
    pub recipients: RawConfigRecipients,
    /// A list of files to encrypt
    #[serde(default)]
    pub files: Vec<RawConfigFile>,
}

impl RawConfig {
    /// Creates a new instance of [`RawConfig`] by reading the file at `config_path`.
    ///
    /// This function will read the path it is given and attempt to deserialize it through their
    /// structs representation.
    pub fn new(config_path: &Path) -> Result<Self, ConfigError> {
        let builder = config::Config::builder().add_source(config::File::from(config_path));

        builder.build()?.try_deserialize().map_err(|err| err.into())
    }
}

/// Struct representation of recipients definition in the config file. Part of [`RawConfig`].
#[derive(Serialize, Deserialize)]
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
#[derive(Serialize, Deserialize)]
pub struct RawConfigFile {
    /// The path of the unencrypted file source
    pub src: PathBuf,
    /// The path to the encrypted file output
    pub out: Option<PathBuf>,
    /// The recipients of the file
    pub recipients: Vec<String>,
    /// Should this file be armored?
    #[serde(default)]
    pub armor: bool,
}

impl RawConfigFile {
    fn get_output_path(&self) -> PathBuf {
        match &self.out {
            Some(path) => path.clone(),
            None => self.src.with_added_extension(".age"),
        }
    }
}

/// A ProcessableFile represent a file that can be processed to be either encrypted or decrypted.
/// It is a standalone struct that contains all information required in order to complete
/// processing without any additional infos.
///
/// In constrast to [`config::RawConfigFile`], this type is ready for code execution and does not
/// represent the content of the config file as data has been prepared and may have been virtually
/// modified for further use.
pub struct ProcessableFile {
    /// Source of the file to process (decrypted content)
    pub src: PathBuf,
    /// Output of processed file (encrypted content)
    pub out: PathBuf,
    /// Recipients that have the ability to decrypt this file
    pub recipients: Vec<Rc<dyn age::Recipient>>,
    /// Indicate if the file should be encrypted in armor format.
    pub use_armor_format: bool,
}

impl ProcessableFile {
    pub fn new(
        base_processing_path: &Path,
        raw_config_file: &RawConfigFile,
        recipients: &[Rc<dyn age::Recipient>],
    ) -> Self {
        Self {
            src: base_processing_path.join(raw_config_file.src.clone()),
            out: base_processing_path.join(raw_config_file.get_output_path()),
            recipients: recipients.to_vec(),
            use_armor_format: raw_config_file.armor,
        }
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
    let mut found_recipients: Vec<String> = Vec::new();

    let content = std::fs::read_to_string(file)?;
    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with("#") {
            continue;
        }

        found_recipients.push(line.to_owned());
    }

    Ok(found_recipients)
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
    /// Path to the config file
    config_path: PathBuf,
    /// Recipients part of the config file.
    config_recipients: &'config RawConfigRecipients,
    /// Cache containing age direct recipients. Key: age recipient as string.
    /// Value: struct [`age::Recipient`]
    age_recipients_cache: RefCell<HashMap<String, Rc<dyn age::Recipient>>>,
}

impl<'config> RecipientsFactory<'config> {
    /// Return a new instance of [`RecipientsFactory`].
    pub fn new(config_path: &Path, recipients: &'config RawConfigRecipients) -> Self {
        Self {
            config_path: config_path.to_path_buf(),
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
            let parsed_recipient = read_recipients(
                vec![age_recipient_str.to_owned()],
                vec![],
                vec![],
                None,
                stdin_guard,
            )
            .unwrap()
            .remove(0);
            let rc_recipient: Rc<dyn age::Recipient + Send> = Rc::from(parsed_recipient);

            cache.insert(age_recipient_str.to_owned(), rc_recipient);
        }

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
            .ok_or_else(|| NotFound::config_recipient(config_key))?;

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
            .ok_or_else(|| NotFound::config_group(config_key))?;

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
            .ok_or_else(|| NotFound::config_file(config_key))?;

        let base_path = self
            .config_path
            .parent()
            .expect("same shit as before, you're... not supposed to have that error...");
        // Note: This could use some extra optimization to avoid reading the file each iteration
        let file_content = read_recipients_file(&base_path.join(file_path))?;

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
