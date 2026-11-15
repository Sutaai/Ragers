use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("could not build config file: {0}")]
    ParseError(#[from] config::ConfigError),
}

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

pub fn get_alias_kind(alias: &str) -> AliasKind {
    if let Some(stripped) = alias.strip_prefix("file:") {
        AliasKind::RecipientsFile(stripped.to_owned())
    } else if let Some(stripped) = alias.strip_prefix("group:") {
        AliasKind::Group(stripped.to_owned())
    } else {
        AliasKind::DirectRecipient(alias.to_owned())
    }
}
