use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// List of usable character to make up a glob pattern
const GLOB_META_CHARS: [char; 3] = ['*', '?', '['];

#[derive(Error, Debug)]
pub enum ConfigError {
    /// A [`ConfigError::BuildError`] is threw whenever it is impossible for Ragers to create the
    /// config struct and load it into Rust code. Considering this error, it should be impossible
    /// to continue forward if the config cannot be loaded. In ragers-core, there will be no other
    /// way attempted to load the config than by using [`RawConfig::new`], which attempt to
    /// deserialize
    #[error("could not build config: {0}")]
    BuildError(#[from] serde_saphyr::Error),

    /// This will later be used for glob validation.
    #[error("invalid src at `{0}`: {1}")]
    InvalidSrc(String, String),
}

/// Struct representation of the Ragers config file. Used for deserialization.
#[derive(Serialize, Deserialize)]
pub struct ConfigContent {
    /// A list of pre-defined recipients
    pub recipients: ConfigContentRecipients,
    /// A list of files to encrypt
    #[serde(default)]
    pub files: Vec<ConfigContentFile>,
}

impl ConfigContent {
    /// Creates a new instance of [`ConfigContent`] by reading `content`.
    pub fn from_str(content: &str) -> Result<Self, ConfigError> {
        serde_saphyr::from_str(content).map_err(|err| ConfigError::from(err))
    }
}

/// Struct representation of recipients definition in the config file. Part of [`ConfigContent`].
#[derive(Serialize, Deserialize)]
pub struct ConfigContentRecipients {
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
/// [`ConfigContent`].
#[derive(Serialize, Deserialize)]
pub struct ConfigContentFile {
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

pub struct ConfigFile {
    /// The path to the config file.
    pub path: PathBuf,

    /// Parent path of `path`. This exists in order to avoid having to recheck for parent's
    /// optional possibility.
    pub base_path: PathBuf,

    /// The deserialized content of the config file.
    pub content: ConfigContent,
}

impl ConfigFile {
    pub fn new(path: &Path, content: ConfigContent) -> Self {
        return Self {
            path: path.to_path_buf(),
            base_path: path
                .parent()
                .expect("config file path should have a parent")
                .to_path_buf(),
            content: content,
        };
    }
}

/// A ProcessableFile represent a file that can be processed to be either encrypted or decrypted.
/// It is a standalone struct that contains all information required in order to complete
/// processing without any additional infos.
///
/// In contrast to [`ConfigContentFile`], this type is ready for code execution and does not
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
    /// Creates a new [`ProcessableFile`] instance.
    pub fn new(
        source_path: &Path,
        output_path: &Path,
        recipients: &[Rc<dyn age::Recipient>],
        use_armor_format: &bool,
    ) -> Self {
        Self {
            src: source_path.to_path_buf(),
            out: output_path.to_path_buf(),
            recipients: recipients.to_vec(),
            use_armor_format: use_armor_format.clone(),
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

/// Obtain the kind of alias a string refers to. This can be used to obtain the corresponding
/// recipient(s) in a config file.
///
/// See [`AliasKind`] for the existing aliases.
pub fn get_alias_kind(alias: &str) -> AliasKind {
    if let Some(stripped) = alias.strip_prefix("file:") {
        AliasKind::RecipientsFile(stripped.to_owned())
    } else if let Some(stripped) = alias.strip_prefix("group:") {
        AliasKind::Group(stripped.to_owned())
    } else {
        AliasKind::DirectRecipient(alias.to_owned())
    }
}

/// Attempt to check if a given string `source` can and should be interpreted as a glob pattern.
fn is_potential_glob(source: &str) -> bool {
    if source.contains(GLOB_META_CHARS) {
        glob::Pattern::new(source).map(|_| true).unwrap_or(false)
    } else {
        false
    }
}
