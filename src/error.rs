use std::path::PathBuf;

use thiserror::Error;

#[derive(Error, Debug)]
#[error("{0}")]
pub struct NotFound(String);

impl NotFound {
    pub fn config_recipient(recipient: &str) -> Self {
        NotFound(format!("recipient in config not found: {recipient}").to_owned())
    }

    pub fn config_group(group: &str) -> Self {
        NotFound(format!("group in config not found: {group}").to_owned())
    }

    pub fn config_file(file: &str) -> Self {
        NotFound(format!("file in config not found: {file}").to_owned())
    }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("could not build config file: {0}")]
    ParseError(#[from] config::ConfigError),
    // #[error("Validation error: {0}")]
    #[error("validation error: {0:#?}")]
    ValidationError(Vec<ConfigValidationError>),
}

impl From<Vec<ConfigValidationError>> for ConfigError {
    fn from(errs: Vec<ConfigValidationError>) -> Self {
        ConfigError::ValidationError(errs)
    }
}

#[derive(Error, Debug)]
pub enum ConfigValidationError {
    #[error(
        "Invalid recipient:
- Alias: {key}
- Error: {parse_error:?}"
    )]
    InvalidRecipient {
        key: String,
        #[source]
        parse_error: age::cli_common::ReadError,
    },
    #[error(
        "Duplicated recipient:
- Alias: {value}

Note: The key isn't duplicated but the value itself is"
    )]
    DuplicatedRecipient { value: String },
    #[error(
        "Recipients file not found:
- Key: {key}
- Path: {path:?}"
    )]
    RecipientsFileNotFound { key: String, path: String },
    #[error(
        "Recipient in group not found:
- Group: {group}
- Recipient: {alias}"
    )]
    RecipientInGroupNotFound { group: String, alias: String },
    #[error("File with duplicated source path at index {}
Source path: {}", .index, .path .display())]
    FileDuplicatedSource { index: usize, path: PathBuf },
    #[error("File with duplicated source path at index {}
Source path: {}", .index, .path.display())]
    FileDuplicatedDestination { index: usize, path: PathBuf },
    #[error("File with invalid recipient at index {}
Invalid alias: {}", .index, .alias)]
    FileAliasNotFound { index: usize, alias: String },
    #[error("File has duplicated recipient at index {}
Duplicated alias: {}", .index, .alias)]
    FileAliasDuplicated { index: usize, alias: String },
}

#[derive(Error, Debug)]
pub enum RecipientsFactoryError {
    #[error(transparent)]
    KeyInConfigNotFound(#[from] NotFound),

    #[error(transparent)]
    RecipientParseError(#[from] age::cli_common::ReadError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum CmdError {
    /// Returned when there are no files to process found in the config file
    #[error("no files to process")]
    NoFilesToProcess,

    #[error("IO error, could not read \"{path}\": {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("IO error, could not write at \"{path}\": {source}")]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },

    /// For more "unknown" IO error
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),

    /// Returned when there is an underlying issue with the config file
    #[error(transparent)]
    Config(#[from] ConfigError),

    /// Returned when age could not decrypt a file
    #[error("decryption error: {0}")]
    AgeDecryptError(#[from] age::DecryptError),

    /// Returned when age could not encrypt a file
    #[error("encryption error: {0}")]
    AgeEncryptError(#[from] age::EncryptError),

    /// Returned when the age library is unable to parse one of it's struct
    #[error("could not parse recipient or identity: {0}")]
    AgeReadError(#[from] age::cli_common::ReadError),

    /// Returned when the recipients factory has had an issue
    #[error(transparent)]
    RecipientsFactory(#[from] RecipientsFactoryError),
}
