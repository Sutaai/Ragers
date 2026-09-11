use std::path::PathBuf;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum RecipientParseError {
    #[error("Invalid recipient")]
    Invalid,
    #[error("SSH recipient parse error")]
    SSH(age::ssh::ParseRecipientKeyError),
}

impl From<age::ssh::ParseRecipientKeyError> for RecipientParseError {
    fn from(value: age::ssh::ParseRecipientKeyError) -> Self {
        Self::SSH(value)
    }
}

#[derive(Error, Debug)]
#[error("Item not found: {0}")]
pub struct NotFound(pub String);

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Could not parse config file: {0}")]
    ParseError(#[from] config::ConfigError),
    // #[error("Validation error: {0}")]
    #[error(transparent)]
    ValidationError(#[from] ConfigValidationError),
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
        parse_error: RecipientParseError,
    },
    #[error(
        "Duplicated recipient:
- Alias: {value}

Note: The key is not the duplicated value but the value itself"
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
    NotFound(#[from] NotFound),
    #[error(transparent)]
    RecipientParseError(#[from] RecipientParseError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error)
}

#[derive(Error, Debug)]
pub enum CmdError {
    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error("Config validation error: {0}")]
    Validation(#[from] ConfigValidationError),

    #[error(transparent)]
    RecipientsFactory(#[from] RecipientsFactoryError)
}
