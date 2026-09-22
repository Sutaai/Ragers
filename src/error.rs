use std::path::PathBuf;

use thiserror::Error;

#[derive(Error, Debug)]
#[error("Item not found: {0}")]
pub struct NotFound(pub String);

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
    NotFound(#[from] NotFound),

    #[error(transparent)]
    RecipientParseError(#[from] age::cli_common::ReadError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Error, Debug)]
pub enum CmdError {
    #[error("{0}")]
    PreconditionCheck(&'static str),

    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error("Could not parse recipient or identity: {0}")]
    AgeReadError(#[from] age::cli_common::ReadError),

    #[error(transparent)]
    RecipientsFactory(#[from] RecipientsFactoryError),
}
