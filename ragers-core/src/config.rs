use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::str::FromStr;

use age::cli_common::read_recipients;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// List of usable character to make up a glob pattern
const GLOB_META_CHARS: [char; 3] = ['*', '?', '['];

/// Names of the default config file that Ragers should look for.
const CONFIG_FILE_NAMES: [&str; 2] = [".ragers.yaml", ".ragers.yml"];

#[derive(Error, Debug)]
pub enum ConfigError {
    /// A [`ConfigError::BuildError`] is threw whenever it is impossible for Ragers to create the
    /// config struct and load it into Rust code. Considering this error, it should be impossible
    /// to continue forward if the config cannot be loaded. In ragers-core, there will be no other
    /// way attempted to load the config than by using [`RawConfig::new`], which attempt to
    /// deserialize
    #[error("could not build config: {0}")]
    BuildError(#[from] serde_saphyr::Error),

    #[error("invalid glob: {0}")]
    InvalidGlob(#[from] glob::GlobError),

    /// [`ConfigError::InvalidSrc`] represent an error hwhenever a source path has been given, but
    /// is invalid as per Ragers's rules.
    #[error("invalid source path: {0}")]
    InvalidSrc(String),

    /// [`ConfigError::InvalidOut`] represent an error hwhenever an output path has been given, but
    /// is invalid as per Ragers's rules.
    #[error("invalid output path: {0}")]
    InvalidOut(String),

    /// [`ConfigError::FactoryError`] is an error possibly raised by [`RecipientsFactory`] whenever
    /// the factory cannot fetch a recipient from the config file.
    #[error("could not obtain recipient: {0}")]
    FactoryError(String),

    /// This error is used by [`RecipientsFactory`] whenever it attempts to parse an age recipient.
    /// If age is unable to convert that recipient into a Rust struct,
    /// [`age::cli_common::ReadError`] could be raised and is caught by this error.
    #[error("while obtaining recipient, could not read information: {0}")]
    FactoryReadError(#[from] age::cli_common::ReadError),

    /// Similar to [`ConfigError::FactoryReadError`], this error is specific to Io errors and it is
    /// impossible to obtain the recipient(s) string to parse.
    #[error("while obtaining recipient, io error: {0}")]
    FactoryIoError(#[from] std::io::Error),
}

/// Obtain a path to a config file that can be found starting from `working_dir` and up to the
/// filesystem's root. If multiples are to be expected in different folders, only the file the
/// closest to the current working directory is returned.
///
/// Existence is checked, and if a path is returned, can safely be read.
///
/// In the case that no config file seems to exist, [None] in [Ok] is returned.
pub fn get_closest_config_path(working_dir: &Path) -> Result<Option<PathBuf>, std::io::Error> {
    let all_directories = working_dir.ancestors();

    for dir in all_directories {
        for name in CONFIG_FILE_NAMES {
            let potential_file = dir.join(name);

            if potential_file.is_file() {
                return Ok(Some(potential_file));
            }
        }
    }

    Ok(None)
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

impl FromStr for ConfigContent {
    type Err = ConfigError;

    /// Creates a new instance of [`ConfigContent`] by reading `content`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_saphyr::from_str(s).map_err(ConfigError::from)
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
    pub src: String,
    /// The path to the encrypted file output
    pub out: Option<String>,
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
    /// Create a new [`ConfigFile`] instance.
    ///
    /// `config_path` must be a path that points to the config file directly.
    /// `content` must be a [`ConfigContent`] instance that this struct will take over ownership.
    pub fn new(config_path: &Path, content: ConfigContent) -> Self {
        Self {
            path: config_path.to_path_buf(),
            base_path: config_path
                .parent()
                .expect("config file path should have a parent")
                .to_path_buf(),
            content,
        }
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
            use_armor_format: *use_armor_format,
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
fn attempt_convert_into_glob(source: &str) -> Result<Option<glob::Paths>, glob::PatternError> {
    if source.contains(GLOB_META_CHARS) {
        glob::glob(source).map(Some)
    } else {
        Ok(None)
    }
}

/// Obtain a list of processable files.
pub fn get_processable_files(
    config: &ConfigFile,
    recipients_factory: &RecipientsFactory,
) -> Result<Vec<ProcessableFile>, ConfigError> {
    let mut processable_files = Vec::new();
    let stdin_guard = &mut age::cli_common::StdinGuard::new(false);

    for file in &config.content.files {
        let recipients = recipients_factory.obtain_for_file(file, stdin_guard)?;

        if let Some(glob_pattern) = attempt_convert_into_glob(&file.src)
            .map_err(|_| ConfigError::InvalidSrc(file.src.clone()))?
        {
            // This is a glob: special logic!
            let out_extension = file.out.clone().unwrap_or("age".to_string());

            for entry in glob_pattern {
                let path = entry?;

                let processable_file = ProcessableFile::new(
                    &path,
                    &path.with_added_extension(&out_extension),
                    &recipients,
                    &file.armor,
                );
                processable_files.push(processable_file);
            }
        } else {
            // This is path: nothing crazy...
            let src_path = PathBuf::from_str(&file.src)
                .map_err(|_| ConfigError::InvalidOut(file.src.clone()))?;

            let out_path = match &file.out {
                Some(path_str) => PathBuf::from_str(path_str)
                    .map_err(|_| ConfigError::InvalidOut(path_str.clone()))?,
                None => src_path.with_added_extension("age"),
            };

            let processable_file =
                ProcessableFile::new(&src_path, &out_path, &recipients, &file.armor);
            processable_files.push(processable_file);
        }
    }

    Ok(processable_files)
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
/// an application's lifetime, mostly handling parsing and caching.
///
/// Caching is done to avoid re-parsing a known recipient that has already been parsed.
/// The cache has an infinite longevity and none of its element ever dies. This is an
/// assumed implementation as it is assumed the impact is not severe enough in the usage of the
/// tool to be an issue.
pub struct RecipientsFactory<'config> {
    /// Path to the config file
    config_base_path: PathBuf,
    /// Recipients part of the config file.
    config_recipients: &'config ConfigContentRecipients,
    /// Cache containing age direct recipients. Key: age recipient as string.
    /// Value: struct [`age::Recipient`]
    age_recipients_cache: RefCell<HashMap<String, Rc<dyn age::Recipient>>>,
}

impl<'config> RecipientsFactory<'config> {
    /// Return a new instance of [`RecipientsFactory`].
    ///
    /// `config_base_path` must point to the folder where the config file is contained. This is
    /// used in the case a recipients file must be read.
    pub fn new(config: &'config ConfigFile) -> Self {
        Self {
            config_base_path: config.base_path.to_path_buf(),
            config_recipients: &config.content.recipients,
            age_recipients_cache: RefCell::new(HashMap::new()),
        }
    }

    fn get_or_store_recipient(
        &self,
        age_recipient_str: &str,
        stdin_guard: &mut age::cli_common::StdinGuard,
    ) -> Result<Rc<dyn age::Recipient>, age::cli_common::ReadError> {
        let mut cache = self.age_recipients_cache.borrow_mut();

        if let Some(recipient) = cache.get(age_recipient_str) {
            return Ok(Rc::clone(recipient));
        }

        let parsed_recipient = read_recipients(
            vec![age_recipient_str.to_owned()],
            vec![],
            vec![],
            None,
            stdin_guard,
        )?
        .into_iter()
        .next()
        .ok_or_else(|| {
            age::cli_common::ReadError::InvalidRecipient(age_recipient_str.to_owned())
        })?;
        let rc_recipient: Rc<dyn age::Recipient + Send> = Rc::from(parsed_recipient);

        cache.insert(age_recipient_str.to_owned(), rc_recipient);

        let age_recipient = Rc::clone(cache.get(age_recipient_str).unwrap_or_else(|| {
            panic!("expected {age_recipient_str} to exist in factory cache, but nothing was found")
        }));

        Ok(age_recipient)
    }

    fn direct_recipient(
        &self,
        config_key: &str,
        stdin_guard: &mut age::cli_common::StdinGuard,
    ) -> Result<Rc<dyn age::Recipient>, ConfigError> {
        let age_recipient_str = self
            .config_recipients
            .direct
            .get(config_key)
            .ok_or_else(|| {
                ConfigError::FactoryError(format!("direct recipient `{config_key}` not found"))
            })?;

        let age_recipient = self.get_or_store_recipient(age_recipient_str, stdin_guard)?;

        Ok(age_recipient)
    }

    fn group(
        &self,
        config_key: &str,
        stdin_guard: &mut age::cli_common::StdinGuard,
    ) -> Result<Vec<Rc<dyn age::Recipient>>, ConfigError> {
        let mut parsed_recipients = Vec::new();

        let group = self
            .config_recipients
            .groups
            .get(config_key)
            .ok_or_else(|| ConfigError::FactoryError(format!("group `{config_key}` not found")))?;

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
    ) -> Result<Vec<Rc<dyn age::Recipient>>, ConfigError> {
        let mut parsed_recipients = Vec::new();

        let file_path = self
            .config_recipients
            .files
            .get(config_key)
            .ok_or_else(|| {
                ConfigError::FactoryError(format!("recipients file `{config_key}` not found"))
            })?;

        // Note: This could use some extra optimization to avoid reading the file each iteration
        let file_content = read_recipients_file(&self.config_base_path.join(file_path))?;

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
    ) -> Result<Vec<Rc<dyn age::Recipient>>, ConfigError> {
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
        config_file: &ConfigContentFile,
        stdin_guard: &mut age::cli_common::StdinGuard,
    ) -> Result<Vec<Rc<dyn age::Recipient>>, ConfigError> {
        let mut fetched_recipients = Vec::new();

        for alias in &config_file.recipients {
            let recipients = self.obtain_for_alias(alias, stdin_guard)?;
            fetched_recipients.extend(recipients);
        }

        Ok(fetched_recipients)
    }
}
