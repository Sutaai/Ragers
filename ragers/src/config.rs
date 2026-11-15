use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use age::cli_common::read_recipients;
use ragers::libconfig::{AliasKind, RawConfigFile, RawConfigRecipients, get_alias_kind};

use crate::error::{NotFound, RecipientsFactoryError};

/// Names of the default config file that Ragers should look for.
const CONFIG_FILE_NAMES: [&str; 2] = [".ragers.yaml", ".ragers.yml"];

/// Obtain a path to a config file that can be found starting from the current working directory up
/// to the filesystem's root. If multiples are to be expected in different folders, only the file
/// the closest to the current working directory is returned.
///
/// Existence is checked, and if a path is returned, can safely be read.
pub fn get_closest_config_path() -> Result<Option<PathBuf>, std::io::Error> {
    let working_dir = std::env::current_dir()?;

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
