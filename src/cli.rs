use std::{
    fmt::Display,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use clap::{Args, Parser, Subcommand};
use inquire::Confirm;
use itertools::Itertools;
use which::which;

use crate::{
    config::RawConfigFile,
    context::Context,
    error::{CmdError, DecryptionError, EncryptionError},
};

mod decrypt;
mod edit;
mod encrypt;

pub use self::decrypt::decrypt;
pub use self::edit::edit;
pub use self::encrypt::encrypt;

#[derive(Parser)]
#[command(name = "ragers", version, about, next_line_help = true)]
pub struct Cli {
    #[arg(
        short = 'c',
        long = "config",
        action = clap::ArgAction::Set,
        default_value = ".ragers.yaml",
        global = true,
        // default_values = [".ragers.yaml", ".ragers.yml"], // For now this is confusing me too much, lack of documentation
        env = "RAGERS_CONFIG",
        help = "Path the Ragers configuration file",
        value_hint = clap::ValueHint::FilePath,
        value_parser = clap::value_parser!(PathBuf),
        long_help = "Path the Ragers configuration file. This must specify a path to a YAML file that can be read as per Ragers's configuration standard. This config file is used to determine which and how are files are encrypted. Refer to documentation."
    )]
    pub config_path: PathBuf,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Encrypt one, multiple or all files")]
    Encrypt {
        #[arg(
            help = "Path to file(s) to encrypt. If none are provided, all files defined in config will be encrypted.",
            long_help = "Optional path to one or multiple files to encrypt. If none are provided, all files defined in config will be encrypted. The identity is not used for encryption, only recipients defined for the file(s) will be used for encryption.",
            action = clap::ArgAction::Append,
            value_hint = clap::ValueHint::FilePath,
            value_parser = clap::value_parser!(PathBuf),
            required = false
        )]
        files: Option<Vec<PathBuf>>,
    },

    #[command(about = "Decrypt one, multiple or all files")]
    Decrypt {
        #[arg(
            help = "Path to file to decrypt. If none are provided, all files defined in config will be decrypted.",
            long_help = "Optional path to one or multiple files to decrypt. If none are provided, all files defined in config will be decrypted. Requires an identity to read to decrypt files. Files that cannot be decrypted are ignored.",
            action = clap::ArgAction::Append,
            value_hint = clap::ValueHint::FilePath,
            value_parser = clap::value_parser!(PathBuf),
            required = false
        )]
        files: Option<Vec<PathBuf>>,

        #[command(flatten)]
        identity: IdentityArgs,
    },

    #[command(about = "Edit a file directly without manual decryption")]
    Edit {
        #[arg(
            help = "Path to file to edit.",
            long_help = "Path to the file to edit. This can either be an encrypted file or the original decrypted content. The file must be registered in the config file before using this command. If the given file is encrypted, the same decryption logic as the \"decrypt\" command, see its help to have more information.",
            action = clap::ArgAction::Set,
            value_hint = clap::ValueHint::FilePath,
            value_parser = clap::value_parser!(PathBuf),
            required = false
        )]
        file: PathBuf,

        #[command(flatten)]
        identity: IdentityArgs,
    },
}

#[derive(Debug, Args)]
pub struct IdentityArgs {
    #[arg(
        short = 'I',
        long = "identity-file",
        action = clap::ArgAction::Append,
        env = "RAGERS_IDENTITIES_FILE",
        default_value = ".identity",
        help = "Paths to one or multiple identities file used to decrypt files. Repeat to use multiple.",
        value_hint = clap::ValueHint::FilePath,
        value_parser = clap::value_parser!(PathBuf),
        long_help = "Path to a file containing one or more private keys (age identities, or a single SSH private key) used to decrypt files. This flag may be repeated to supply multiple identities; all of them will be tried against every encrypted file."
    )]
    pub identities_file: Vec<PathBuf>,
}

/// Filters and returns a vector of files to process based on the requested files from the user.
///
/// If `requested_files` is `None`, all files from the context's configuration are returned.
/// If `requested_files` is `Some`, only the configuration files that match the requested paths
/// are returned. Path comparison is done using [`is_same_path`].
///
/// This function does not check for path existence or does not make any check at all. It only
/// exists as a filter from the files set in config and what's been requested.
///
/// This may return a [`CmdError`] error variant in the case that there are no files that have
/// matched the search, or if no files have been configured in the config file.
fn obtain_files_to_process<'ctx>(
    ctx: &'ctx Context,
    requested_files: &Option<Vec<PathBuf>>,
) -> Result<Vec<&'ctx RawConfigFile>, CmdError> {
    let files: Vec<&'ctx RawConfigFile> = match requested_files {
        None => ctx.config.files.iter().collect(),
        Some(requested) => ctx
            .config
            .files
            .iter()
            .filter(|config_file| {
                for one_requested_path in requested {
                    if is_same_path(one_requested_path, &config_file.src)
                        .ok()
                        .is_some()
                    {
                        return true;
                    }
                }
                false
            })
            .collect(),
    };

    if files.is_empty() {
        return Err(CmdError::NoFilesToProcess);
    }

    Ok(files)
}

/// Compares two path and attempt to check if they are pointing to the same file.
///
/// This will compares the two paths using their absolute representation, ensuring that a different current directory
/// won't be an issue while making the check.
fn is_same_path<P: AsRef<Path>>(path_one: P, path_two: P) -> Result<bool, std::io::Error> {
    // https://ibb.co/TqdmZBYJ
    let absolute_path_one = std::path::absolute(path_one)?;
    let absolute_path_two = std::path::absolute(path_two)?;

    if absolute_path_one == absolute_path_two {
        return Ok(true);
    }

    Ok(false)
}

/// Attempt to decrypt an encrypted content buffer.
///
/// This is a wrapper around [`age`]'s decryption logic, allowing multiple identities to be used
/// for the decryption process.
/// In the case the decryption could have not been completed, [`DecryptionError`] is returned.
fn get_decrypted_content(
    encrypted_content: &[u8],
    identities: &[&dyn age::Identity],
) -> Result<Vec<u8>, DecryptionError> {
    let mut decrypted_content: Vec<u8> = Vec::new();

    // ArmoredReader can both read ASCII and binary formats, no need to check ourselves.
    let decryptor =
        age::Decryptor::new_buffered(age::armor::ArmoredReader::new(encrypted_content))?;

    // Write the decrypted content to `decrypted_content`.
    let mut decryptor_stream = decryptor.decrypt(identities.iter().copied())?;
    decryptor_stream
        .read_to_end(&mut decrypted_content)
        .expect("could not read decrypted content");

    Ok(decrypted_content)
}

/// Attempt to encrypted a raw content buffer.
///
/// This is a wrapper around [`age`]'s encryption logic, allowing encryption using multiple
/// recipients and to select the according format.
/// In the case the decryption could have not been completed, [`EncryptionError`] is returned.
fn get_encrypted_content(
    raw_content: &[u8],
    recipients: Vec<&dyn age::Recipient>,
    format: age::armor::Format,
) -> Result<Vec<u8>, EncryptionError> {
    let mut encrypted_content: Vec<u8> = Vec::new();

    let encryptor = age::Encryptor::with_recipients(recipients.into_iter())?;

    let mut decryptor = encryptor.wrap_output(age::armor::ArmoredWriter::wrap_output(
        &mut encrypted_content,
        format,
    )?)?;
    decryptor.write_all(raw_content)?;
    decryptor.finish().and_then(|armor| armor.finish())?;

    Ok(encrypted_content)
}

/// Simple enum to easily represent if we are either encrypting or decrypting.
enum Action {
    Encryption,
    Decryption,
}

impl Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Encryption => write!(f, "encrypt"),
            Action::Decryption => write!(f, "decrypt"),
        }
    }
}

/// Reusable wrapper to request the user if they are confirming encryption/decryption.
/// This output a list of files that will be processed, request a yes or no from the user, and
/// return the value to the caller, in which they decide what to do next.
fn confirm_action(files: &[&RawConfigFile], action: Action) -> bool {
    let files_displayed: String = files
        .iter()
        .map(|path| match action {
            Action::Encryption => format!("\t- {}", path.src.display()),
            Action::Decryption => format!("\t- {}", path.out.display()),
        })
        .join("\n");

    let confirm_str = format!(
        "There are {} files to {action}:\n{}\nProceed?",
        files.len(),
        files_displayed
    );

    Confirm::new(&confirm_str)
        .with_default(true)
        .prompt()
        .expect("couldn't prompt to user")
}

/// Attempt to read identities from files. Wrapper around [`age::cli_common::read_identities`] to
/// reused a stdin_guard from context and avoid rewriting logic.
///
/// # Warning
///
/// This function called for a mutable borrow from [`Context::stdin_guard`]. There shall be no
/// other mutable borrow made before in order for this function to work. Drop your borrow if
/// needed.
fn get_identities(
    ctx: &Context,
    identity_files: &[PathBuf],
) -> Result<Vec<Box<dyn age::Identity>>, age::cli_common::ReadError> {
    let mut stdin_guard = ctx.stdin_guard.borrow_mut();
    let filenames = identity_files
        .iter()
        .map(|item| item.to_string_lossy().to_string())
        .collect::<Vec<String>>();

    let dyn_identities = age::cli_common::read_identities(filenames, None, &mut stdin_guard)?;

    Ok(dyn_identities)
}

/// Convert a str representation of a command into a tuple of two elements:
/// - Path to the binary
/// - Additionnal arguments, if any
///
/// While possible, the function shall not panic as long as it is checked that the str is not
/// empty.
fn convert_str_to_cmd(cmd_str: &str) -> (PathBuf, Vec<String>) {
    let mut args = cmd_str.split_ascii_whitespace();

    (
        args.next().unwrap().into(),
        args.map(String::from).collect(),
    )
}

/// Get the path to the ragers editor from the `RAGERS_EDITOR` environment variable, if set.
///
/// Returns `None` if the variable is not set or is empty.
/// In the case that the editor binary path can not be found, `None` is returned and a warning is
/// printed to alert the user.
fn get_ragers_editor() -> Option<PathBuf> {
    let env_var = std::env::var_os("RAGERS_EDITOR");

    env_var.as_ref()?;

    let env_var_str = env_var.unwrap().into_string().ok()?;
    if env_var_str.is_empty() {
        return None;
    };

    let (cmd, _) = convert_str_to_cmd(&env_var_str);

    which(cmd).inspect_err(|&err| {
        if err == which::Error::CannotFindBinaryPath {
            println!("warning: cannot find path to binary for 'RAGERS_EDITOR={env_var_str}' variable. attempting to use your default editor")
        }
    }).ok()
}
