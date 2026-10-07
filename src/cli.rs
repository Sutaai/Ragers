use std::{
    borrow::Borrow,
    fmt::Display,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use clap::{Args, Parser, Subcommand};
use inquire::Confirm;
use itertools::Itertools;

use crate::{
    config::RawConfigFile,
    context::Context,
    error::{
        CmdError, DecryptionError, DeleteFileError, EncryptionError, ReadFileError, WriteFileError,
    },
};

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
    #[command(about = "Encrypt files")]
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

    #[command(about = "Decrypt files")]
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

/// Given a list of path, attempt to find a path that is comparable to the given path.
fn find_comparable_path<'path, P: Borrow<PathBuf> + AsRef<Path>>(
    path: &PathBuf,
    list: &'path [P],
) -> Result<Option<&'path P>, std::io::Error> {
    let full_path = std::path::absolute(path)?;

    for listed_path in list {
        let compare_path = std::path::absolute(listed_path)?;
        if full_path == compare_path {
            return Ok(Some(listed_path));
        }
    }

    Ok(None)
}

fn find_comparable_path_single<'path, P: Borrow<PathBuf> + AsRef<Path>>(
    path_one: P,
    path_two: P,
) -> Result<bool, std::io::Error> {
    let full_path_one = std::path::absolute(path_one)?;
    let full_path_two = std::path::absolute(path_two)?;

    if full_path_one == full_path_two {
        return Ok(true);
    }

    Ok(false)
}

fn get_decrypted_content(
    file: &PathBuf,
    identities: &[&dyn age::Identity],
) -> Result<Vec<u8>, DecryptionError> {
    let mut decrypted_content: Vec<u8> = Vec::new();

    let encrypted_file = std::fs::File::open(&file).map_err(|err| ReadFileError {
        path: file.clone(),
        source: err,
    })?;

    // ArmoredReader can both read ASCII and binary formats, no need to check ourselves.
    let decryptor = age::Decryptor::new_buffered(age::armor::ArmoredReader::new(encrypted_file))?;

    // Write the decrypted content to `decrypted_content`.
    let mut decryptor_stream = decryptor.decrypt(identities.iter().copied())?;
    decryptor_stream
        .read_to_end(&mut decrypted_content)
        .expect("could not read decrypted content");

    Ok(decrypted_content)
}

fn get_encrypted_content(
    file: &PathBuf,
    recipients: Vec<&dyn age::Recipient>,
    format: age::armor::Format,
) -> Result<Vec<u8>, EncryptionError> {
    let mut encrypted_content: Vec<u8> = Vec::new();

    let encryptor = age::Encryptor::with_recipients(recipients.into_iter())?;

    let content = std::fs::read(file).map_err(|err| ReadFileError {
        path: file.clone(),
        source: err,
    })?;

    let mut decryptor = encryptor.wrap_output(age::armor::ArmoredWriter::wrap_output(
        &mut encrypted_content,
        format,
    )?)?;
    decryptor.write_all(&content)?;
    decryptor.finish().and_then(|armor| armor.finish())?;

    Ok(encrypted_content)
}

fn begin_encrypt_files(ctx: &Context, files: &[&RawConfigFile]) -> Result<(), CmdError> {
    let mut stdin_guard = ctx.stdin_guard.borrow_mut();

    for file in files {
        // Todo: Check for file existence, if does not exist,
        let recipients = ctx
            .recipients_factory
            .obtain_for_file(file, &mut stdin_guard)?;

        let recipient_refs: Vec<&dyn age::Recipient> =
            recipients.iter().map(|r| r.as_ref()).collect();

        // Configure age's encryptor
        let format = if file.armor {
            age::armor::Format::AsciiArmor
        } else {
            age::armor::Format::Binary
        };

        let encrypted_content = get_encrypted_content(&file.src, recipient_refs, format)?;

        // Write to encrypted file
        std::fs::write(&file.out, &encrypted_content).map_err(|err| WriteFileError {
            path: file.src.clone(),
            source: err,
        })?;

        // This should only be done after all files have been encrypted
        fs::remove_file(&file.src).map_err(|err| DeleteFileError {
            path: file.src.clone(),
            source: err,
        })?;
    }

    Ok(())
}

fn begin_decrypt_files(
    files: &[&RawConfigFile],
    identities: Vec<&dyn age::Identity>,
) -> Result<(), CmdError> {
    for file in files {
        // Todo: Check for file existence, if does not exist,
        let decrypted_content = get_decrypted_content(&file.out, &identities)?;

        std::fs::write(&file.src, &decrypted_content).map_err(|err| WriteFileError {
            path: file.src.clone(),
            source: err,
        })?;

        // This should only be done after all files have been decrypted
        fs::remove_file(&file.out).map_err(|err| DeleteFileError {
            path: file.out.clone(),
            source: err,
        })?;
    }

    Ok(())
}

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

fn confirm_action(files: &[&RawConfigFile], action: Action) -> bool {
    let files_displayed: String = files
        .iter()
        .map(|path| match action {
            Action::Encryption => format!("\t- {}", path.src.display()),
            Action::Decryption => format!("\t- {}", path.out.display()),
        })
        .join("\n");

    let confirm_str = format!(
        "There are {} files to {action}:\n{}\nProceed with encryption?",
        files.len(),
        files_displayed
    );

    Confirm::new(&confirm_str)
        .with_default(true)
        .prompt()
        .expect("Couldn't prompt to user")
}

fn get_identities(
    identity_files: &Vec<PathBuf>,
) -> Result<Vec<Box<dyn age::Identity>>, age::cli_common::ReadError> {
    let mut stdin_guard = age::cli_common::StdinGuard::new(true);

    let dyn_identities = age::cli_common::read_identities(
        identity_files
            .iter()
            .map(|item| {
                item.to_str()
                    .expect("path must be turned to string")
                    .to_owned()
            })
            .collect::<Vec<String>>(),
        None,
        &mut stdin_guard,
    )?;

    Ok(dyn_identities)
}

pub fn encrypt(ctx: &Context, files_to_encrypt: &Option<Vec<PathBuf>>) -> Result<(), CmdError> {
    let to_process_files: Vec<&RawConfigFile> = match files_to_encrypt {
        None => ctx.config.files.iter().collect(),
        Some(requested) => ctx
            .config
            .files
            .iter()
            .filter(|cfg| {
                find_comparable_path(&cfg.src, requested)
                    .ok()
                    .flatten()
                    .is_some()
            })
            .collect(),
    };

    if to_process_files.is_empty() {
        return Err(CmdError::NoFilesToProcess);
    }

    if confirm_action(&to_process_files, Action::Encryption) {
        begin_encrypt_files(ctx, &to_process_files)?
    };

    Ok(())
}

pub fn decrypt(
    ctx: &Context,
    files_to_decrypt: &Option<Vec<PathBuf>>,
    identities: &IdentityArgs,
) -> Result<(), CmdError> {
    let to_process_files: Vec<&RawConfigFile> = match files_to_decrypt {
        None => ctx.config.files.iter().collect(),
        Some(requested) => ctx
            .config
            .files
            .iter()
            .filter(|cfg| {
                find_comparable_path(&cfg.out, requested)
                    .ok()
                    .flatten()
                    .is_some()
            })
            .collect(),
    };

    if to_process_files.is_empty() {
        return Err(CmdError::NoFilesToProcess);
    }

    let identities_struct = get_identities(&identities.identities_file)?;
    let identities: Vec<&dyn age::Identity> =
        identities_struct.iter().map(|i| i.as_ref()).collect();

    if confirm_action(&to_process_files, Action::Decryption) {
        begin_decrypt_files(&to_process_files, identities)?
    };

    Ok(())
}

pub fn edit(
    ctx: &Context,
    file_to_edit: &PathBuf,
    identities: &IdentityArgs,
) -> Result<(), CmdError> {
    let matched_file = ctx
        .config
        .files
        .iter()
        .find(|cfg| {
            find_comparable_path_single(&cfg.src, file_to_edit)
                .ok()
                .is_some()
                || find_comparable_path_single(&cfg.out, file_to_edit)
                    .ok()
                    .is_some()
        })
        .ok_or(CmdError::NoFilesToProcess)?;

    let is_encrypted = find_comparable_path_single(&matched_file.out, file_to_edit)?;
    let file_path = if is_encrypted {
        println!("matching against an encrypted file");
        &matched_file.out
    } else {
        println!("matching against a source file");
        &matched_file.src
    };

    let file_content = {
        if is_encrypted {
            let identities_struct = get_identities(&identities.identities_file)?;
            let final_identities: Vec<&dyn age::Identity> =
                identities_struct.iter().map(|i| i.as_ref()).collect();
            get_decrypted_content(file_path, &final_identities)?
        } else {
            fs::read(file_path).map_err(|err| ReadFileError {
                path: file_path.clone(),
                source: err,
            })?
        }
    };

    Ok(())
}
