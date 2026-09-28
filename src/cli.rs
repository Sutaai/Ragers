use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
};

use clap::{Parser, Subcommand};
use inquire::Confirm;
use itertools::Itertools;

use crate::{config::RawConfigFile, context::Context, error::CmdError};

#[derive(Parser)]
#[command(version, about)]
#[command(next_line_help = true)]
pub struct Cli {
    #[arg(
        short = 'c',
        long = "config",
        action = clap::ArgAction::Set,
        default_value = ".ragers.yaml",
        // default_values = [".ragers.yaml", ".ragers.yml"], // For now this is confusing me too much, lack of documentation
        env = "RAGERS_CONFIG",
        help = "Path the Ragers configuration file",
        value_hint = clap::ValueHint::FilePath,
        value_parser = clap::value_parser!(PathBuf),
        long_help = "Path the Ragers configuration file. This must specify a path to a YAML file that can be read as per Ragers's configuration standard. This config file is used to determine which and how are files are encrypted. Refer to documentation."
    )]
    pub config_path: PathBuf,

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

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Encrypt files")]
    Encrypt {
        #[arg(
            help = "Path to file to encrypt. If none are provided, all files defined in config will be encrypted.",
            value_hint = clap::ValueHint::FilePath,
            required = false
        )]
        files: Option<Vec<PathBuf>>,
    },

    #[command(about = "Decrypt files")]
    Decrypt {
        #[arg(
            help = "Path to file to decrypt. If none are provided, all files defined in config will be decrypted.",
            value_hint = clap::ValueHint::FilePath,
            required = false
        )]
        files: Option<Vec<PathBuf>>,
    },
}

/// Given a list of path, attempt to find a path that is comparable to the given path.
fn find_comparable_path<'path>(
    path: &PathBuf,
    list: &'path [PathBuf],
) -> Result<Option<&'path PathBuf>, std::io::Error> {
    let full_path = std::path::absolute(path)?;

    for listed_path in list {
        let compare_path = std::path::absolute(listed_path)?;
        if full_path == compare_path {
            return Ok(Some(listed_path));
        }
    }

    Ok(None)
}

fn begin_encrypt_files(ctx: &Context, files: &[&RawConfigFile]) -> Result<(), CmdError> {
    let mut stdin_guard = ctx.stdin_guard.borrow_mut();

    for file in files {
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

        let encrypted_content = {
            let mut encrypted_content: Vec<u8> = Vec::new();

            let encryptor = age::Encryptor::with_recipients(recipient_refs.into_iter())?;

            let content = std::fs::read(&file.src).map_err(|err| CmdError::ReadFile {
                path: file.src.clone(),
                source: err,
            })?;

            let mut decryptor = encryptor.wrap_output(age::armor::ArmoredWriter::wrap_output(
                &mut encrypted_content,
                format,
            )?)?;
            decryptor.write_all(&content)?;
            decryptor.finish().and_then(|armor| armor.finish())?;

            encrypted_content
        };

        // Write to encrypted file
        std::fs::write(&file.out, &encrypted_content).map_err(|err| CmdError::WriteFile {
            path: file.src.clone(),
            source: err,
        })?;

        // This should only be done after all files have been encrypted
        fs::remove_file(&file.src)?;
    }

    Ok(())
}

fn begin_decrypt_files(
    _: &Context,
    files: &[&RawConfigFile],
    identities: Vec<&dyn age::Identity>,
) -> Result<(), CmdError> {
    for file in files {
        let decrypted_content = {
            let encrypted_file =
                std::fs::File::open(&file.out).map_err(|err| CmdError::ReadFile {
                    path: file.out.clone(),
                    source: err,
                })?;

            // ArmoredReader can both read ASCII and binary formats, no need to check ourselves.
            let decryptor =
                age::Decryptor::new_buffered(age::armor::ArmoredReader::new(encrypted_file))?;

            let mut decrypted_content_vec: Vec<u8> = Vec::new();

            let mut decryptor_stream = match decryptor.decrypt(identities.iter().copied()) {
                Ok(res) => res,
                Err(_) => continue,
            };

            decryptor_stream
                .read_to_end(&mut decrypted_content_vec)
                .expect("could not read decrypted contents");

            decrypted_content_vec
        };

        std::fs::write(&file.src, &decrypted_content).map_err(|err| CmdError::WriteFile {
            path: file.src.clone(),
            source: err,
        })?;

        // This should only be done after all files have been decrypted
        fs::remove_file(&file.out)?;
    }

    Ok(())
}

pub fn encrypt(ctx: &Context, to_encrypt_files: &Option<Vec<PathBuf>>) -> Result<(), CmdError> {
    let to_process_files: Vec<&RawConfigFile> = match to_encrypt_files {
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

    let files_as_str_list: String = to_process_files
        .iter()
        .map(|path| format!("\t- {}", path.src.display()))
        .join("\n");

    let confirm_str = format!(
        "There are {} files to encrypt:\n{}\nProceed with encryption?",
        to_process_files.len(),
        files_as_str_list
    );

    if Confirm::new(&confirm_str)
        .with_default(true)
        .prompt()
        .expect("Couldn't prompt to user")
    {
        begin_encrypt_files(ctx, &to_process_files)?
    }

    Ok(())
}

pub fn decrypt(ctx: &Context, to_decrypt_files: &Option<Vec<PathBuf>>) -> Result<(), CmdError> {
    let to_process_files: Vec<&RawConfigFile> = match to_decrypt_files {
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

    let identities_struct = ctx.get_identities()?;
    let identities: Vec<&dyn age::Identity> =
        identities_struct.iter().map(|i| i.as_ref()).collect();

    let files_as_str_list: String = to_process_files
        .iter()
        .map(|path| format!("\t- {}", path.out.display()))
        .join("\n");

    let confirm_str = format!(
        "There are {} files to decrypt:\n{}\nProceed with decryption?",
        to_process_files.len(),
        files_as_str_list
    );

    if Confirm::new(&confirm_str)
        .with_default(true)
        .prompt()
        .expect("Couldn't prompt to user")
    {
        begin_decrypt_files(ctx, &to_process_files, identities)?
    }

    Ok(())
}
