use std::{
    fs,
    io::{Read, Write},
    path::{self, PathBuf},
    rc::Rc,
};

use clap::{Parser, Subcommand};
use inquire::Confirm;
use itertools::Itertools;
use log::error;

use crate::{
    config::RawConfigFile, context::{Context, load_identities, load_identities_from_values}, error::{CmdError, RecipientsFactoryError},
};

#[derive(Parser)]
#[command(version, about)]
#[command(next_line_help = true)]
pub struct Cli {
    #[arg(
        short,
        long,
        action = clap::ArgAction::Set,
        default_value = "info",
        env = "RAGERS_LOG_LEVEL",
        help = "Log level",
        value_parser = clap::value_parser!(log::LevelFilter),
        long_help = "The log level when running. By default, this is set to 'info'. Possible values are (in order of severity): 'off'. 'error', 'warn', 'info', 'debug'. 'trace'."
    )]
    pub log_level: log::LevelFilter,

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
        long,
        action = clap::ArgAction::Append,
        env = "RAGERS_IDENTITY_FILE",
        help = "Path to an identity file used to decrypt files. May be repeated.",
        value_hint = clap::ValueHint::FilePath,
        value_parser = clap::value_parser!(PathBuf),
        long_help = "Path to a file containing one or more private keys (age identities, or a single SSH private key) used to decrypt files. This flag may be repeated to supply multiple identities; all of them will be tried against every encrypted file."
    )]
    pub identity: Vec<PathBuf>,

    #[arg(
        short = 'i',
        long,
        action = clap::ArgAction::Append,
        env = "RAGERS_IDENTITY",
        help = "Raw identity (private key) value used to decrypt files, provided directly instead of via a file. May be repeated.",
        long_help = "Raw identity (private key) value, provided directly instead of via a file. This may be an age identity (an 'AGE-SECRET-KEY-1...' value, optionally with several such values on separate lines), or a single SSH private key. This flag may be repeated to supply multiple identities; all of them will be tried against every encrypted file. When set through its environment variable, only a single occurrence is read, but that value may itself contain multiple newline-separated age identities."
    )]
    pub identity_value: Vec<String>,

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
fn find_comparable_path<'a>(path: &PathBuf, list: &'a [PathBuf]) -> Option<&'a PathBuf> {
    let full_path = path::absolute(path).expect("could not convert path to absolute path");

    for listed_path in list {
        if let Ok(compare_path) = std::path::absolute(listed_path) {
            if full_path == compare_path {
                return Some(listed_path);
            }
        }
    }

    None
}

fn begin_encrypt_files(ctx: &mut Context, files: &[&RawConfigFile]) -> Result<(), RecipientsFactoryError> {
    for file in files {
        // Obtain recipients
        let age_recipients = ctx.recipients_factory.obtain_for_file(&file)?;

        let recipient_refs: Vec<&dyn age::Recipient> =
            age_recipients.iter().map(|r| r.as_ref()).collect();

        // Configure age's encryptor
        let encryptor: age::Encryptor = age::Encryptor::with_recipients(recipient_refs.into_iter())
            .expect("expected encryptor to accept recipients");
        let format: age::armor::Format = if file.armor {
            age::armor::Format::AsciiArmor
        } else {
            age::armor::Format::Binary
        };

        let plaintext = std::fs::read(&file.src).expect(&format!(
            "could not read source file \"{}\"",
            file.src.display()
        ));

        let output = std::fs::File::create(&file.out).expect(&format!(
            "could not create output file \"{}\"",
            file.out.display()
        ));

        let armored_output = age::armor::ArmoredWriter::wrap_output(output, format)
            .expect("could not wrap output writer");

        let mut writer = encryptor
            .wrap_output(armored_output)
            .expect("could not begin encryption");

        writer
            .write_all(&plaintext)
            .expect("could not write plaintext to encrypted output");

        writer
            .finish()
            .and_then(|armor| armor.finish())
            .expect("could not finish encryption");

        fs::remove_file(&file.src)
            .unwrap_or_else(|_| error!("Could not delete file source: {}", file.src.display()));

    }

    Ok(())
}

fn begin_decrypt_files(ctx: &Context, files: &[&RawConfigFile]) {
    let mut identities = load_identities(&ctx.cli.identity);
    identities.extend(load_identities_from_values(&ctx.cli.identity_value));

    let identity_refs: Vec<&dyn age::Identity> = identities.iter().map(|i| i.as_ref()).collect();

    for file in files {
        let encrypted = std::fs::File::open(&file.out).expect(&format!(
            "could not open encrypted file \"{}\"",
            file.out.display()
        ));

        // ArmoredReader auto-detects whether the input is ASCII-armored or binary.
        let armored_reader = age::armor::ArmoredReader::new(encrypted);

        let decryptor = age::Decryptor::new_buffered(armored_reader).expect(&format!(
            "could not read age header from \"{}\", is it a valid age file?",
            file.out.display()
        ));

        let mut reader = decryptor
            .decrypt(identity_refs.iter().copied())
            .expect(&format!(
                "could not decrypt \"{}\" with the provided identities",
                file.out.display()
            ));

        let mut plaintext = Vec::new();
        reader
            .read_to_end(&mut plaintext)
            .expect("could not read decrypted contents");

        std::fs::write(&file.src, &plaintext).expect(&format!(
            "could not write decrypted file to \"{}\"",
            file.src.display()
        ));

        fs::remove_file(&file.out).unwrap_or_else(|_| {
            error!(
                "Could not delete encrypted file source: {}",
                file.src.display()
            )
        });
    }
}

pub fn encrypt(ctx: &mut Context, to_encrypt_files: &Option<Vec<PathBuf>>) -> Result<(), CmdError> {
    let to_process_files: Vec<&RawConfigFile> = match to_encrypt_files {
        None => ctx.config.files.iter().collect(),
        Some(requested) => ctx
            .config
            .files
            .iter()
            .filter(|cfg| find_comparable_path(&cfg.src, requested).is_some())
            .collect(),
    };

    if to_process_files.is_empty() {
        println!("There are no files to encrypt.");
        return Ok(());
    }

    let files_as_str_list: String = to_process_files
        .iter()
        .map(|path| format!("\t- {}", path.src.display()))
        .join("\n");

    let confirm_str = format!(
        "There are {} files to encrypt:\n{}\nProceed with encryption?",
        &to_process_files.len(),
        files_as_str_list
    );

    if Confirm::new(&confirm_str)
        .with_default(true)
        .prompt()
        .expect("Couldn't prompt to user")
    {
        begin_encrypt_files(&mut ctx, &to_process_files)?
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
            .filter(|cfg| find_comparable_path(&cfg.out, requested).is_some())
            .collect(),
    };

    if to_process_files.is_empty() {
        println!("There are no files to decrypt.");
        return Ok(());
    }

    if ctx.cli.identity.is_empty() && ctx.cli.identity_value.is_empty() {
        println!(
            "No identity provided. Use --identity-file or --identity to supply decrypting identity."
        );
        return Ok(());
    }

    let files_as_str_list: String = to_process_files
        .iter()
        .map(|path| format!("\t- {}", path.out.display()))
        .join("\n");

    let confirm_str = format!(
        "There are {} files to decrypt:\n{}\nProceed with decryption?",
        &to_process_files.len(),
        files_as_str_list
    );

    if Confirm::new(&confirm_str)
        .with_default(true)
        .prompt()
        .expect("Couldn't prompt to user")
    {
        begin_decrypt_files(&ctx, &to_process_files)
    }

    Ok(())
}
