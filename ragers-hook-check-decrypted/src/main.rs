use lexopt::{Arg::Value, ValueExt};
use ragers_core::config::{
    self, ConfigContent, ConfigFile, ProcessableFile, RecipientsFactory, get_closest_config_path,
    get_processable_files,
};
use same_file::is_same_file;
use std::{fmt::Display, fs, path::PathBuf, str::FromStr, string::FromUtf8Error};

const HELP: &'static str = "ragers hook - check decrypted files

Usage: ragers-hook-check-decrypted [-c CONFIG] [--working-dir WORKING_DIR] (FILE)

Arguments:
  (FILE)            Optional path to a file to check against config. If not provided, check
                    against all files in the repo.

Options:
  -c, --config      Path to the config file to open. If not provided, default \".ragers.yaml\"
                    or \".ragers.yml\", in this order, is attempted. The search for the config
                    file will be attempted based on \"--working-dir\" if the path is relative.
                    It is left untouched if absolute.

  --working-dir     Path to the current working directory, or to the path where the check must
                    be completed. Must be relative to the paths checked in the config file. If
                    not provided, the default will be the current working directory.

  --help            I don't need to state the obvious. Do I?";

struct Args {
    // Path to the config file to open. If not provided, default ".ragers.yaml" or ".ragers.yml",
    // in this order, is attempted.
    // The search for the config file will be attempted based on "--working-dir" if the path is
    // relative. It is left untouched if absolute.
    config_path: Option<PathBuf>,

    // Path to the current working directory, or to the path where the check must be completed.
    // Must be relative to the paths checked in the config file. If not provided, the default will
    // be the current working directory.
    working_dir: PathBuf,

    // Optional Optional path to a file to check against config. If not provided, check against all
    // files in the repo.
    files_to_check: Vec<PathBuf>,
}

fn parse_args() -> Result<Args, ExecError> {
    use lexopt::prelude::{Long, Short};

    let mut config_path: Option<PathBuf> = None;
    let mut working_dir: PathBuf = std::env::current_dir()?;
    let mut file_to_check: Vec<PathBuf> = Vec::new();

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next()? {
        match arg {
            Short('c') | Long("config") => {
                config_path = Some(parser.value()?.parse()?);
            }
            Long("working-dir") => {
                let value = parser.value()?;
                let content: PathBuf = value.parse()?;
                if !content.is_dir() {
                    return Err(lexopt::Error::ParsingFailed {
                        value: value.to_string_lossy().to_string(),
                        error: "must point to a directory".into(),
                    }
                    .into());
                }
                working_dir = content;
            }
            Short('h') | Long("help") => {
                println!("{HELP}");
                std::process::exit(0);
            }
            Value(val) => {
                file_to_check.push(val.parse()?);
            }
            _ => {
                println!("{HELP}");
                std::process::exit(0);
            }
        }
    }

    Ok(Args {
        config_path,
        working_dir,
        files_to_check: file_to_check,
    })
}

fn main() {
    match wrap_execution() {
        Ok(_) => {}
        Err(err) => {
            println!("{}", err.kind);
            std::process::exit(err.exit_code)
        }
    };
}

fn wrap_execution() -> Result<(), ExecError> {
    let args = parse_args()?;

    let config_path = if args.config_path.is_none() {
        get_closest_config_path(&args.working_dir)?
    } else {
        args.config_path
    }
    .ok_or(ExecError {
        exit_code: exitcode::NOINPUT,
        kind: ExecErrorKind::NoConfigFound,
    })?;

    let config_content = String::from_utf8(std::fs::read(&config_path)?)?;

    let config = ConfigFile::new(&config_path, ConfigContent::from_str(&config_content)?);
    let recipients_factory = RecipientsFactory::new(&config);

    let processable_files = get_processable_files(&config, &recipients_factory)?;

    let mut detected_files: Vec<PathBuf> = Vec::new();

    let files_to_check = {
        if !args.files_to_check.is_empty() {
            processable_files
                .into_iter()
                .filter(|file| {
                    for arg_file in &args.files_to_check {
                        if is_same_file(arg_file, &file.src).unwrap_or(false) {
                            return true;
                        }
                    }
                    return false;
                })
                .collect::<Vec<ProcessableFile>>()
        } else {
            processable_files
        }
    };

    for file in &files_to_check {
        let path = args.working_dir.join(&file.src);
        if fs::exists(&path)? {
            detected_files.push(path);
        }
    }

    if detected_files.is_empty() {
        return Ok(());
    }

    for file in &detected_files {
        println!("DECRYPTED FILE FOUND: {}", file.display())
    }
    std::process::exit(1);
}

struct ExecError {
    kind: ExecErrorKind,
    exit_code: i32,
}

enum ExecErrorKind {
    NoConfigFound,

    ConfigError(config::ConfigError),

    CmdParseError(lexopt::Error),

    Io(std::io::Error),

    FromUtf8Error(FromUtf8Error),
}

impl From<lexopt::Error> for ExecError {
    fn from(value: lexopt::Error) -> Self {
        Self {
            kind: ExecErrorKind::CmdParseError(value),
            exit_code: exitcode::USAGE,
        }
    }
}

impl From<std::io::Error> for ExecError {
    fn from(value: std::io::Error) -> Self {
        Self {
            kind: ExecErrorKind::Io(value),
            exit_code: exitcode::IOERR,
        }
    }
}

impl From<FromUtf8Error> for ExecError {
    fn from(value: FromUtf8Error) -> Self {
        Self {
            kind: ExecErrorKind::FromUtf8Error(value),
            exit_code: exitcode::IOERR,
        }
    }
}

impl From<config::ConfigError> for ExecError {
    fn from(value: config::ConfigError) -> Self {
        Self {
            kind: ExecErrorKind::ConfigError(value),
            exit_code: exitcode::CONFIG,
        }
    }
}

impl Display for ExecErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error: ")?;
        match self {
            Self::NoConfigFound => {
                write!(f, "no config file was found")
            }
            Self::CmdParseError(err) => {
                write!(f, "{err}")
            }
            Self::Io(err) => {
                write!(f, "{err}")
            }
            Self::FromUtf8Error(err) => {
                write!(f, "{err}")
            }
            Self::ConfigError(err) => {
                write!(f, "error with config: {err}")
            }
        }
    }
}
