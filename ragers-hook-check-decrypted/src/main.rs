use lexopt::{Arg::Value, ValueExt};
use serde::Deserialize;
use std::{fmt::Display, fs, path::PathBuf, string::FromUtf8Error};
use yaml_serde;

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
    config: Option<PathBuf>,

    // Path to the current working directory, or to the path where the check must be completed.
    // Must be relative to the paths checked in the config file. If not provided, the default will
    // be the current working directory.
    working_dir: PathBuf,

    // Optional Optional path to a file to check against config. If not provided, check against all
    // files in the repo.
    files_to_check: Vec<PathBuf>,
}

#[derive(Deserialize, Debug)]
struct Config {
    /// A list of files
    files: Vec<ConfigFile>,
}

#[derive(Deserialize, Debug)]
struct ConfigFile {
    /// The path of the unencrypted file source
    pub src: PathBuf,
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
        config: config_path,
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

fn get_config_path(args: &Args) -> Result<PathBuf, ExecError> {
    let defined_custom_config = &args.config;

    if let Some(custom_config_path) = defined_custom_config {
        if custom_config_path.is_absolute() {
            return Ok(custom_config_path.clone());
        }

        return Ok(args.working_dir.join(custom_config_path));
    }

    let yml_or_yaml_for_default: Option<PathBuf> = {
        let yaml_ver = args.working_dir.join(".ragers.yaml");
        let yml_ver = args.working_dir.join(".ragers.yml");
        if fs::exists(&yaml_ver)? {
            Some(yaml_ver)
        } else if fs::exists(&yml_ver)? {
            Some(yml_ver)
        } else {
            None
        }
    };

    if let Some(default_config) = yml_or_yaml_for_default {
        return Ok(default_config);
    }

    return Err(ExecError {
        kind: ExecErrorKind::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "config file not found",
        )),
        exit_code: exitcode::DATAERR,
    });
}

fn wrap_execution() -> Result<(), ExecError> {
    let args = parse_args()?;

    let config = get_config_path(&args)?;
    let work_dir = &args.working_dir;

    let file_content = String::from_utf8(std::fs::read(config)?)?;
    let toml_struct: Config = yaml_serde::from_str(&file_content)?;

    let mut detected_files: Vec<PathBuf> = Vec::new();

    let files_to_check = {
        if !args.files_to_check.is_empty() {
            toml_struct
                .files
                .into_iter()
                .filter(|file| args.files_to_check.contains(&file.src))
                .collect::<Vec<ConfigFile>>()
        } else {
            toml_struct.files
        }
    };

    for file in &files_to_check {
        let path = work_dir.join(&file.src);
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
    CmdParseError(lexopt::Error),

    Io(std::io::Error),

    FromUtf8Error(FromUtf8Error),

    DeserializeError(yaml_serde::Error),
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

impl From<yaml_serde::Error> for ExecError {
    fn from(value: yaml_serde::Error) -> Self {
        Self {
            kind: ExecErrorKind::DeserializeError(value),
            exit_code: exitcode::CONFIG,
        }
    }
}

impl Display for ExecErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "error: ")?;
        match self {
            Self::CmdParseError(err) => {
                write!(f, "{err}")
            }
            Self::Io(err) => {
                write!(f, "{err}")
            }
            Self::FromUtf8Error(err) => {
                write!(f, "{err}")
            }
            Self::DeserializeError(err) => {
                write!(f, "config deserialization: {err}")
            }
        }
    }
}
