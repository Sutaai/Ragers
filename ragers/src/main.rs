use std::{fs::read_to_string, str::FromStr};

use clap::{CommandFactory, Parser};

use crate::{
    cli::{Cli, cmd},
    error::{CmdError, WithPath},
};

use ragers_core::config::{ConfigContent, ConfigFile, get_closest_config_path};

mod cli;
mod context;
mod error;

fn main() {
    let cli = Cli::parse();
    match wrap_execution(cli) {
        Ok(_) => {
            std::process::exit(0);
        } // Execution is done
        Err(err) => {
            println!("error: {err}");
            std::process::exit(1);
        }
    }
}

fn wrap_execution(cli: Cli) -> Result<(), CmdError> {
    if cli.command.is_none() {
        Cli::command().print_help().unwrap();
        return Ok(());
    }

    let config_path = {
        if let Some(custom_config_path) = &cli.config_path {
            custom_config_path.clone()
        } else {
            match get_closest_config_path(&std::env::current_dir().result_with_path(None)?)
                .result_with_path(None)?
            {
                Some(path) => path,
                None => {
                    return Err(CmdError::Io {
                        source: std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "no config file found",
                        ),
                        path: None,
                    });
                }
            }
        }
    };

    let config_content = read_to_string(&config_path).map_err(|err| CmdError::Io {
        source: err,
        path: Some(config_path.clone()),
    })?;

    let config_content = ConfigContent::from_str(&config_content)?;
    let config = ConfigFile::new(&config_path, config_content);

    let ctx = context::Context::new(cli, &config)?;

    match &ctx.cli.command {
        Some(cli::Commands::Encrypt { files, no_delete }) => cmd::encrypt(&ctx, files, no_delete)?,
        Some(cli::Commands::Decrypt {
            files,
            identity,
            no_delete,
        }) => cmd::decrypt(&ctx, files, identity, no_delete)?,
        Some(cli::Commands::Edit { file, identity }) => cmd::edit(&ctx, file, identity)?,
        None => panic!("can't be reached"),
    };

    Ok(())
}
