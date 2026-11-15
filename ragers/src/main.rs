use clap::{CommandFactory, Parser};
use ragers::libconfig::get_closest_config_path;

use crate::{
    cli::{Cli, cmd},
    config::RawConfig,
    error::{CmdError, WithPath},
};

mod cli;
mod config;
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
            match get_closest_config_path().result_with_path(None)? {
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

    let config = RawConfig::new(&config_path)?;

    let ctx = context::Context::new(cli, &config, config_path)?;

    match &ctx.cli.command {
        Some(cli::Commands::Encrypt { files, no_delete }) => cmd::encrypt(&ctx, files, no_delete)?,
        Some(cli::Commands::Decrypt {
            files,
            identity,
            no_delete,
        }) => cmd::decrypt(&ctx, files, identity, no_delete)?,
        Some(cli::Commands::Edit { file, identity }) => cmd::edit(&ctx, file, identity)?,
        None => {
            Cli::command().print_help().unwrap();
        }
    };

    Ok(())
}
