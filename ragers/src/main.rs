use clap::{CommandFactory, Parser};

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
        Ok(_) => {} // Execution is done
        Err(err) => {
            println!("error: {err}")
        }
    }
}

fn wrap_execution(cli: Cli) -> Result<(), CmdError> {
    match &cli.command {
        None => {
            Cli::command().print_help().unwrap();
            return Ok(());
        }
        _ => {}
    }

    let config_path = {
        if let Some(custom_config_path) = &cli.config_path {
            custom_config_path.clone()
        } else {
            let working_dir = std::env::current_dir().result_with_path(None)?;
            let yaml_ver = working_dir.join(".ragers.yaml");
            let yml_ver = working_dir.join(".ragers.yml");
            if std::fs::exists(&yaml_ver).result_with_path(Some(&yaml_ver))? {
                yaml_ver
            } else if std::fs::exists(&yml_ver).result_with_path(Some(&yml_ver))? {
                yml_ver
            } else {
                return Err(CmdError::Io {
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no config file found",
                    ),
                    path: None,
                });
            }
        }
    };

    let config = RawConfig::new(&config_path)?;

    let ctx = context::Context::new(cli, &config)?;

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
