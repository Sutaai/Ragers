use clap::{CommandFactory, Parser};

use crate::{
    cli::{Cli, decrypt, encrypt},
    config::RawConfig,
    error::CmdError,
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
        },
    }
}

fn wrap_execution(cli: Cli) -> Result<(), CmdError> {
    let config = RawConfig::new(&cli.config_path)?;
    let ctx = context::Context::new(cli, &config)?;

    match &ctx.cli.command {
        Some(cli::Commands::Encrypt { files }) => encrypt(&ctx, files)?,
        Some(cli::Commands::Decrypt { files }) => decrypt(&ctx, files)?,
        None => {
            Cli::command().print_help().unwrap();
        }
    };

    Ok(())
}
