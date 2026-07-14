use clap::{CommandFactory, Parser};
use env_logger::fmt::style;
use std::io::Write;

use crate::{
    cli::{Cli, decrypt, encrypt},
    error::CmdError,
};

mod cli;
mod config;
mod context;
mod error;

fn setup_logger(level: &log::LevelFilter) {
    env_logger::builder()
        .default_format()
        .filter_level(*level)
        .format(|buf, record| {
            let level_str = match record.level() {
                log::Level::Error => {
                    let lvl_style = style::Style::new()
                        .bold()
                        .effects(style::Effects::BOLD)
                        .fg_color(Some(style::AnsiColor::BrightRed.into()));
                    format!("{lvl_style}[ERROR]{lvl_style:#}")
                }
                log::Level::Warn => {
                    let lvl_style =
                        style::Style::new().fg_color(Some(style::AnsiColor::BrightYellow.into()));
                    format!("{lvl_style}[WARN]{lvl_style:#}")
                }
                log::Level::Info => {
                    let lvl_style =
                        style::Style::new().fg_color(Some(style::AnsiColor::Blue.into()));
                    format!("{lvl_style}[I]{lvl_style:#}")
                }
                log::Level::Debug => {
                    let lvl_style = style::Style::new().effects(style::Effects::DIMMED);
                    format!("{lvl_style}[D]{lvl_style:#}")
                }
                log::Level::Trace => {
                    let lvl_style = style::Style::new().effects(style::Effects::DIMMED);
                    format!("{lvl_style}[T]{lvl_style:#}")
                }
            };

            let mod_style = style::Style::new()
                .fg_color(Some(style::AnsiColor::Yellow.into()))
                .effects(style::Effects::ITALIC);
            writeln!(
                buf,
                "{} ({mod_style}{}{mod_style:#}): {}",
                level_str,
                record.metadata().target(),
                record.args()
            )
        })
        .init();
}

fn handle_cmd_error(_err: CmdError) {
    unimplemented!()
}

fn main() {
    match wrap_execution() {
        Ok(_) => {} // Execution is done
        Err(err) => handle_cmd_error(err),
    }
}

fn wrap_execution() -> Result<(), CmdError> {
    let cli = Cli::parse();
    setup_logger(&cli.log_level);

    let ctx = context::Context::new(cli)?;

    match &ctx.cli.command {
        Some(cli::Commands::Encrypt { files }) => encrypt(&ctx, files)?,
        Some(cli::Commands::Decrypt { files }) => decrypt(&ctx, files)?,
        None => {
            Cli::command().print_help().unwrap();
        }
    };

    Ok(())
}
