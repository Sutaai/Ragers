use std::{fs, path::PathBuf};

use crate::{
    cli::{
        Action, FailurePolicy, NoDeleteArg, confirm_action, get_encrypted_content,
        obtain_files_to_process,
    },
    config::AsArmorFormat,
    context::Context,
    error::{CmdError, WithPath},
};

pub fn encrypt(
    ctx: &Context,
    files_to_encrypt: &Option<Vec<PathBuf>>,
    no_delete: &NoDeleteArg,
) -> Result<(), CmdError> {
    let to_process_files = obtain_files_to_process(ctx, files_to_encrypt)?;

    if !ctx.cli.no_prompt && !confirm_action(&to_process_files, Action::Encryption) {
        return Ok(());
    }

    let mut stdin_guard = ctx.stdin_guard.borrow_mut();
    let mut files_to_delete: Vec<&PathBuf> = Vec::new();

    for file in to_process_files {
        match process_file(ctx, &mut stdin_guard, file) {
            Ok(_) => {
                println!("encrypted: {}", file.out.display());
                files_to_delete.push(&file.src);
            }
            Err(err) => match &ctx.cli.on_failure {
                FailurePolicy::Abort => return Err(err),
                FailurePolicy::Ignore => {
                    println!("ignored: {}", file.src.display());
                    continue;
                }
                FailurePolicy::AbortAtomic => unimplemented!(),
            },
        };
    }

    if !no_delete.no_delete {
        for file in files_to_delete {
            fs::remove_file(&file).result_with_path(Some(&file))?;
            println!("deleted: {}", file.display());
        }
    }

    Ok(())
}

fn process_file(
    ctx: &Context,
    stdin_guard: &mut std::cell::RefMut<'_, age::cli_common::StdinGuard>,
    file: &crate::config::RawConfigFile,
) -> Result<(), CmdError> {
    let recipients = ctx.recipients_factory.obtain_for_file(file, stdin_guard)?;
    let recipient_refs: Vec<&dyn age::Recipient> = recipients.iter().map(|r| r.as_ref()).collect();
    let encrypted_content = {
        let encrypted_content = std::fs::read(&file.src).result_with_path(Some(&file.src))?;
        get_encrypted_content(
            &encrypted_content,
            recipient_refs,
            file.armor.as_armor_format(),
        )?
    };

    std::fs::write(&file.out, &encrypted_content).result_with_path(Some(&file.out))?;

    Ok(())
}
