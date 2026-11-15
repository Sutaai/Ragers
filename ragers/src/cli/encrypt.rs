use std::{fs, path::PathBuf};

use itertools::Itertools;
use same_file::is_same_file;

use crate::{
    cli::{
        Action, FailurePolicy, NoDeleteArg, confirm_action, get_encrypted_content,
        get_processable_files,
    },
    context::Context,
    error::{CmdError, WithPath},
};
use ragers::libconfig::ProcessableFile;

pub fn encrypt(
    ctx: &Context,
    files_to_encrypt: &Option<Vec<PathBuf>>,
    no_delete: &NoDeleteArg,
) -> Result<(), CmdError> {
    let processable_files = match files_to_encrypt {
        None => get_processable_files(ctx)?,
        Some(selected_files) => get_processable_files(ctx)?
            .into_iter()
            .filter(|file| {
                for select_file in selected_files {
                    if is_same_file(&file.src, select_file).unwrap_or(false) {
                        return true;
                    };
                }
                false
            })
            .collect(),
    };

    if processable_files.is_empty() {
        return Err(CmdError::NoFilesToProcess);
    }

    if !ctx.cli.no_prompt && !confirm_action(&processable_files, Action::Encryption) {
        return Ok(());
    }

    let mut files_to_delete: Vec<PathBuf> = Vec::new();

    for file in processable_files {
        match process_file(&file) {
            Ok(_) => {
                println!("encrypted: {}", file.out.display());
                files_to_delete.push(file.src);
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

fn process_file(file: &ProcessableFile) -> Result<(), CmdError> {
    let recipients_refs = file.recipients.iter().map(|i| i.as_ref()).collect_vec();
    let encrypted_content = {
        let encrypted_content = std::fs::read(&file.src).result_with_path(Some(&file.src))?;
        get_encrypted_content(&encrypted_content, &recipients_refs, file.use_armor_format)?
    };

    std::fs::write(&file.out, &encrypted_content).result_with_path(Some(&file.out))?;

    Ok(())
}
