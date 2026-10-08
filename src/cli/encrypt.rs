use std::{fs, path::PathBuf};

use crate::{
    cli::{Action, confirm_action, find_comparable_path, get_encrypted_content}, config::{AsArmorFormat, RawConfigFile}, context::Context, error::{CmdError, DeleteFileError, ReadFileError, WriteFileError},
};

fn begin_encrypt_files(ctx: &Context, files: &[&RawConfigFile]) -> Result<(), CmdError> {
    let mut stdin_guard = ctx.stdin_guard.borrow_mut();

    for file in files {
        // Todo: Check for file existence, if does not exist,
        let recipients = ctx
            .recipients_factory
            .obtain_for_file(file, &mut stdin_guard)?;

        let recipient_refs: Vec<&dyn age::Recipient> =
            recipients.iter().map(|r| r.as_ref()).collect();

        let encrypted_content = {
            let encrypted_content = std::fs::read(&file.src).map_err(|err| ReadFileError {
                path: file.src.clone(),
                source: err,
            })?;
            get_encrypted_content(&encrypted_content, recipient_refs, file.armor.as_armor_format())?
        };

        // Write to encrypted file
        std::fs::write(&file.out, &encrypted_content).map_err(|err| WriteFileError {
            path: file.src.clone(),
            source: err,
        })?;

        // This should only be done after all files have been encrypted
        fs::remove_file(&file.src).map_err(|err| DeleteFileError {
            path: file.src.clone(),
            source: err,
        })?;
    }

    Ok(())
}

pub fn encrypt(ctx: &Context, files_to_encrypt: &Option<Vec<PathBuf>>) -> Result<(), CmdError> {
    let to_process_files: Vec<&RawConfigFile> = match files_to_encrypt {
        None => ctx.config.files.iter().collect(),
        Some(requested) => ctx
            .config
            .files
            .iter()
            .filter(|cfg| {
                find_comparable_path(&cfg.src, requested)
                    .ok()
                    .flatten()
                    .is_some()
            })
            .collect(),
    };

    if to_process_files.is_empty() {
        return Err(CmdError::NoFilesToProcess);
    }

    if confirm_action(&to_process_files, Action::Encryption) {
        begin_encrypt_files(ctx, &to_process_files)?
    };

    Ok(())
}
