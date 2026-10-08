use std::{fs, path::PathBuf};

use crate::{
    cli::{
        Action, IdentityArgs, confirm_action, find_comparable_path, get_decrypted_content,
        get_identities,
    },
    config::RawConfigFile,
    context::Context,
    error::{CmdError, DeleteFileError, ReadFileError, WriteFileError},
};

fn begin_decrypt_files(
    files: &[&RawConfigFile],
    identities: Vec<&dyn age::Identity>,
) -> Result<(), CmdError> {
    for file in files {
        // Todo: Check for file existence, if does not exist,
        let decrypted_content = {
            let encrypted_content = std::fs::read(&file.out).map_err(|err| ReadFileError {
                path: file.out.clone(),
                source: err,
            })?;
            get_decrypted_content(&encrypted_content, &identities)?
        };

        std::fs::write(&file.src, &decrypted_content).map_err(|err| WriteFileError {
            path: file.src.clone(),
            source: err,
        })?;

        // This should only be done after all files have been decrypted
        fs::remove_file(&file.out).map_err(|err| DeleteFileError {
            path: file.out.clone(),
            source: err,
        })?;
    }

    Ok(())
}

pub fn decrypt(
    ctx: &Context,
    files_to_decrypt: &Option<Vec<PathBuf>>,
    identities: &IdentityArgs,
) -> Result<(), CmdError> {
    let to_process_files: Vec<&RawConfigFile> = match files_to_decrypt {
        None => ctx.config.files.iter().collect(),
        Some(requested) => ctx
            .config
            .files
            .iter()
            .filter(|cfg| {
                find_comparable_path(&cfg.out, requested)
                    .ok()
                    .flatten()
                    .is_some()
            })
            .collect(),
    };

    if to_process_files.is_empty() {
        return Err(CmdError::NoFilesToProcess);
    }

    let identities_struct = get_identities(&identities.identities_file)?;
    let identities: Vec<&dyn age::Identity> =
        identities_struct.iter().map(|i| i.as_ref()).collect();

    if confirm_action(&to_process_files, Action::Decryption) {
        begin_decrypt_files(&to_process_files, identities)?
    };

    Ok(())
}
