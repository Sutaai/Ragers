use std::{fs, path::PathBuf};

use itertools::Itertools;

use crate::{
    cli::{
        Action, FailurePolicy, IdentityArg, NoDeleteArg, confirm_action, get_decrypted_content,
        get_identities, obtain_files_to_process,
    },
    config::RawConfigFile,
    context::Context,
    error::{CmdError, WithPath},
};

pub fn decrypt(
    ctx: &Context,
    files_to_decrypt: &Option<Vec<PathBuf>>,
    identities: &IdentityArg,
    no_delete: &NoDeleteArg,
) -> Result<(), CmdError> {
    let to_process_files: Vec<&RawConfigFile> = obtain_files_to_process(ctx, files_to_decrypt)?;

    let identities_struct = get_identities(ctx, &identities.identities_file)?;
    let identities = identities_struct.iter().map(|i| i.as_ref()).collect_vec();

    if !ctx.cli.no_prompt && !confirm_action(&to_process_files, Action::Decryption) {
        return Ok(());
    };

    let mut files_to_delete: Vec<&PathBuf> = Vec::new();

    for file in to_process_files {
        // Todo: Check for file existence, if does not exist,
        match process_file(file, &identities) {
            Ok(_) => {
                println!("decrypted: {}", file.src.display());
                files_to_delete.push(&file.out);
            }
            Err(err) => match &ctx.cli.on_failure {
                FailurePolicy::Abort => return Err(err),
                FailurePolicy::Ignore => {
                    println!("ignored: {}", file.out.display());
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

fn process_file(file: &RawConfigFile, identities: &[&dyn age::Identity]) -> Result<(), CmdError> {
    let decrypted_content = {
        let encrypted_content = std::fs::read(&file.out).result_with_path(Some(&file.out))?;
        get_decrypted_content(&encrypted_content, &identities)?
    };

    std::fs::write(&file.src, &decrypted_content).result_with_path(Some(&file.src))?;

    Ok(())
}
