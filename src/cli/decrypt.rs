use std::{fs, path::PathBuf};

use crate::{
    cli::{
        Action, IdentityArgs, confirm_action, get_decrypted_content, get_identities,
        obtain_files_to_process,
    },
    config::RawConfigFile,
    context::Context,
    error::CmdError,
};

pub fn decrypt(
    ctx: &Context,
    files_to_decrypt: &Option<Vec<PathBuf>>,
    identities: &IdentityArgs,
) -> Result<(), CmdError> {
    let to_process_files: Vec<&RawConfigFile> = obtain_files_to_process(ctx, files_to_decrypt)?;

    let identities_struct = get_identities(ctx, &identities.identities_file)?;
    let identities: Vec<&dyn age::Identity> =
        identities_struct.iter().map(|i| i.as_ref()).collect();

    if confirm_action(&to_process_files, Action::Decryption) {
        for file in &to_process_files {
            // Todo: Check for file existence, if does not exist,
            let decrypted_content = {
                let encrypted_content = std::fs::read(&file.out)?;
                get_decrypted_content(&encrypted_content, &identities)?
            };

            std::fs::write(&file.src, &decrypted_content)?;

            // This should only be done after all files have been decrypted
            fs::remove_file(&file.out)?;
        }
    };

    Ok(())
}
