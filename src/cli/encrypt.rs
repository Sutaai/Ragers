use std::{fs, path::PathBuf};

use crate::{
    cli::{Action, confirm_action, get_encrypted_content, obtain_files_to_process},
    config::AsArmorFormat,
    context::Context,
    error::CmdError,
};

pub fn encrypt(ctx: &Context, files_to_encrypt: &Option<Vec<PathBuf>>) -> Result<(), CmdError> {
    let to_process_files = obtain_files_to_process(ctx, files_to_encrypt)?;

    if !ctx.cli.no_prompt && !confirm_action(&to_process_files, Action::Encryption) {
        return Ok(());
    }

    let mut stdin_guard = ctx.stdin_guard.borrow_mut();

    for file in to_process_files {
        // Todo: Check for file existence, if does not exist,
        let recipients = ctx
            .recipients_factory
            .obtain_for_file(file, &mut stdin_guard)?;

        let recipient_refs: Vec<&dyn age::Recipient> =
            recipients.iter().map(|r| r.as_ref()).collect();

        let encrypted_content = {
            let encrypted_content = std::fs::read(&file.src)?;
            get_encrypted_content(
                &encrypted_content,
                recipient_refs,
                file.armor.as_armor_format(),
            )?
        };

        // Write to encrypted file
        std::fs::write(&file.out, &encrypted_content)?;
        println!("encrypted: {}", file.out.display());

        // This should only be done after all files have been encrypted
        fs::remove_file(&file.src)?;
        println!("deleted: {}", file.src.display());
    }

    Ok(())
}
