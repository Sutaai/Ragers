use std::{fs, path::PathBuf};

use itertools::Itertools;

use crate::{
    cli::{
        IdentityArgs, get_decrypted_content, get_encrypted_content, get_identities,
        get_ragers_editor, is_same_path,
    },
    config::AsArmorFormat,
    context::Context,
    error::CmdError,
};

pub fn edit(
    ctx: &Context,
    file_to_edit: &PathBuf,
    identities: &IdentityArgs,
) -> Result<(), CmdError> {
    let matched_file = ctx
        .config
        .files
        .iter()
        .find(|cfg| {
            is_same_path(&cfg.src, file_to_edit).ok().is_some()
                || is_same_path(&cfg.out, file_to_edit).ok().is_some()
        })
        .ok_or(CmdError::NoFilesToProcess)?;

    let is_encrypted = is_same_path(&matched_file.out, file_to_edit)?;
    let file_path = if is_encrypted {
        println!("info: matching against an encrypted file");
        &matched_file.out
    } else {
        println!("info: matching against a source file");
        &matched_file.src
    };

    let raw_content = {
        let buffer = if is_encrypted {
            let identities = get_identities(ctx, &identities.identities_file)?;
            let identities_refs: Vec<&dyn age::Identity> =
                identities.iter().map(|i| i.as_ref()).collect();
            let encrypted_content = fs::read(file_path)?;
            get_decrypted_content(&encrypted_content, &identities_refs)?
        } else {
            fs::read(file_path)?
        };

        String::from_utf8(buffer).map_err(|_| {
            CmdError::IO(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("'{}' could not be converted to utf8", file_path.display()),
            ))
        })?
    };

    let suffix = matched_file
        .src
        .extension()
        .map_or(".txt".to_owned(), |e| format!(".{}", e.to_string_lossy()));

    // Open editor
    let ragers_editor = get_ragers_editor();

    let filename = format!(
        "edit {}:",
        file_path.file_name().and_then(|n| n.to_str()).unwrap_or("?")
    );
    let mut editor = inquire::Editor::new(&filename)
        .with_file_extension(&suffix)
        .with_predefined_text(&raw_content);

    if let Some(editor_command) = &ragers_editor {
        editor = editor.with_editor_command(editor_command.as_os_str());
    }

    let new_content = editor.prompt()?;

    match is_encrypted {
        false => fs::write(file_path, new_content.as_bytes())?,
        true => {
            let encrypted_content = {
                let mut stdin_guard = ctx.stdin_guard.borrow_mut();

                let recipients = ctx
                    .recipients_factory
                    .obtain_for_file(matched_file, &mut stdin_guard)?;
                let recipients_ref = recipients.iter().map(|r| r.as_ref()).collect_vec();

                get_encrypted_content(
                    &new_content.into_bytes(),
                    recipients_ref,
                    matched_file.armor.as_armor_format(),
                )
            }?;

            std::fs::write(&matched_file.out, &encrypted_content)?;
        }
    }
    Ok(())
}
