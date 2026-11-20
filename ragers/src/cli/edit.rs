use std::{fs, path::PathBuf};

use itertools::Itertools;
use same_file::is_same_file;

use crate::{
    cli::{
        IdentityArg, get_decrypted_content, get_encrypted_content, get_identities,
        get_processable_files, get_ragers_editor,
    },
    context::Context,
    error::{CmdError, WithPath},
};

pub fn edit(
    ctx: &Context,
    file_to_edit: &PathBuf,
    identities: &IdentityArg,
) -> Result<(), CmdError> {
    if ctx.cli.no_prompt {
        println!("error: this command requires prompting, but no prompt has been set");
        return Ok(());
    }

    let all_processable_files = get_processable_files(ctx)?;
    let matching_file = all_processable_files
        .iter()
        .find(|file| {
            is_same_file(&file.src, file_to_edit)
                .ok()
                .is_some_and(|p| p)
                || is_same_file(&file.out, file_to_edit)
                    .ok()
                    .is_some_and(|p| p)
        })
        .ok_or_else(|| CmdError::NoFilesToProcess)?;

    let is_encrypted = is_same_file(&matching_file.out, file_to_edit).is_ok();
    let file_path = if is_encrypted {
        println!("info: matching against an encrypted file");
        &matching_file.out
    } else {
        println!("info: matching against a source file");
        &matching_file.src
    };

    let raw_content = {
        let buffer = if is_encrypted {
            let identities =
                get_identities(ctx, &identities.path_to_identities(&ctx.config.base_path))?;
            let identities_refs: Vec<&dyn age::Identity> =
                identities.iter().map(|i| i.as_ref()).collect();
            let encrypted_content = fs::read(file_path).result_with_path(Some(file_path))?;
            get_decrypted_content(&encrypted_content, &identities_refs)?
        } else {
            fs::read(file_path).result_with_path(Some(file_path))?
        };

        String::from_utf8(buffer).map_err(|_| CmdError::Io {
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("'{}' could not be converted to utf8", file_path.display()),
            ),
            path: Some(file_path.clone()),
        })?
    };

    let suffix = matching_file
        .src
        .extension()
        .map_or(".txt".to_owned(), |e| format!(".{}", e.to_string_lossy()));

    // Open editor
    let ragers_editor = get_ragers_editor(ctx);

    let filename = format!(
        "edit {}:",
        file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
    );
    let mut editor = inquire::Editor::new(&filename)
        .with_file_extension(&suffix)
        .with_predefined_text(&raw_content);

    if let Some(editor_command) = &ragers_editor {
        editor = editor.with_editor_command(editor_command.as_os_str());
    }

    let new_content = editor.prompt()?;

    match is_encrypted {
        false => fs::write(file_path, new_content.as_bytes()).result_with_path(Some(file_path))?,
        true => {
            let encrypted_content = {
                let recipients = matching_file
                    .recipients
                    .iter()
                    .map(|r| r.as_ref())
                    .collect_vec();

                get_encrypted_content(
                    &new_content.into_bytes(),
                    &recipients,
                    matching_file.use_armor_format,
                )
            }?;

            std::fs::write(&matching_file.out, &encrypted_content)
                .result_with_path(Some(&matching_file.out))?;
        }
    }
    Ok(())
}
