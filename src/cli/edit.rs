use std::{fs, path::PathBuf};

use itertools::Itertools;

use crate::{
    cli::{
        IdentityArgs, find_comparable_path_single, get_decrypted_content, get_encrypted_content,
        get_identities, get_ragers_editor,
    }, config::AsArmorFormat, context::Context, error::{CmdError, ReadFileError, WriteFileError},
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
            find_comparable_path_single(&cfg.src, file_to_edit)
                .ok()
                .is_some()
                || find_comparable_path_single(&cfg.out, file_to_edit)
                    .ok()
                    .is_some()
        })
        .ok_or(CmdError::NoFilesToProcess)?;

    let is_encrypted = find_comparable_path_single(&matched_file.out, file_to_edit)?;
    let file_path = if is_encrypted {
        println!("info: matching against an encrypted file");
        &matched_file.out
    } else {
        println!("info: matching against a source file");
        &matched_file.src
    };

    let file_content = {
        if is_encrypted {
            let identities_struct = get_identities(&identities.identities_file)?;
            let final_identities: Vec<&dyn age::Identity> =
                identities_struct.iter().map(|i| i.as_ref()).collect();

            let encrypted_content = fs::read(file_path).map_err(|err| ReadFileError {
                path: file_path.clone(),
                source: err,
            })?;
            get_decrypted_content(&encrypted_content, &final_identities)?
        } else {
            fs::read(file_path).map_err(|err| ReadFileError {
                path: file_path.clone(),
                source: err,
            })?
        }
    };
    let file_content_str = String::from_utf8(file_content).map_err(|_| {
        CmdError::IO(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("'{}' could not be converted to utf8", file_path.display()),
        ))
    })?;

    let suffix = matched_file
        .src
        .extension()
        .map_or(".txt".to_owned(), |e| format!(".{}", e.to_string_lossy()));
    // .unwrap_or_else(|| OsStr::new(".txt"))
    // .to_string_lossy();

    // Open editor
    let ragers_editor = get_ragers_editor();

    let mut editor = inquire::Editor::new("your file can be edited in your editor:")
        .with_file_extension(&suffix)
        .with_predefined_text(&file_content_str);

    if let Some(editor_command) = &ragers_editor {
        editor = editor.with_editor_command(editor_command.as_os_str());
    }

    let new_content = editor.prompt().unwrap();

    match is_encrypted {
        false => fs::write(file_path, new_content.as_bytes()).map_err(|err| WriteFileError {
            path: file_path.clone(),
            source: err,
        })?,
        true => {
            let encrypted_content = {
                let mut stdin_guard = ctx.stdin_guard.borrow_mut();

                let recipients = ctx
                    .recipients_factory
                    .obtain_for_file(matched_file, &mut stdin_guard)?;
                let recipients_ref = recipients.iter().map(|r| r.as_ref()).collect_vec();

                get_encrypted_content(&new_content.into_bytes(), recipients_ref, matched_file.armor.as_armor_format())
            }?;

            std::fs::write(&matched_file.out, &encrypted_content).map_err(|err| {
                WriteFileError {
                    path: matched_file.out.clone(),
                    source: err,
                }
            })?;

            println!("info: new content has been saved in out (encrypted) file")
        }
    }
    Ok(())
}
