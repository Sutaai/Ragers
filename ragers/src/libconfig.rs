use std::path::PathBuf;

/// Names of the default config file that Ragers should look for.
const CONFIG_FILE_NAMES: [&str; 2] = [".ragers.yaml", ".ragers.yml"];

/// Obtain a list of all different paths that must be attempted in order to read config files.
/// Those paths are checked for existence, and can be attempted to be read.
///
/// The paths will be appended from the lowest priority to highest priority.
///
/// Each directory from the filesystem's root down to the current working directory is checked for
/// a `.ragers.yml` and a `.ragers.yaml` file, in this order. Therefore, files closer to the current
/// working directory take precedence over the ones further away, and in a same directory,
/// `.ragers.yaml` takes precedence over `.ragers.yml`.
///
/// Only paths pointing to existing files are returned. Directories that cannot be inspected due to
/// missing permissions are silently skipped.
pub fn obtain_default_configs_paths() -> Result<Vec<PathBuf>, std::io::Error> {
    let working_dir = std::env::current_dir()?;
    let mut valid_paths = Vec::new();

    let all_directories = working_dir
        .ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev();

    for dir in all_directories {
        for name in CONFIG_FILE_NAMES {
            let potential_file = dir.join(name);

            if potential_file.is_file() {
                valid_paths.push(potential_file);
                break;
            }
        }
    }

    Ok(valid_paths)
}
