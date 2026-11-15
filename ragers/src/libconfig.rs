use std::path::PathBuf;

/// Names of the default config file that Ragers should look for.
const CONFIG_FILE_NAMES: [&str; 2] = [".ragers.yaml", ".ragers.yml"];

/// Obtain a path to a config file that can be found starting from the current working directory up
/// to the filesystem's root. If multiples are to be expected in different folders, only the file
/// the closest to the current working directory is returned.
///
/// Existence is checked, and if a path is returned, can safely be read.
// TODO: This should be moved to the main.rs scope, but I wanted to have lib.rs for later. This is
// fine. For now.
pub fn get_closest_config_path() -> Result<Option<PathBuf>, std::io::Error> {
    let working_dir = std::env::current_dir()?;

    let all_directories = working_dir.ancestors();

    for dir in all_directories {
        for name in CONFIG_FILE_NAMES {
            let potential_file = dir.join(name);

            if potential_file.is_file() {
                return Ok(Some(potential_file));
            }
        }
    }

    Ok(None)
}
