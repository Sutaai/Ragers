mod common;

use std::{collections::HashMap, path::PathBuf, str::FromStr};

use ragers_core::config::{
    AliasKind, ConfigContent, ConfigContentFile, ConfigContentRecipients, get_alias_kind,
    get_closest_config_path,
};
use same_file::is_same_file;
use tempfile::TempDir;

use crate::common::User;

fn basic_schema(user: &User) -> ConfigContent {
    ConfigContent {
        recipients: ConfigContentRecipients {
            direct: HashMap::from([(user.alias.clone(), user.key.clone())]),
            groups: HashMap::new(),
            files: HashMap::new(),
        },
        files: vec![
            ConfigContentFile {
                src: "single.tmp".to_string(),
                out: Some("single.tmp.age".to_string()),
                recipients: vec![user.alias.clone()],
                armor: false,
            },
            ConfigContentFile {
                src: "armored.tmp".to_string(),
                out: Some("armored.tmp.age".to_string()),
                recipients: vec![user.alias.clone()],
                armor: true,
            },
        ],
    }
}

fn temp_config(schema: Option<&ConfigContent>) -> (TempDir, PathBuf) {
    let final_schema = match schema {
        Some(schema) => schema,
        None => &basic_schema(&User::default()),
    };

    let str_content = serde_saphyr::to_string(final_schema).unwrap();

    let temp_dir = tempfile::tempdir().unwrap();
    let file = temp_dir.path().join(".ragers.yaml");

    std::fs::write(&file, str_content).unwrap();

    return (temp_dir, file);
}

#[test]
fn test_get_closest_config_path_from_working_dir() {
    let (config_dir, config_path) = temp_config(None);

    let obtained_config = get_closest_config_path(&config_dir.path())
        .expect("cannot obtain closest config path")
        .expect("no config files found, but is to be expected");

    assert!(is_same_file(config_path, obtained_config).expect("cannot check if is same file"));
}

#[test]
fn test_get_closest_config_path_from_upper_folder() {
    let (config_dir, config_path) = temp_config(None);

    let working_dir = config_dir.path().join("working_dir/");
    std::fs::create_dir(&working_dir).expect("could not create working directory");

    let obtained_config = get_closest_config_path(&working_dir)
        .expect("cannot obtain closest config path")
        .expect("no config files found, but is to be expected");

    assert!(is_same_file(config_path, obtained_config).expect("cannot check if is same file"));
}

#[test]
fn test_get_closest_config_path_find_yml() {
    let (config_dir, config_path) = temp_config(None);

    std::fs::remove_file(&config_path).expect("could not delete config path");

    let file = config_dir.path().join(".ragers.yml");
    std::fs::File::create(&file).expect("could not create config file");

    let obtained_config = get_closest_config_path(&config_dir.path())
        .expect("cannot obtain closest config path")
        .expect("no config files found, but is to be expected");

    assert!(is_same_file(file, obtained_config).expect("cannot check if is same file"));
}

#[test]
fn test_get_closest_config_path_no_load_dir() {
    let (config_dir, config_path) = temp_config(None);

    std::fs::remove_file(&config_path).expect("could not delete config path");

    let incorrect_dir = config_dir.path().join(".ragers.yaml");
    std::fs::create_dir(&incorrect_dir).expect("could not create incorrect directory");

    assert!(
        get_closest_config_path(&incorrect_dir)
            .expect("cannot obtain closest config path")
            .is_none()
    );
}

#[test]
fn test_configcontent_from_str_valid_yaml() {
    let schema = basic_schema(&User::default());
    let schema_str = serde_saphyr::to_string(&schema).expect("schema should be serializable");

    assert!(ConfigContent::from_str(&schema_str).is_ok())
}
