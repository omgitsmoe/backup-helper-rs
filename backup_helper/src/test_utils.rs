use std::path::PathBuf;

pub(crate) fn fixture_path(value: &str) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from("C:/").join(value.trim_start_matches('/'))
    } else {
        PathBuf::from(value)
    }
}

pub(crate) fn config_with_absolute_paths(config: &str) -> String {
    if cfg!(windows) {
        config.replace("\"/", "\"C:/")
    } else {
        config.to_owned()
    }
}
