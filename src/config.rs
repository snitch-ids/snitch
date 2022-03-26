use std::collections::BTreeMap;
use std::path::Path;

fn basic_config() -> Result<String, serde_yaml::Error> {
    let directories = vec!["some/directory".to_string()];
    let mut map = BTreeMap::new();
    map.insert("directories".to_string(), directories);

    let s = serde_yaml::to_string(&map)?;

    Ok(s)
}

pub fn load_config_from_file(
    path: &Path,
) -> Result<BTreeMap<String, Vec<String>>, serde_yaml::Error> {
    let reader = std::fs::File::open(path).unwrap();
    let config = serde_yaml::from_reader(reader)?;
    Ok(config)
}

pub fn print_basic_config() {
    let config = basic_config().unwrap();
    println!("{}", config);
}

#[cfg(test)]
mod tests {
    use crate::config::basic_config;

    #[test]
    fn test_basic_config() {
        basic_config().unwrap();
    }
}
