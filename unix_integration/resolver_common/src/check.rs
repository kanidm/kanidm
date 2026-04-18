use std::fs;
use std::path::PathBuf;

/// Check for passwd and groups lines and return them if they're missing, this allows us to test parsing
pub fn parse_nsswitch_contents_return_missing(contents: &str, module_name: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            for tag in ["passwd:", "group:"] {
                if line.starts_with(tag) {
                    debug!(
                        "Found {} line in nsswitch.conf: {}",
                        tag.trim_end_matches(':'),
                        line
                    );
                    if !line.contains(module_name) {
                        warn!(
                            "nsswitch.conf {} line does not contain string '{}': {}",
                            tag.trim_end_matches(':'),
                            module_name,
                            line
                        );
                        return Some(line.to_string());
                    } else {
                        debug!(
                            "nsswitch.conf {} line contains string '{}': {}",
                            tag.trim_end_matches(':'),
                            module_name,
                            line
                        );
                        return None;
                    }
                }
            }
            None
        })
        .collect()
}

/// Warn the admin that user/group resolution may fail if Kanidm is not configured in nsswitch.conf. This is a common misconfiguration that can lead to confusion, and is worth proactively warning about.
pub fn check_nsswitch_has_module(path: Option<PathBuf>, module_name: &str) -> bool {
    // returns true if kanidm is configured in nsswitch.conf, false otherwise.
    let nsswitch_conf = path.unwrap_or_else(|| PathBuf::from("/etc/nsswitch.conf"));
    if nsswitch_conf.exists() {
        match fs::read_to_string(&nsswitch_conf) {
            Ok(contents) => {
                let missing_lines = parse_nsswitch_contents_return_missing(&contents, module_name);
                if missing_lines.is_empty() {
                    debug!(
                        "{} appears to have {} configured OK for passwd/group resolution",
                        nsswitch_conf.display(),
                        module_name
                    );
                    true
                } else {
                    warn!("{} does not appear to be configured in {} for passwd/group resolution. Lines of interest: {:?}", module_name, nsswitch_conf.display(), missing_lines);
                    false
                }
            }
            Err(err) => {
                debug!(
                    ?err,
                    "Couldn't read {} to check for {} presence",
                    nsswitch_conf.display(),
                    module_name
                );
                false
            }
        }
    } else {
        debug!(
            "Couldn't read {} to check for {} presence - file does not exist",
            nsswitch_conf.display(),
            module_name
        );
        false
    }
}

#[cfg(test)]
mod tests {
    use super::parse_nsswitch_contents_return_missing;

    #[test]
    fn parse_nsswitch_contents() {
        let contents = r#"
            # this is a comment
            passwd: files
            group: files
        "#;
        let missing = parse_nsswitch_contents_return_missing(contents, "test");
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&"passwd: files".to_string()));
        assert!(missing.contains(&"group: files".to_string()));

        let contents = r#"
            # this is a comment
            passwd: files test
            group: files test
        "#;
        let missing = parse_nsswitch_contents_return_missing(contents, "test");
        assert!(missing.is_empty());
    }
}
