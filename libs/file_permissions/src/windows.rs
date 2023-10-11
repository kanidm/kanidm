// #[cfg(target_os = "windows")]
// use std::os::windows::fs::MetadataExt;

/// Check a given file's metadata is read-only for the current user (true = read-only) Stub function if you're building for windows!
pub fn readonly(meta: &Metadata) -> bool {
    eprintln!(
        "Windows target asked to check metadata on {:?} returning false",
        meta
    );
    false
}

#[derive(Debug)]
pub struct Diagnosis;

impl fmt::Display for Diagnosis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Unable to diagnose path issues on windows 😢")
    }
}

pub fn diagnose_path(path: &Path) -> Diagnosis {
    Diagnosis {}
}
