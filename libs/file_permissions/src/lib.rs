use std::fs::Metadata;

#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;

#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;

// #[cfg(target_os = "windows")]
// use std::os::windows::fs::MetadataExt;
#[cfg(target_family = "unix")]
use users::{get_current_gid, get_current_uid};

#[cfg(target_family = "unix")]
/// Check a given file's metadata is read-only for the current user (true = read-only)
pub fn readonly(meta: &Metadata) -> bool {
    // Who are we running as?
    let cuid = get_current_uid();
    let cgid = get_current_gid();

    // Who owns the file?
    // Who is the group owner of the file?
    let f_gid = meta.st_gid();
    let f_uid = meta.st_uid();

    let f_mode = meta.st_mode();

    !(
        // If we are the owner, we have write perms as we can alter the DAC rights
        cuid == f_uid ||
        // If we are the group owner, check the mode bits do not have write.
        (cgid == f_gid && (f_mode & 0o0020) != 0) ||
        // Finally, check that everyone bits don't have write.
        ((f_mode & 0o0002) != 0)
    )
}

#[cfg(target_family = "unix")]
#[test]
fn test_readonly() {
    // check if the file Cargo.toml exists
    use std::path::Path;
    if Path::new("Cargo.toml").exists() == false {
        panic!("Can't find Cargo.toml");
    }

    let meta = std::fs::metadata("Cargo.toml").expect("Can't find Cargo.toml");
    println!("meta={:?} -> readonly={:?}", meta, readonly(&meta));
    assert!(readonly(&meta)==false);
}

#[cfg(not(target_family = "unix"))]
/// Check a given file's metadata is read-only for the current user (true = read-only) Stub function if you're building for windows!
pub fn readonly(meta: &Metadata) -> bool {
    eprintln!(
        "Windows target asked to check metadata on {:?} returning false",
        meta
    );
    false
}
