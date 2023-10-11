use std::fs::Metadata;

#[cfg(target_os = "linux")]
use std::os::linux::fs::MetadataExt;

#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;

// #[cfg(target_os = "windows")]
// use std::os::windows::fs::MetadataExt;
#[cfg(target_family = "unix")]
use kanidm_utils_users::{get_current_gid, get_current_uid};

use std::fmt;
use std::path::{Path, PathBuf};

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
    let meta = std::fs::metadata("Cargo.toml").expect("Can't find Cargo.toml");
    println!("meta={:?} -> readonly={:?}", meta, readonly(&meta));
    assert!(readonly(&meta) == false);
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

#[cfg(target_family = "unix")]
#[derive(Debug)]
pub enum PathStatus {
    Dir {
        f_gid: u32,
        f_uid: u32,
        f_mode: u32,
        access: bool,
    },
    Link {
        f_gid: u32,
        f_uid: u32,
        f_mode: u32,
        access: bool,
    },
    File {
        f_gid: u32,
        f_uid: u32,
        f_mode: u32,
        access: bool,
    },
    Error(std::io::Error),
}

#[cfg(target_family = "unix")]
#[derive(Debug)]
pub struct Diagnosis {
    cuid: u32,
    cgid: u32,
    path: PathBuf,
    abs_path: Result<PathBuf, std::io::Error>,
    ancestors: Vec<(PathBuf, PathStatus)>,
}

impl fmt::Display for Diagnosis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "diagnosis for path: {}", self.path.to_string_lossy())?;
        let indent = match &self.abs_path {
            Ok(abs) => {
                let abs_str = abs.to_string_lossy();
                writeln!(f, "canonicalised to: {}", abs_str)?;
                abs_str.len() + 1
            }
            Err(err) => {
                writeln!(f, "unable to canonicalise path {:?}", err)?;
                0
            }
        };

        writeln!(f, "running as: {}:{}", self.cuid, self.cgid)?;

        writeln!(f, "path permissions\n")?;
        for (anc, status) in &self.ancestors {
            match &status {
                PathStatus::Dir {
                    f_gid,
                    f_uid,
                    f_mode,
                    access,
                } => {
                    writeln!(
                        f,
                        "  {:indent$}: DIR access: {} owner: {} group: {} mode: {:04o}",
                        anc.to_string_lossy(),
                        access,
                        f_uid,
                        f_gid,
                        f_mode
                    )?;
                }
                PathStatus::Link {
                    f_gid,
                    f_uid,
                    f_mode,
                    access,
                } => {
                    writeln!(
                        f,
                        "  {:indent$}: LINK access: {} owner: {} group: {} mode: {:04o}",
                        anc.to_string_lossy(),
                        access,
                        f_uid,
                        f_gid,
                        f_mode
                    )?;
                }
                PathStatus::File {
                    f_gid,
                    f_uid,
                    f_mode,
                    access,
                } => {
                    writeln!(
                        f,
                        "  {:indent$}: FILE access: {} owner: {} group: {} mode: {:04o}",
                        anc.to_string_lossy(),
                        access,
                        f_uid,
                        f_gid,
                        f_mode
                    )?;
                }
                PathStatus::Error(err) => {
                    writeln!(f, "  {:indent$}: ERROR: {:?}", anc.to_string_lossy(), err)?;
                }
            }
        }

        writeln!(
            f,
            "\n  note that accesibility does not account for ACL's or MAC"
        )?;
        writeln!(f, "-- end diagnosis")
    }
}

#[cfg(target_family = "unix")]
pub fn diagnose_path(path: &Path) -> Diagnosis {
    // Who are we?
    let cuid = get_current_uid();
    let cgid = get_current_gid();

    // clone the path
    let path: PathBuf = path.into();

    // Display the abs/resolved path.
    let abs_path = path.canonicalize();

    // For each segment, from the root inc root
    // show the path -> owner/group mode
    //      or show that we have permission denied.
    let mut all_ancestors: Vec<_> = match &abs_path {
        Ok(ap) => ap.ancestors().collect(),
        Err(_) => Vec::with_capacity(0),
    };

    let mut ancestors = Vec::with_capacity(all_ancestors.len());

    // Now pop from the right to start from the root.
    while let Some(anc) = all_ancestors.pop() {
        let status = match anc.metadata() {
            Ok(meta) => {
                let f_gid = meta.st_gid();
                let f_uid = meta.st_uid();
                let f_mode = meta.st_mode();
                if meta.is_dir() {
                    let access = x_accessible(cuid, cgid, f_uid, f_gid, f_mode);

                    PathStatus::Dir {
                        f_gid,
                        f_uid,
                        f_mode,
                        access,
                    }
                } else if meta.is_symlink() {
                    let access = x_accessible(cuid, cgid, f_uid, f_gid, f_mode);

                    PathStatus::Link {
                        f_gid,
                        f_uid,
                        f_mode,
                        access,
                    }
                } else {
                    let access = accessible(cuid, cgid, f_uid, f_gid, f_mode);

                    PathStatus::File {
                        f_gid,
                        f_uid,
                        f_mode,
                        access,
                    }
                }
            }
            Err(e) => PathStatus::Error(e),
        };

        ancestors.push((anc.into(), status))
    }

    Diagnosis {
        cuid,
        cgid,
        path,
        abs_path,
        ancestors,
    }
}

fn x_accessible(cuid: u32, cgid: u32, f_uid: u32, f_gid: u32, f_mode: u32) -> bool {
    (cuid == f_uid && f_mode & 0o500 == 0o500)
        || (cgid == f_gid && f_mode & 0o050 == 0o050)
        || f_mode & 0o005 == 0o005
}

fn accessible(cuid: u32, cgid: u32, f_uid: u32, f_gid: u32, f_mode: u32) -> bool {
    (cuid == f_uid && f_mode & 0o400 == 0o400)
        || (cgid == f_gid && f_mode & 0o040 == 0o040)
        || f_mode & 0o004 == 0o004
}
