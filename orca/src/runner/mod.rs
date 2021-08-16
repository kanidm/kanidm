use crate::setup::config;
use crate::{TargetOpt, TestTypeOpt};
use std::path::{Path, PathBuf};

mod search;

pub(crate) async fn doit(
    testtype: &TestTypeOpt,
    target: &TargetOpt,
    profile_path: &Path,
) -> Result<(), ()> {
    info!(
        "Performing test {} against {:?} from {}",
        testtype,
        target,
        profile_path.to_str().unwrap(),
    );

    let (data, profile, server) = config(target, profile_path)?;

    debug!("Profile -> {:?}", profile);

    let result_path = PathBuf::from(&profile.results);
    if !result_path.is_dir() {
        error!("Profile: results must be a directory");
        return Err(());
    };
    debug!("Result Path -> {}", result_path.to_str().unwrap());

    // Match on what kind of test we are doing. It takes over from here.
    match testtype {
        TestTypeOpt::SearchBasic => search::basic(data, profile, server, result_path).await?,
    };

    info!("Test {} complete.", testtype);

    Ok(())
}
