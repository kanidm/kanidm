use crate::setup::config;
use crate::{TargetOpt, TestTypeOpt};
use dialoguer::Confirm;
use std::fs::create_dir_all;
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
    if !result_path.exists() {
        debug!(
            "Couldn't find results directory from profile: {:#?}",
            result_path
        );

        match Confirm::new()
            .with_prompt(
                format!("I couldn't find the directory you told me to send results to ({:?}). Would you like to create it?",
                result_path,)
            )
            .interact()
        {
            Ok(_) => match create_dir_all(result_path.as_path()) {
                Ok(_) => info!("Successfully created {:#?}", result_path.canonicalize()),
                Err(error) => {
                    error!("{:#?}", error);
                    return Err(());
                }
            },
            _ => {
                println!("Ok, going to quit!");
                return Err(());
            }
        }
    }
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
