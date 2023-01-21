
use std::path::Path;

pub(crate) fn doit(profile_path: &Path) -> Result<(), ()> {
    info!(
        "Performing data generation into {}",
        profile_path.to_str().unwrap(),
    );

    // Number of users

    // Number of groups.

    // Number of memberships per user.

    // Should groups be randomly nested?

    // Data Enrichment?

    Err(())
}
