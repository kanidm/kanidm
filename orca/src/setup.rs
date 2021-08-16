use crate::data::TestData;
use crate::ds::DirectoryServer;
use crate::kani::{KaniHttpServer, KaniLdapServer};
use crate::profile::Profile;
use crate::TargetOpt;
use crate::TargetServer;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub(crate) fn config(
    target: &TargetOpt,
    profile_path: &Path,
) -> Result<(TestData, Profile, TargetServer), ()> {
    // read the profile that we are going to be using/testing
    let mut f = File::open(profile_path).map_err(|e| {
        error!("Unable to open profile file [{:?}] 🥺", e);
    })?;

    let mut contents = String::new();
    f.read_to_string(&mut contents)
        .map_err(|e| error!("unable to read profile contents {:?}", e))?;

    let profile: Profile = toml::from_str(contents.as_str())
        .map_err(|e| eprintln!("unable to parse config {:?}", e))?;

    debug!("Profile -> {:?}", profile);

    // Where is our datafile?

    let data_path = if Path::new(&profile.data).is_absolute() {
        PathBuf::from(&profile.data)
    } else if let Some(p) = profile_path.parent() {
        p.join(&profile.data)
    } else {
        error!(
            "Unable to find parent directory of {}",
            profile_path.to_str().unwrap()
        );
        return Err(());
    };

    debug!("Data Path -> {}", data_path.to_str().unwrap());

    // Does our target section exist?
    let server: TargetServer = match target {
        TargetOpt::Ds => {
            if let Some(dsconfig) = profile.ds_config.as_ref() {
                DirectoryServer::new(dsconfig)?
            } else {
                error!("To use ds, you must have the ds_config section in your profile");
                return Err(());
            }
        }
        TargetOpt::KanidmLdap => {
            if let Some(klconfig) = profile.kani_ldap_config.as_ref() {
                KaniLdapServer::new(klconfig)?
            } else {
                error!("To use kanidm_ldap, you must have the kani_ldap_config section in your profile");
                return Err(());
            }
        }
        TargetOpt::Kanidm => {
            if let Some(khconfig) = profile.kani_http_config.as_ref() {
                KaniHttpServer::new(khconfig)?
            } else {
                error!("To use kanidm, you must have the kani_http_config section in your profile");
                return Err(());
            }
        }
    };

    debug!("Target server info -> {}", server.info());

    // load the related data (if any) or generate it if that is what we have.
    let data_file = File::open(data_path).map_err(|e| {
        error!("Unable to open data file [{:?}] 🥺", e);
    })?;

    let data_reader = BufReader::new(data_file);

    let data: TestData = serde_json::from_reader(data_reader).map_err(|e| {
        error!(
            "Unable to process data file. You may need to preprocess it again: {:?}",
            e
        );
    })?;

    Ok((data, profile, server))
}

pub(crate) async fn doit(target: &TargetOpt, profile_path: &Path) -> Result<(), ()> {
    info!(
        "Performing setup of {:?} from {}",
        target,
        profile_path.to_str().unwrap(),
    );

    let (data, _profile, server) = config(target, profile_path)?;

    // ensure that things we will "add" won't be there.
    // delete anything that is modded, so that it will be reset.

    let mut remove: Vec<Uuid> = data
        .connections
        .iter()
        .flat_map(|conn| conn.ops.iter())
        .filter_map(|op| op.require_reset())
        .flatten()
        /*
        // Do we need to recreate all groups? If they were modded, we already reset them ...
        .chain(
            Box::new(
            data.precreate.iter().filter(|e| e.is_group()).map(|e| e.get_uuid()) )
        )
        */
        .collect();

    remove.sort_unstable();
    remove.dedup();

    debug!("Will remove IDS -> {:?}", remove);

    server.open_admin_connection().await?;

    // Delete everything that needs to be removed.
    server.setup_admin_delete_uuids(remove.as_slice()).await?;

    // ensure that all items we need to precreate are!
    server
        .setup_admin_precreate_entities(&data.precreate, &data.all_entities)
        .await?;

    // Setup access controls - if something modifies something that IS NOT
    // itself, we grant them extra privs.
    server
        .setup_access_controls(&data.access, &data.all_entities)
        .await?;

    // Done!

    Ok(())
}
