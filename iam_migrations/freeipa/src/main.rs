#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
// We allow expect since it forces good error messages at the least.
#![allow(clippy::expect_used)]

mod config;

#[cfg(test)]
mod tests;

use crate::config::{Config, EntryConfig};
use clap::Parser;
use std::collections::HashMap;
use std::fs::metadata;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::thread;
use uuid::Uuid;
use tokio::runtime;
use tracing::{debug, error, info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use kanidm_client::KanidmClientBuilder;
use kanidm_proto::scim_v1::{
    ScimEntry, ScimExternalMember, ScimSyncGroup, ScimSyncPerson, ScimSyncRequest, ScimSyncState,
};
use kanidmd_lib::utils::file_permissions_readonly;

use users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};

use ldap3_client::{
    proto, proto::LdapFilter, LdapClientBuilder, LdapSyncRepl, LdapSyncReplEntry,
    LdapSyncStateValue,
};

include!("./opt.rs");

async fn driver_main(opt: Opt) {
    debug!("Starting kanidm freeipa sync driver.");
    // Parse the configs.

    let mut f = match File::open(&opt.ipa_sync_config) {
        Ok(f) => f,
        Err(e) => {
            error!("Unable to open profile file [{:?}] 🥺", e);
            return;
        }
    };

    let mut contents = String::new();
    if let Err(e) = f.read_to_string(&mut contents) {
        error!("unable to read profile contents {:?}", e);
        return;
    };

    let sync_config: Config = match toml::from_str(contents.as_str()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("unable to parse config {:?}", e);
            return;
        }
    };

    debug!(?sync_config);

    let cb = match KanidmClientBuilder::new().read_options_from_optional_config(&opt.client_config)
    {
        Ok(v) => v,
        Err(_) => {
            error!("Failed to parse {}", opt.client_config.to_string_lossy());
            return;
        }
    };

    // Do we need this?
    // let cb = cb.connect_timeout(cfg.conn_timeout);

    let rsclient = match cb.build() {
        Ok(rsc) => rsc,
        Err(_e) => {
            error!("Failed to build async client");
            return;
        }
    };

    rsclient.set_token(sync_config.sync_token.clone()).await;

    // Preflight check.
    //  * can we connect to ipa?

    let mut ipa_client = match LdapClientBuilder::new(&sync_config.ipa_uri)
        .add_tls_ca(&sync_config.ipa_ca)
        .build()
        .await
    {
        Ok(lc) => lc,
        Err(e) => {
            error!(?e, "Failed to connect to freeipa");
            return;
        }
    };

    match ipa_client
        .bind(
            sync_config.ipa_sync_dn.clone(),
            sync_config.ipa_sync_pw.clone(),
        )
        .await
    {
        Ok(()) => {
            debug!(ipa_sync_dn = ?sync_config.ipa_sync_dn, ipa_uri = %sync_config.ipa_uri);
        }
        Err(e) => {
            error!(?e, "Failed to bind (authenticate) to freeipa");
            return;
        }
    };

    //  * can we connect to kanidm?
    // - get the current sync cookie from kanidm.
    let scim_sync_status = match rsclient.scim_v1_sync_status().await {
        Ok(s) => s,
        Err(e) => {
            error!(?e, "Failed to access scim sync status");
            return;
        }
    };

    debug!(state=?scim_sync_status);

    // === Everything is connected! ===

    // Based on the scim_sync_status, perform our sync repl

    let mode = proto::SyncRequestMode::RefreshOnly;

    let cookie = match &scim_sync_status {
        ScimSyncState::Refresh => None,
        ScimSyncState::Active { cookie } => Some(cookie.0.clone()),
    };

    let filter = LdapFilter::Or(vec![
        // LdapFilter::Equality("objectclass".to_string(), "domain".to_string()),
        LdapFilter::And(vec![
            LdapFilter::Equality("objectclass".to_string(), "person".to_string()),
            LdapFilter::Equality("objectclass".to_string(), "ipantuserattrs".to_string()),
            LdapFilter::Equality("objectclass".to_string(), "posixaccount".to_string()),
        ]),
        LdapFilter::And(vec![
            LdapFilter::Equality("objectclass".to_string(), "groupofnames".to_string()),
            LdapFilter::Equality("objectclass".to_string(), "ipausergroup".to_string()),
            LdapFilter::Not(Box::new(LdapFilter::Equality(
                "objectclass".to_string(),
                "mepmanagedentry".to_string(),
            ))),
            // Need to exclude the admins group as it gid conflicts to admin.
            LdapFilter::Not(Box::new(LdapFilter::Equality(
                "cn".to_string(),
                "admins".to_string(),
            ))),
            // Kani internally has an all persons group.
            LdapFilter::Not(Box::new(LdapFilter::Equality(
                "cn".to_string(),
                "ipausers".to_string(),
            ))),
        ]),
        LdapFilter::And(vec![
            LdapFilter::Equality("objectclass".to_string(), "ipatoken".to_string()),
            LdapFilter::Equality("objectclass".to_string(), "ipatokentotp".to_string()),
        ]),
    ]);

    debug!(ipa_sync_base_dn = ?sync_config.ipa_sync_base_dn, ?cookie, ?mode, ?filter);
    let sync_result = match ipa_client
        .syncrepl(sync_config.ipa_sync_base_dn, filter, cookie, mode)
        .await
    {
        Ok(results) => results,
        Err(e) => {
            error!(?e, "Failed to perform syncrepl from ipa");
            return;
        }
    };

    if opt.proto_dump {
        let stdout = std::io::stdout();
        if let Err(e) = serde_json::to_writer_pretty(stdout, &sync_result) {
            error!(?e, "Failed to serialise ldap sync response");
        }
    }

    // pre-process the entries.
    //  - > fn so we can test.
    let scim_sync_request = match process_ipa_sync_result(scim_sync_status, sync_result, &sync_config.entry_map).await {
        Ok(ssr) => ssr,
        Err(()) => return,
    };

    if opt.proto_dump {
        let stdout = std::io::stdout();
        // write it out.
        if let Err(e) = serde_json::to_writer_pretty(stdout, &scim_sync_request) {
            error!(?e, "Failed to serialise scim sync request");
        };
    } else if opt.dry_run {
        info!("dry-run complete");
        info!("Success!");
    } else {
        if let Err(e) = rsclient.scim_v1_sync_update(&scim_sync_request).await {
            error!(
                ?e,
                "Failed to submit scim sync update - see the kanidmd server log for more details."
            );
        } else {
            info!("Success!");
        }
    }
    // done!
}

async fn process_ipa_sync_result(
    from_state: ScimSyncState,
    sync_result: LdapSyncRepl,
    entry_config_map: &HashMap<Uuid, EntryConfig>,
) -> Result<ScimSyncRequest, ()> {
    match sync_result {
        LdapSyncRepl::Success {
            cookie,
            refresh_deletes,
            entries,
            delete_uuids,
            present_uuids,
        } => {
            if refresh_deletes {
                error!("Unsure how to handle refreshDeletes=True");
                return Err(());
            }

            if !present_uuids.is_empty() {
                error!("Unsure how to handle presentUuids > 0");
                return Err(());
            }

            let to_state = cookie
                .map(|cookie| {
                    ScimSyncState::Active { cookie }
                })
                .ok_or_else(|| {
                    error!("Invalid state, ldap sync repl did not provide a valid state cookie in response.");
                })?;

            // Future - make this par-map
            let entries = entries
                .into_iter()
                .filter_map(|e| {
                let e_config = entry_config_map.get(&e.entry_uuid).cloned().unwrap_or_default();
                match ipa_to_scim_entry(e, &e_config) {
                    Ok(Some(e)) => Some(Ok(e)),
                    Ok(None) => None,
                    Err(()) => Some(Err(())),
                }
                })
                .collect::<Result<Vec<_>, _>>();

            let entries = match entries {
                Ok(e) => e,
                Err(()) => {
                    error!("Failed to process IPA entries to SCIM");
                    return Err(());
                }
            };

            Ok(ScimSyncRequest {
                from_state,
                to_state,
                entries,
                delete_uuids,
            })
        }
        LdapSyncRepl::RefreshRequired => {
            let to_state = ScimSyncState::Refresh;

            Ok(ScimSyncRequest {
                from_state,
                to_state,
                entries: Vec::new(),
                delete_uuids: Vec::new(),
            })
        }
    }
}

// TODO: Allow re-map of uuid -> uuid

fn ipa_to_scim_entry(sync_entry: LdapSyncReplEntry, entry_config: &EntryConfig) -> Result<Option<ScimEntry>, ()> {
    debug!("{:#?}", sync_entry);

    // check the sync_entry state?
    if sync_entry.state != LdapSyncStateValue::Add {
        unimplemented!();
    }

    let dn = sync_entry.entry.dn.clone();

    // Is this an entry we need to observe/look at?
    if entry_config.exclude {
        info!("entry_config excludes {}", dn);
        return Ok(None);
    }

    let oc = sync_entry.entry.attrs.get("objectclass").ok_or_else(|| {
        error!("Invalid entry - no object class {}", dn);
    })?;

    if oc.contains("person") {
        let LdapSyncReplEntry {
            entry_uuid,
            state: _,
            mut entry,
        } = sync_entry;

        let id = entry_uuid;

        let user_name = entry.remove_ava_single("uid").ok_or_else(|| {
            error!("Missing required attribute uid");
        })?;

        // ⚠️  hardcoded skip on admin here!!!
        if user_name == "admin" {
            info!("kanidm excludes {}", dn);
            return Ok(None);
        }

        let display_name = entry.remove_ava_single("cn").ok_or_else(|| {
            error!("Missing required attribute cn");
        })?;

        let gidnumber = entry
            .remove_ava_single("gidnumber")
            .map(|gid| {
                u32::from_str(&gid).map_err(|_| {
                    error!("Invalid gidnumber");
                })
            })
            .transpose()?;

        let password_import = entry
            .remove_ava_single("ipanthash")
            .map(|s| format!("ipaNTHash: {}", s));
        let login_shell = entry.remove_ava_single("loginshell");
        let external_id = Some(entry.dn);

        Ok(Some(
            ScimSyncPerson {
                id,
                external_id,
                user_name,
                display_name,
                gidnumber,
                password_import,
                login_shell,
            }
            .into(),
        ))
    } else if oc.contains("groupofnames") {
        let LdapSyncReplEntry {
            entry_uuid,
            state: _,
            mut entry,
        } = sync_entry;

        let id = entry_uuid;

        let name = entry.remove_ava_single("cn").ok_or_else(|| {
            error!("Missing required attribute cn");
        })?;

        // ⚠️  hardcoded skip on trust admins / editors / ipausers here!!!
        if name == "trust admins" || name == "editors" || name == "ipausers" || name == "admins" {
            info!("kanidm excludes {}", dn);
            return Ok(None);
        }

        let description = entry.remove_ava_single("description");

        let gidnumber = entry
            .remove_ava_single("gidnumber")
            .map(|gid| {
                u32::from_str(&gid).map_err(|_| {
                    error!("Invalid gidnumber");
                })
            })
            .transpose()?;

        let members: Vec<_> = entry
            .remove_ava("member")
            .map(|set| {
                set.into_iter()
                    .map(|external_id| ScimExternalMember { external_id })
                    .collect()
            })
            .unwrap_or_default();

        let external_id = Some(entry.dn);

        Ok(Some(
            ScimSyncGroup {
                id,
                external_id,
                name,
                description,
                gidnumber,
                members,
            }
            .into(),
        ))
    } else if oc.contains("ipatokentotp") {
        // Skip for now, we don't supporty multiple totp yet.
        Ok(None)
    } else {
        debug!("Skipping entry {} with oc {:?}", dn, oc);
        Ok(None)
    }
}

fn config_security_checks(cfg_path: &Path) -> bool {
    let cfg_path_str = cfg_path.to_string_lossy();

    if !cfg_path.exists() {
        // there's no point trying to start up if we can't read a usable config!
        error!(
            "Config missing from {} - cannot start up. Quitting.",
            cfg_path_str
        );
        return false;
    } else {
        let cfg_meta = match metadata(&cfg_path) {
            Ok(v) => v,
            Err(e) => {
                error!("Unable to read metadata for {} - {:?}", cfg_path_str, e);
                return false;
            }
        };
        if !file_permissions_readonly(&cfg_meta) {
            warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
                cfg_path_str
                );
        }

        let cuid = get_current_uid();
        let ceuid = get_effective_uid();

        if cfg_meta.uid() == cuid || cfg_meta.uid() == ceuid {
            warn!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
                cfg_path_str
            );
        }

        true
    }
}

fn main() {
    let cuid = get_current_uid();
    let ceuid = get_effective_uid();
    let cgid = get_current_gid();
    let cegid = get_effective_gid();

    let opt = Opt::parse();

    let fmt_layer = fmt::layer().with_writer(std::io::stderr);

    let filter_layer = if opt.debug {
        match EnvFilter::try_new("kanidm_client=debug,kanidm_ipa_sync=debug,ldap3_client=debug") {
            Ok(f) => f,
            Err(e) => {
                eprintln!("ERROR! Unable to start tracing {:?}", e);
                return;
            }
        }
    } else {
        match EnvFilter::try_from_default_env() {
            Ok(f) => f,
            Err(_) => EnvFilter::new("kanidm_client=warn,kanidm_ipa_sync=info,ldap3_client=warn"),
        }
    };

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    // Startup sanity checks.
    if opt.skip_root_check {
        warn!("Skipping root user check, if you're running this for testing, ensure you clean up temporary files.")
        // TODO: this wording is not great m'kay.
    } else {
        if cuid == 0 || ceuid == 0 || cgid == 0 || cegid == 0 {
            error!("Refusing to run - this process must not operate as root.");
            return;
        }
    };

    if !config_security_checks(&opt.client_config) || !config_security_checks(&opt.ipa_sync_config)
    {
        return;
    }

    let par_count = thread::available_parallelism()
        .expect("Failed to determine available parallelism")
        .get();

    let rt = runtime::Builder::new_current_thread()
        // We configure this as we use parallel workers at some points.
        .max_blocking_threads(par_count)
        .enable_all()
        .build()
        .expect("Failed to initialise tokio runtime!");

    tracing::debug!("Using {} worker threads", par_count);

    rt.block_on(async move { driver_main(opt).await });
}
