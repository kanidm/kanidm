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
mod error;

use crate::config::{Config, EntryConfig};
use crate::error::SyncError;
use chrono::Utc;
use clap::Parser;
use cron::Schedule;
use kanidm_proto::constants::ATTR_OBJECTCLASS;
use kanidmd_lib::prelude::Attribute;
use std::fs::metadata;
use std::fs::File;
use std::io::Read;
#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::runtime;
use tokio::sync::broadcast;
use tokio::time::sleep;

use tracing::{debug, error, info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use kanidm_client::KanidmClientBuilder;
use kanidm_lib_file_permissions::readonly as file_permissions_readonly;
use kanidm_proto::scim_v1::{
    MultiValueAttr, ScimEntry, ScimExternalMember, ScimSshPubKey, ScimSyncGroup, ScimSyncPerson,
    ScimSyncRequest, ScimSyncRetentionMode, ScimSyncState,
};

#[cfg(target_family = "unix")]
use kanidm_utils_users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};

use ldap3_client::{proto, LdapClientBuilder, LdapSyncRepl, LdapSyncReplEntry, LdapSyncStateValue};

include!("./opt.rs");

async fn driver_main(opt: Opt) {
    debug!("Starting kanidm ldap sync driver.");

    let mut f = match File::open(&opt.ldap_sync_config) {
        Ok(f) => f,
        Err(e) => {
            error!(
                "Unable to open ldap sync config from '{}' [{:?}] 🥺",
                &opt.ldap_sync_config.display(),
                e
            );
            return;
        }
    };

    let mut contents = String::new();
    if let Err(e) = f.read_to_string(&mut contents) {
        error!(
            "unable to read file '{}': {:?}",
            &opt.ldap_sync_config.display(),
            e
        );
        return;
    };

    let sync_config: Config = match toml::from_str(contents.as_str()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "Unable to parse config from '{}' error: {:?}",
                &opt.ldap_sync_config.display(),
                e
            );
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

    let expression = sync_config.schedule.as_deref().unwrap_or("0 */5 * * * * *");

    let schedule = match Schedule::from_str(expression) {
        Ok(s) => s,
        Err(_) => {
            error!("Failed to parse cron schedule expression");
            return;
        }
    };

    if opt.schedule {
        let last_op_status = Arc::new(AtomicBool::new(true));
        let (broadcast_tx, mut broadcast_rx) = broadcast::channel(4);

        let last_op_status_c = last_op_status.clone();

        // Can we setup the socket for status?

        let status_handle = if let Some(sb) = sync_config.status_bind.as_deref() {
            // Can we bind?
            let listener = match TcpListener::bind(sb).await {
                Ok(l) => l,
                Err(e) => {
                    error!(?e, "Failed to bind status socket");
                    return;
                }
            };

            info!("Status listener is started on {:?}", sb);
            // Detach a status listener.
            let status_rx = broadcast_tx.subscribe();
            Some(tokio::spawn(async move {
                status_task(listener, status_rx, last_op_status_c).await
            }))
        } else {
            warn!("No status listener configured, this will prevent you monitoring the sync tool");
            None
        };

        // main driver loop
        let driver_handle = tokio::spawn(async move {
            loop {
                let now = Utc::now();
                let next_time = match schedule.after(&now).next() {
                    Some(v) => v,
                    None => {
                        error!("Failed to access any future scheduled events, terminating.");
                        break;
                    }
                };

                // If we don't do 1 + here we can trigger the event multiple times
                // rapidly since we are in the same second.
                let wait_seconds = 1 + (next_time - now).num_seconds() as u64;
                info!("next sync on {}, wait_time = {}s", next_time, wait_seconds);

                tokio::select! {
                    _ = broadcast_rx.recv() => {
                        // stop the event loop!
                        break;
                    }
                    _ = sleep(Duration::from_secs(wait_seconds)) => {
                        info!("starting sync ...");
                        match run_sync(cb.clone(), &sync_config, &opt).await {
                            Ok(_) => last_op_status.store(true, Ordering::Relaxed),
                            Err(e) => {
                                error!(?e, "sync completed with error");
                                last_op_status.store(false, Ordering::Relaxed)
                            }
                        };
                    }
                }
            }
            info!("Stopped sync driver");
        });

        // TODO: this loop/handler should be generic across the various crates
        // Block on signals now.
        loop {
            #[cfg(target_family = "unix")]
            {
                tokio::select! {
                    Ok(()) = tokio::signal::ctrl_c() => {
                        break
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::terminate();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        break
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::alarm();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::hangup();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::user_defined1();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                    Some(()) = async move {
                        let sigterm = tokio::signal::unix::SignalKind::user_defined2();
                        #[allow(clippy::unwrap_used)]
                        tokio::signal::unix::signal(sigterm).unwrap().recv().await
                    } => {
                        // Ignore
                    }
                }
            }
            #[cfg(target_family = "windows")]
            {
                tokio::select! {
                    Ok(()) = tokio::signal::ctrl_c() => {
                        break
                    }
                }
            }
        }

        broadcast_tx
            .send(true)
            .expect("Failed to trigger a clean shutdown!");

        let _ = driver_handle.await;
        if let Some(sh) = status_handle {
            let _ = sh.await;
        }
    } else if let Err(e) = run_sync(cb, &sync_config, &opt).await {
        error!(?e, "Sync completed with error");
    }
}

async fn run_sync(
    cb: KanidmClientBuilder,
    sync_config: &Config,
    opt: &Opt,
) -> Result<(), SyncError> {
    let rsclient = match cb.build() {
        Ok(rsc) => rsc,
        Err(_e) => {
            error!("Failed to build async client");
            return Err(SyncError::ClientConfig);
        }
    };

    rsclient.set_token(sync_config.sync_token.clone()).await;

    // Preflight check.
    //  * can we connect to ldap?
    let mut ldap_client = match LdapClientBuilder::new(&sync_config.ldap_uri)
        .max_ber_size(sync_config.max_ber_size)
        .add_tls_ca(&sync_config.ldap_ca)
        .build()
        .await
    {
        Ok(lc) => lc,
        Err(e) => {
            error!(?e, "Failed to connect to ldap");
            return Err(SyncError::LdapConn);
        }
    };

    match ldap_client
        .bind(
            sync_config.ldap_sync_dn.clone(),
            sync_config.ldap_sync_pw.clone(),
        )
        .await
    {
        Ok(()) => {
            debug!(ldap_sync_dn = ?sync_config.ldap_sync_dn, ldap_uri = %sync_config.ldap_uri);
        }
        Err(e) => {
            error!(?e, "Failed to bind (authenticate) to freeldap");
            return Err(SyncError::LdapAuth);
        }
    };

    //  * can we connect to kanidm?
    // - get the current sync cookie from kanidm.
    let scim_sync_status = match rsclient.scim_v1_sync_status().await {
        Ok(s) => s,
        Err(e) => {
            error!(?e, "Failed to access scim sync status");
            return Err(SyncError::SyncStatus);
        }
    };

    debug!(state=?scim_sync_status);

    // === Everything is connected! ===

    let mode = proto::SyncRequestMode::RefreshOnly;

    let cookie = match &scim_sync_status {
        ScimSyncState::Refresh => None,
        ScimSyncState::Active { cookie } => Some(cookie.0.clone()),
    };

    let filter = sync_config.ldap_filter.clone();

    debug!(ldap_sync_base_dn = ?sync_config.ldap_sync_base_dn, ?cookie, ?mode, ?filter);
    let sync_result = match ldap_client
        .syncrepl(sync_config.ldap_sync_base_dn.clone(), filter, cookie, mode)
        .await
    {
        Ok(results) => results,
        Err(e) => {
            error!(?e, "Failed to perform syncrepl from ldap");
            return Err(SyncError::LdapSyncrepl);
        }
    };

    if opt.proto_dump {
        let stdout = std::io::stdout();
        if let Err(e) = serde_json::to_writer_pretty(stdout, &sync_result) {
            error!(?e, "Failed to serialise ldap sync response");
        }
    }

    let scim_sync_request = match sync_result {
        LdapSyncRepl::Success {
            cookie,
            refresh_deletes: _,
            entries,
            delete_uuids,
            present_uuids,
        } => {
            // refresh deletes is true only on the first refresh from openldap, implying
            // to delete anything not marked as present. In otherwords
            // refresh_deletes means to assert the content as it exists from the ldap server
            // in the openldap case. For our purpose, we can use this to mean "present phase" since
            // that will imply that all non present entries are purged.

            let to_state = if let Some(cookie) = cookie {
                // Only update the cookie if it's present - openldap omits!
                ScimSyncState::Active { cookie }
            } else {
                info!("no changes required");
                return Ok(());
            };

            let retain = match (delete_uuids, present_uuids) {
                (None, None) => {
                    // if delete_phase == false && present_phase == false
                    //     Only update entries if they are present in the *add* state.
                    //     Generally also means do nothing with other entries, no updates for example.
                    //
                    //     This is the state of 389-ds with no deletes *and* entries are updated *only*.
                    //     This is the state for openldap and 389-ds when there are no changes to apply.
                    ScimSyncRetentionMode::Ignore
                }
                (Some(d_uuids), None) => {
                    //    update entries that are in Add state, delete from delete uuids.
                    //
                    //    This only occurs on 389-ds, which sends a list of deleted uuids as required.
                    ScimSyncRetentionMode::Delete(d_uuids)
                }
                (None, Some(p_uuids)) => {
                    //    update entries in Add state, assert entry is live from present_uuids
                    //    NOTE! Even if an entry is updated, it will also be in the present phase set. This
                    //    means we can use present_set > 0 as an indicator too.
                    //
                    //    This occurs only on openldap, where present phase lists all uuids in the filter set
                    //    *and* includes all entries that are updated at the same time.
                    ScimSyncRetentionMode::Retain(p_uuids)
                }
                (Some(_), Some(_)) => {
                    //    error! No Ldap server emits this!
                    error!("Ldap server provided an invalid sync repl response - unable to have both delete and present phases.");
                    return Err(SyncError::LdapStateInvalid);
                }
            };

            let entries = match process_ldap_sync_result(entries, sync_config).await {
                Ok(ssr) => ssr,
                Err(()) => {
                    error!("Failed to process IPA entries to SCIM");
                    return Err(SyncError::Preprocess);
                }
            };

            ScimSyncRequest {
                from_state: scim_sync_status,
                to_state,
                entries,
                retain,
            }
        }
        LdapSyncRepl::RefreshRequired => {
            let to_state = ScimSyncState::Refresh;

            ScimSyncRequest {
                from_state: scim_sync_status,
                to_state,
                entries: Vec::new(),
                retain: ScimSyncRetentionMode::Ignore,
            }
        }
    };

    if opt.proto_dump {
        let stdout = std::io::stdout();
        // write it out.
        if let Err(e) = serde_json::to_writer_pretty(stdout, &scim_sync_request) {
            error!(?e, "Failed to serialise scim sync request");
        };
        Ok(())
    } else if opt.dry_run {
        info!("dry-run complete");
        info!("Success!");
        Ok(())
    } else if let Err(e) = rsclient.scim_v1_sync_update(&scim_sync_request).await {
        error!(
            ?e,
            "Failed to submit scim sync update - see the kanidmd server log for more details."
        );
        Err(SyncError::SyncUpdate)
    } else {
        info!("Success!");
        Ok(())
    }
    // done!
}

async fn process_ldap_sync_result(
    ldap_entries: Vec<LdapSyncReplEntry>,
    sync_config: &Config,
) -> Result<Vec<ScimEntry>, ()> {
    // Future - make this par-map
    ldap_entries
        .into_iter()
        .filter_map(|lentry| {
            let e_config = sync_config
                .entry_map
                .get(&lentry.entry_uuid)
                .cloned()
                .unwrap_or_default();

            match ldap_to_scim_entry(lentry, &e_config, sync_config) {
                Ok(Some(e)) => Some(Ok(e)),
                Ok(None) => None,
                Err(()) => Some(Err(())),
            }
        })
        .collect::<Result<Vec<_>, _>>()
}

fn ldap_to_scim_entry(
    sync_entry: LdapSyncReplEntry,
    entry_config: &EntryConfig,
    sync_config: &Config,
) -> Result<Option<ScimEntry>, ()> {
    debug!("{:#?}", sync_entry);

    // check the sync_entry state?
    #[allow(clippy::unimplemented)]
    if sync_entry.state != LdapSyncStateValue::Add {
        unimplemented!();
    }

    let dn = sync_entry.entry.dn.clone();

    // Is this an entry we need to observe/look at?
    if entry_config.exclude {
        info!("entry_config excludes {}", dn);
        return Ok(None);
    }

    let oc = sync_entry
        .entry
        .attrs
        .get(ATTR_OBJECTCLASS)
        .ok_or_else(|| {
            error!("Invalid entry - no object class {}", dn);
        })?;

    if oc.contains(&sync_config.person_objectclass) {
        let LdapSyncReplEntry {
            entry_uuid,
            state: _,
            mut entry,
        } = sync_entry;

        let id = if let Some(map_uuid) = &entry_config.map_uuid {
            *map_uuid
        } else {
            entry_uuid
        };

        let user_name = if let Some(name) = entry_config.map_name.clone() {
            name
        } else {
            entry
                .remove_ava_single(&sync_config.person_attr_user_name)
                .ok_or_else(|| {
                    error!(
                        "Missing required attribute {} (person_attr_user_name)",
                        sync_config.person_attr_user_name
                    );
                })?
        };

        let display_name = entry
            .remove_ava_single(&sync_config.person_attr_display_name)
            .ok_or_else(|| {
                error!(
                    "Missing required attribute {} (person_attr_display_name)",
                    sync_config.person_attr_display_name
                );
            })?;

        let gidnumber = if let Some(number) = entry_config.map_gidnumber {
            Some(number)
        } else {
            entry
                .remove_ava_single(&sync_config.person_attr_gidnumber)
                .map(|gid| {
                    u32::from_str(&gid).map_err(|_| {
                        error!(
                            "Invalid gidnumber - {} is not a u32 (person_attr_gidnumber)",
                            sync_config.person_attr_gidnumber
                        );
                    })
                })
                .transpose()?
        };

        let password_import = entry.remove_ava_single(&sync_config.person_attr_password);

        let password_import = if let Some(pw_prefix) = sync_config.person_password_prefix.as_ref() {
            password_import.map(|s| format!("{}{}", pw_prefix, s))
        } else {
            password_import
        };

        let unix_password_import = if sync_config
            .sync_password_as_unix_password
            .unwrap_or_default()
        {
            password_import.clone()
        } else {
            None
        };

        let mail: Vec<_> = entry
            .remove_ava(&sync_config.person_attr_mail)
            .map(|set| {
                set.into_iter()
                    .map(|addr| MultiValueAttr {
                        type_: None,
                        primary: None,
                        display: None,
                        ref_: None,
                        value: addr,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let totp_import = Vec::default();

        let ssh_publickey = entry
            .remove_ava(&sync_config.person_attr_ssh_public_key)
            .map(|set| {
                set.into_iter()
                    .enumerate()
                    .map(|(i, value)| ScimSshPubKey {
                        label: format!("sshpublickey-{}", i),
                        value,
                    })
                    .collect()
            })
            .unwrap_or_default();

        let account_disabled: bool = entry
            .remove_ava(Attribute::NsAccountLock.as_ref())
            .map(|set| {
                set.into_iter()
                    .any(|value| value != "FALSE" && value != "false")
            })
            .unwrap_or_default();

        // Account is not valid
        let account_expire = if account_disabled {
            Some(chrono::DateTime::UNIX_EPOCH.to_rfc3339())
        } else {
            None
        };
        let account_valid_from = None;

        let login_shell = entry.remove_ava_single(&sync_config.person_attr_login_shell);
        let external_id = Some(entry.dn);

        Ok(Some(
            ScimSyncPerson {
                id,
                external_id,
                user_name,
                display_name,
                gidnumber,
                password_import,
                unix_password_import,
                totp_import,
                login_shell,
                mail,
                ssh_publickey,
                account_expire,
                account_valid_from,
            }
            .into(),
        ))
    } else if oc.contains(&sync_config.group_objectclass) {
        let LdapSyncReplEntry {
            entry_uuid,
            state: _,
            mut entry,
        } = sync_entry;

        let id = entry_uuid;

        let name = entry
            .remove_ava_single(&sync_config.group_attr_name)
            .ok_or_else(|| {
                error!(
                    "Missing required attribute {} (group_attr_name)",
                    sync_config.group_attr_name
                );
            })?;

        let description = entry.remove_ava_single(&sync_config.group_attr_description);

        let gidnumber = entry
            .remove_ava_single(&sync_config.group_attr_gidnumber)
            .map(|gid| {
                u32::from_str(&gid).map_err(|_| {
                    error!(
                        "Invalid gidnumber - {} is not a u32 (group_attr_gidnumber)",
                        sync_config.group_attr_gidnumber
                    );
                })
            })
            .transpose()?;

        let members: Vec<_> = entry
            .remove_ava(&sync_config.group_attr_member)
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
    } else {
        debug!("Skipping entry {} with oc {:?}", dn, oc);
        Ok(None)
    }
}

async fn status_task(
    listener: TcpListener,
    mut status_rx: broadcast::Receiver<bool>,
    last_op_status: Arc<AtomicBool>,
) {
    loop {
        tokio::select! {
            _ = status_rx.recv() => {
                break;
            }
            maybe_sock = listener.accept() => {
                let mut stream = match maybe_sock {
                    Ok((sock, addr)) => {
                        debug!("accept from {:?}", addr);
                        sock
                    }
                    Err(e) => {
                        error!(?e, "Failed to accept status connection");
                        continue;
                    }
                };

                let sr = if last_op_status.load(Ordering::Relaxed) {
                     stream.write_all(b"Ok\n").await
                } else {
                     stream.write_all(b"Err\n").await
                };
                if let Err(e) = sr {
                    error!(?e, "Failed to send status");
                }
            }
        }
    }
    info!("Stopped status task");
}

fn config_security_checks(cfg_path: &Path) -> bool {
    let cfg_path_str = cfg_path.to_string_lossy();

    if !cfg_path.exists() {
        // there's no point trying to start up if we can't read a usable config!
        error!(
            "Config missing from {} - cannot start up. Quitting.",
            cfg_path_str
        );
        false
    } else {
        let cfg_meta = match metadata(cfg_path) {
            Ok(v) => v,
            Err(e) => {
                error!(
                    "Unable to read metadata for '{}' during security checks - {:?}",
                    cfg_path_str, e
                );
                return false;
            }
        };
        if !file_permissions_readonly(&cfg_meta) {
            warn!("permissions on {} may not be secure. Should be readonly to running uid. This could be a security risk ...",
                cfg_path_str
                );
        }

        #[cfg(target_family = "unix")]
        if cfg_meta.uid() == get_current_uid() || cfg_meta.uid() == get_effective_uid() {
            warn!("WARNING: {} owned by the current uid, which may allow file permission changes. This could be a security risk ...",
                cfg_path_str
            );
        }

        true
    }
}

fn main() {
    let opt = Opt::parse();

    let fmt_layer = fmt::layer().with_writer(std::io::stderr);

    let filter_layer = if opt.debug {
        match EnvFilter::try_new("kanidm_client=debug,kanidm_ldap_sync=debug,ldap3_client=debug") {
            Ok(f) => f,
            Err(e) => {
                eprintln!("ERROR! Unable to start tracing {:?}", e);
                return;
            }
        }
    } else {
        match EnvFilter::try_from_default_env() {
            Ok(f) => f,
            Err(_) => EnvFilter::new("kanidm_client=warn,kanidm_ldap_sync=info,ldap3_client=warn"),
        }
    };

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    // Startup sanity checks.
    // TODO: put this in the junk drawer
    #[cfg(target_family = "unix")]
    if opt.skip_root_check {
        warn!("Skipping root user check, if you're running this for testing, ensure you clean up temporary files.")
    } else if get_current_uid() == 0
        || get_effective_uid() == 0
        || get_current_gid() == 0
        || get_effective_gid() == 0
    {
        error!("Refusing to run - this process must not operate as root.");
        return;
    };

    if !config_security_checks(&opt.client_config) || !config_security_checks(&opt.ldap_sync_config)
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

#[tokio::test]
async fn test_driver_main() {
    let testopt = Opt {
        client_config: PathBuf::from("test"),
        ldap_sync_config: PathBuf::from("test"),
        debug: false,
        schedule: false,
        proto_dump: false,
        dry_run: false,
        skip_root_check: true,
    };
    let _ = sketching::test_init();

    println!("testing config");
    // because it can't find the profile file it'll just stop
    assert_eq!(driver_main(testopt.clone()).await, ());
    println!("done testing missing config");

    let testopt = Opt {
        client_config: PathBuf::from(format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"))),
        ldap_sync_config: PathBuf::from(format!("{}/Cargo.toml", env!("CARGO_MANIFEST_DIR"))),
        ..testopt
    };

    println!("valid file path, invalid contents");
    assert_eq!(driver_main(testopt.clone()).await, ());
    println!("done with valid file path, invalid contents");
    let testopt = Opt {
        client_config: PathBuf::from(format!(
            "{}/../../../examples/iam_migration_ldap.toml",
            env!("CARGO_MANIFEST_DIR")
        )),
        ldap_sync_config: PathBuf::from(format!(
            "{}/../../../examples/iam_migration_ldap.toml",
            env!("CARGO_MANIFEST_DIR")
        )),
        ..testopt
    };

    println!("valid file path, invalid contents");
    assert_eq!(driver_main(testopt).await, ());
    println!("done with valid file path, valid contents");
}
