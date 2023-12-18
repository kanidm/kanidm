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

// #[cfg(test)]
// mod tests;

use crate::config::{Config, EntryConfig};
use crate::error::SyncError;
use base64urlsafedata::Base64UrlSafeData;
use chrono::Utc;
use clap::Parser;
use cron::Schedule;
use kanidm_proto::constants::{
    ATTR_UID, LDAP_ATTR_CN, LDAP_ATTR_OBJECTCLASS, LDAP_CLASS_GROUPOFNAMES,
};
use kanidmd_lib::prelude::{Attribute, EntryClass};
use std::collections::BTreeMap;
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
use uuid::Uuid;

use kanidm_client::KanidmClientBuilder;
use kanidm_proto::scim_v1::{
    MultiValueAttr, ScimEntry, ScimExternalMember, ScimSshPubKey, ScimSyncGroup, ScimSyncPerson,
    ScimSyncRequest, ScimSyncRetentionMode, ScimSyncState, ScimTotp,
};

use kanidm_lib_file_permissions::readonly as file_permissions_readonly;

#[cfg(target_family = "unix")]
use kanidm_utils_users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};

use ldap3_client::{
    proto, proto::LdapFilter, LdapClient, LdapClientBuilder, LdapSyncRepl, LdapSyncReplEntry,
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
            let diag = kanidm_lib_file_permissions::diagnose_path(&opt.ipa_sync_config);
            info!(%diag);
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
    //  * can we connect to ipa?
    let mut ipa_client = match LdapClientBuilder::new(&sync_config.ipa_uri)
        .add_tls_ca(&sync_config.ipa_ca)
        .build()
        .await
    {
        Ok(lc) => lc,
        Err(e) => {
            error!(?e, "Failed to connect to freeipa");
            return Err(SyncError::LdapConn);
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

    // Based on the scim_sync_status, perform our sync repl

    let mode = proto::SyncRequestMode::RefreshOnly;

    let cookie = match &scim_sync_status {
        ScimSyncState::Refresh => None,
        ScimSyncState::Active { cookie } => Some(cookie.0.clone()),
    };

    let is_initialise = cookie.is_none();

    let filter = LdapFilter::Or(vec![
        // LdapFilter::Equality(LDAP_ATTR_OBJECTCLASS.into(), "domain".to_string()),
        LdapFilter::And(vec![
            LdapFilter::Equality(LDAP_ATTR_OBJECTCLASS.into(), "person".to_string()),
            LdapFilter::Equality(LDAP_ATTR_OBJECTCLASS.into(), "posixaccount".to_string()),
        ]),
        LdapFilter::And(vec![
            LdapFilter::Equality(LDAP_ATTR_OBJECTCLASS.into(), "groupofnames".to_string()),
            LdapFilter::Equality(LDAP_ATTR_OBJECTCLASS.into(), "ipausergroup".to_string()),
            // Ignore user private groups, kani generates these internally.
            LdapFilter::Not(Box::new(LdapFilter::Equality(
                LDAP_ATTR_OBJECTCLASS.into(),
                "mepmanagedentry".to_string(),
            ))),
            // Need to exclude the admins group as it gid conflicts to admin.
            LdapFilter::Not(Box::new(LdapFilter::Equality(
                LDAP_ATTR_CN.into(),
                "admins".to_string(),
            ))),
            // Kani internally has an all persons group.
            LdapFilter::Not(Box::new(LdapFilter::Equality(
                LDAP_ATTR_CN.into(),
                "ipausers".to_string(),
            ))),
            // Ignore editors/trust admins
            LdapFilter::Not(Box::new(LdapFilter::Equality(
                LDAP_ATTR_CN.into(),
                "editors".to_string(),
            ))),
            LdapFilter::Not(Box::new(LdapFilter::Equality(
                LDAP_ATTR_CN.into(),
                "trust admins".to_string(),
            ))),
        ]),
        // Fetch TOTP's so we know when/if they change.
        LdapFilter::And(vec![
            LdapFilter::Equality(LDAP_ATTR_OBJECTCLASS.into(), "ipatoken".to_string()),
            LdapFilter::Equality(LDAP_ATTR_OBJECTCLASS.into(), "ipatokentotp".to_string()),
        ]),
    ]);

    debug!(ipa_sync_base_dn = ?sync_config.ipa_sync_base_dn, ?cookie, ?mode, ?filter);
    let sync_result = match ipa_client
        .syncrepl(sync_config.ipa_sync_base_dn.clone(), filter, cookie, mode)
        .await
    {
        Ok(results) => results,
        Err(e) => {
            error!(?e, "Failed to perform syncrepl from ipa");
            return Err(SyncError::LdapSyncrepl);
        }
    };

    if opt.proto_dump {
        let stdout = std::io::stdout();
        if let Err(e) = serde_json::to_writer_pretty(stdout, &sync_result) {
            error!(?e, "Failed to serialise ldap sync response");
        }
    }

    // Convert the ldap sync repl result to a scim equivalent
    let scim_sync_request = match sync_result {
        LdapSyncRepl::Success {
            cookie,
            refresh_deletes,
            entries,
            delete_uuids,
            present_uuids,
        } => {
            if refresh_deletes {
                error!("Unsure how to handle refreshDeletes=True");
                return Err(SyncError::Preprocess);
            }

            if present_uuids.is_some() {
                error!("Unsure how to handle presentUuids > 0");
                return Err(SyncError::Preprocess);
            }

            let to_state = cookie
                .map(|cookie| {
                    ScimSyncState::Active { cookie }
                })
                .ok_or_else(|| {
                    error!("Invalid state, ldap sync repl did not provide a valid state cookie in response.");

                    SyncError::Preprocess

                })?;

            // process the entries to scim.
            let entries = match process_ipa_sync_result(
                &mut ipa_client,
                sync_config.ipa_sync_base_dn.clone(),
                entries,
                &sync_config.entry_map,
                is_initialise,
                sync_config
                    .sync_password_as_unix_password
                    .unwrap_or_default(),
            )
            .await
            {
                Ok(ssr) => ssr,
                Err(()) => {
                    error!("Failed to process IPA entries to SCIM");
                    return Err(SyncError::Preprocess);
                }
            };

            let retain = if let Some(delete_uuids) = delete_uuids {
                ScimSyncRetentionMode::Delete(delete_uuids)
            } else {
                ScimSyncRetentionMode::Ignore
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

async fn process_ipa_sync_result(
    ipa_client: &mut LdapClient,
    basedn: String,
    ldap_entries: Vec<LdapSyncReplEntry>,
    entry_config_map: &BTreeMap<Uuid, EntryConfig>,
    is_initialise: bool,
    sync_password_as_unix_password: bool,
) -> Result<Vec<ScimEntry>, ()> {
    // Because of how TOTP works with freeipa it's a soft referral from
    // the totp toward the user. This means if a TOTP is added or removed
    // we see those as unique entries in the syncrepl but we are missing
    // the user entry that actually needs the update since Kanidm makes TOTP
    // part of the entry itself.
    //
    // This *also* means that when a user is updated that we also need to
    // fetch their TOTP's that are related so we can assert them on the
    // submission.
    //
    // Because of this, we have to do some client-side processing here to
    // work out what "entries we are missing" and do a second search to
    // fetch them. Sadly, this means that we need to do a second search
    // and since ldap is NOT transactional there is a possibility of a
    // desync between the sync-repl and the results of the second search.
    //
    // There are 5 possibilities - note one of TOTP or USER must be in syncrepl
    // state else we wouldn't proceed.
    //      TOTP          USER             OUTCOME
    //    SyncRepl      SyncRepl         No ext detail needed, proceed
    //    SyncRepl      Add/Mod          Update user, won't change on next syncrepl
    //    SyncRepl        Del            Ignore this TOTP -> will be deleted on next syncrepl
    //    Add/Mod       SyncRepl         Add the new TOTP, won't change on next syncrepl
    //      Del         SyncRepl         Remove TOTP, won't change on next syncrepl
    //
    // The big challenge is to transform our data in a way that we can actually work
    // with it here meaning we have to disassemble and "index" the content of our
    // sync result.

    // Hash entries by DN -> Split TOTP's to their own set.
    //    make a list of updated TOTP's and what DN's they require.
    //    make a list of updated Users and what TOTP's they require.

    let mut entries = BTreeMap::default();
    let mut user_dns = Vec::default();
    let mut totp_entries: BTreeMap<String, Vec<_>> = BTreeMap::default();

    for lentry in ldap_entries.into_iter() {
        if lentry
            .entry
            .attrs
            .get(LDAP_ATTR_OBJECTCLASS)
            .map(|oc| oc.contains("ipatokentotp"))
            .unwrap_or_default()
        {
            // It's an otp. Lets see ...
            let token_owner_dn = if let Some(todn) = lentry
                .entry
                .attrs
                .get("ipatokenowner")
                .and_then(|attr| if attr.len() != 1 { None } else { attr.first() })
            {
                debug!("totp with owner {}", todn);
                todn.clone()
            } else {
                warn!("totp with invalid ownership will be ignored");
                continue;
            };

            if !totp_entries.contains_key(&token_owner_dn) {
                totp_entries.insert(token_owner_dn.clone(), Vec::default());
            }

            if let Some(v) = totp_entries.get_mut(&token_owner_dn) {
                v.push(lentry)
            }
        } else {
            let dn = lentry.entry.dn.clone();

            if lentry
                .entry
                .attrs
                .get(LDAP_ATTR_OBJECTCLASS)
                .map(|oc| oc.contains(EntryClass::Person.as_ref()))
                .unwrap_or_default()
            {
                user_dns.push(dn.clone());
            }

            entries.insert(dn, lentry);
        }
    }

    // Now, we have to invert the totp set so that it's defined by entry dn instead.
    debug!("te, {}, e {}", totp_entries.len(), entries.len());

    // If this is an INIT we have the full state already - no extra search is needed.

    // On a refresh, we need to search and fix up to make sure TOTP/USER sets are
    // consistent.
    let search_filter = if !is_initialise {
        // If the totp's related user is NOT in our sync repl, we need to fetch them.
        let fetch_user: Vec<&str> = totp_entries
            .keys()
            .map(|k| k.as_str())
            .filter(|k| !entries.contains_key(*k))
            .collect();

        // For every user in our fetch_user *and* entries set, we need to fetch their
        // related TOTP's.
        let fetch_totps_for: Vec<&str> = fetch_user
            .iter()
            .copied()
            .chain(user_dns.iter().map(|s| s.as_str()))
            .collect();

        // Create filter (could hit a limit, may need to split this search).
        let totp_conditions: Vec<_> = fetch_totps_for
            .iter()
            .map(|dn| LdapFilter::Equality("ipatokenowner".to_string(), dn.to_string()))
            .collect();

        let mut or_filter = Vec::with_capacity(2);

        if !totp_conditions.is_empty() {
            or_filter.push(LdapFilter::And(vec![
                LdapFilter::Equality(LDAP_ATTR_OBJECTCLASS.into(), "ipatoken".to_string()),
                LdapFilter::Equality(LDAP_ATTR_OBJECTCLASS.into(), "ipatokentotp".to_string()),
                LdapFilter::Or(totp_conditions),
            ]));
        }

        let user_conditions: Vec<_> = fetch_user
            .iter()
            .filter_map(|dn| {
                // We have to split the DN to it's RDN because lol.
                dn.split_once(',')
                    .and_then(|(rdn, _)| rdn.split_once('='))
                    .map(|(_, uid)| LdapFilter::Equality(ATTR_UID.to_string(), uid.to_string()))
            })
            .collect();

        if !user_conditions.is_empty() {
            or_filter.push(LdapFilter::And(vec![
                LdapFilter::Equality(LDAP_ATTR_OBJECTCLASS.into(), "person".to_string()),
                LdapFilter::Equality(LDAP_ATTR_OBJECTCLASS.into(), "ipantuserattrs".to_string()),
                LdapFilter::Equality(LDAP_ATTR_OBJECTCLASS.into(), "posixaccount".to_string()),
                LdapFilter::Or(user_conditions),
            ]));
        }

        if or_filter.is_empty() {
            None
        } else {
            Some(LdapFilter::Or(or_filter))
        }
    } else {
        None
    };

    // If we have something that needs lookup, apply now.
    if let Some(filter) = search_filter {
        debug!(?filter);
        // Search - we use syncrepl here and discard the cookie because we need the
        // entry uuid to be given from the nsuniqueid else we have issues.
        let mode = proto::SyncRequestMode::RefreshOnly;
        match ipa_client.syncrepl(basedn, filter, None, mode).await {
            Ok(LdapSyncRepl::Success {
                cookie: _,
                refresh_deletes: _,
                entries: sync_entries,
                delete_uuids: _,
                present_uuids: _,
            }) => {
                // Inject all new entries to our maps. At this point we discard the original content
                // of the totp entries since we just fetched them all again anyway.

                totp_entries.clear();

                for lentry in sync_entries.into_iter() {
                    if lentry
                        .entry
                        .attrs
                        .get(LDAP_ATTR_OBJECTCLASS)
                        .map(|oc| oc.contains("ipatokentotp"))
                        .unwrap_or_default()
                    {
                        let token_owner_dn = if let Some(todn) = lentry
                            .entry
                            .attrs
                            .get("ipatokenowner")
                            .and_then(|attr| if attr.len() != 1 { None } else { attr.first() })
                        {
                            debug!("totp with owner {}", todn);
                            todn.clone()
                        } else {
                            warn!("totp with invalid ownership will be ignored");
                            continue;
                        };

                        if !totp_entries.contains_key(&token_owner_dn) {
                            totp_entries.insert(token_owner_dn.clone(), Vec::default());
                        }

                        if let Some(v) = totp_entries.get_mut(&token_owner_dn) {
                            v.push(lentry)
                        }
                    } else {
                        let dn = lentry.entry.dn.clone();
                        entries.insert(dn, lentry);
                    }
                }
            }
            Ok(LdapSyncRepl::RefreshRequired) => {
                error!("Failed due to invalid search state from ipa");
                return Err(());
            }
            Err(e) => {
                error!(?e, "Failed to perform search from ipa");
                return Err(());
            }
        }
    }

    // For each updated TOTP -> If it's related DN is not in Hash -> remove from map
    totp_entries.retain(|k, _| {
        let x = entries.contains_key(k);
        if !x {
            warn!("Removing totp with no valid owner {}", k);
        }
        x
    });

    let empty_slice = Vec::default();

    // Future - make this par-map
    entries
        .into_iter()
        .filter_map(|(dn, e)| {
            let e_config = entry_config_map
                .get(&e.entry_uuid)
                .cloned()
                .unwrap_or_default();

            let totp = totp_entries.get(&dn).unwrap_or(&empty_slice);

            match ipa_to_scim_entry(e, &e_config, totp, sync_password_as_unix_password) {
                Ok(Some(e)) => Some(Ok(e)),
                Ok(None) => None,
                Err(()) => Some(Err(())),
            }
        })
        .collect::<Result<Vec<_>, _>>()
}

fn ipa_to_scim_entry(
    sync_entry: LdapSyncReplEntry,
    entry_config: &EntryConfig,
    totp: &[LdapSyncReplEntry],
    sync_password_as_unix_password: bool,
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
        .get(LDAP_ATTR_OBJECTCLASS)
        .ok_or_else(|| {
            debug!(?sync_entry);
            error!("Invalid entry - no object class {}", dn);
        })?;

    if oc.contains("person") {
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
                .remove_ava_single(Attribute::Uid.as_ref())
                .ok_or_else(|| {
                    error!("Missing required attribute {}", Attribute::Uid);
                })?
        };

        // ⚠️  hardcoded skip on admin here!!!
        if user_name == "admin" {
            info!("kanidm excludes {}", dn);
            return Ok(None);
        }

        let display_name = entry
            .remove_ava_single(Attribute::Cn.as_ref())
            .ok_or_else(|| {
                error!("Missing required attribute {}", Attribute::Cn);
            })?;

        // There are some installs that incorrectly assign this to a shared
        // group.
        let gidnumber = if let Some(number) = entry_config.map_gidnumber {
            Some(number)
        } else {
            entry
                .remove_ava_single(Attribute::UidNumber.as_ref())
                .map(|uid| {
                    u32::from_str(&uid).map_err(|_| {
                        error!("Invalid {}", Attribute::UidNumber);
                    })
                })
                .transpose()?
        };

        let password_import = entry
            .remove_ava_single(Attribute::IpaNtHash.as_ref())
            .map(|s| format!("ipaNTHash: {}", s))
            // If we don't have this, try one of the other hashes that *might* work
            // The reason we don't do this by default is there are multiple
            // pw hash formats in 389-ds we don't support!
            .or_else(|| entry.remove_ava_single(Attribute::UserPassword.as_ref()));

        let unix_password_import = if sync_password_as_unix_password {
            password_import.clone()
        } else {
            None
        };

        let mail: Vec<_> = entry
            .remove_ava(Attribute::Mail.as_ref())
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

        let totp_import = if !totp.is_empty() {
            if password_import.is_some() {
                // If there are TOTP's, convert them to something sensible.
                totp.iter().filter_map(ipa_to_totp).collect()
            } else {
                warn!(
                    "Skipping totp for {} as password is not available to import.",
                    dn
                );
                Vec::default()
            }
        } else {
            Vec::default()
        };

        let ssh_publickey = entry
            .remove_ava(Attribute::IpaSshPubKey.as_ref())
            .map(|set| {
                set.into_iter()
                    .enumerate()
                    .map(|(i, value)| ScimSshPubKey {
                        label: format!("{}-{}", Attribute::IpaSshPubKey, i),
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

        let login_shell = entry.remove_ava_single(Attribute::LoginShell.as_ref());
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
    } else if oc.contains(LDAP_CLASS_GROUPOFNAMES) {
        let LdapSyncReplEntry {
            entry_uuid,
            state: _,
            mut entry,
        } = sync_entry;

        let id = entry_uuid;

        let name = entry
            .remove_ava_single(Attribute::Cn.as_ref())
            .ok_or_else(|| {
                error!("Missing required attribute cn");
            })?;

        // ⚠️  hardcoded skip on trust admins / editors / ipausers here!!!
        if name == "trust admins" || name == "editors" || name == "ipausers" || name == "admins" {
            info!("kanidm excludes {}", dn);
            return Ok(None);
        }

        let description = entry.remove_ava_single(Attribute::Description.as_ref());

        let gidnumber = entry
            .remove_ava_single(Attribute::GidNumber.as_ref())
            .map(|gid| {
                u32::from_str(&gid).map_err(|_| {
                    error!("Invalid gidnumber");
                })
            })
            .transpose()?;

        let members: Vec<_> = entry
            .remove_ava(Attribute::Member.as_ref())
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

fn ipa_to_totp(sync_entry: &LdapSyncReplEntry) -> Option<ScimTotp> {
    let external_id = sync_entry
        .entry
        .attrs
        .get("ipatokenuniqueid")
        .and_then(|v| v.first().cloned())
        .or_else(|| {
            warn!("Invalid ipatokenuniqueid");
            None
        })?;

    let secret = sync_entry
        .entry
        .attrs
        .get("ipatokenotpkey")
        .and_then(|v| v.first())
        .and_then(|s| {
            // Decode, and then make it urlsafe.
            Base64UrlSafeData::try_from(s.as_str())
                .ok()
                .map(|b| b.to_string())
        })
        .or_else(|| {
            warn!("Invalid ipatokenotpkey");
            None
        })?;

    let algo = sync_entry
        .entry
        .attrs
        .get("ipatokenotpalgorithm")
        .and_then(|v| v.first().cloned())
        .or_else(|| {
            warn!("Invalid ipatokenotpalgorithm");
            None
        })?;

    let step = sync_entry
        .entry
        .attrs
        .get("ipatokentotptimestep")
        .and_then(|v| v.first())
        .and_then(|d| u32::from_str(d).ok())
        .or_else(|| {
            warn!("Invalid ipatokentotptimestep");
            None
        })?;

    let digits = sync_entry
        .entry
        .attrs
        .get("ipatokenotpdigits")
        .and_then(|v| v.first())
        .and_then(|d| u32::from_str(d).ok())
        .or_else(|| {
            warn!("Invalid ipatokenotpdigits");
            None
        })?;

    Some(ScimTotp {
        external_id,
        secret,
        algo,
        step,
        digits,
    })
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
