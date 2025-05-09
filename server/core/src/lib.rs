//! These contain the server "cores". These are able to startup the server
//! (bootstrap) to a running state and then execute tasks. This is where modules
//! are logically ordered based on their depenedncies for execution. Some of these
//! are task-only i.e. reindexing, and some of these launch the server into a
//! fully operational state (https, ldap, etc).
//!
//! Generally, this is the "entry point" where the server begins to run, and
//! the entry point for all client traffic which is then directed to the
//! various `actors`.

#![deny(warnings)]
#![warn(unused_extern_crates)]
#![warn(unused_imports)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[macro_use]
extern crate tracing;
#[macro_use]
extern crate kanidmd_lib;

mod actors;
pub mod admin;
pub mod config;
mod crypto;
mod https;
mod interval;
mod ldaps;
mod repl;
mod utils;

use crate::actors::{QueryServerReadV1, QueryServerWriteV1};
use crate::admin::AdminActor;
use crate::config::{Configuration, ServerRole};
use crate::interval::IntervalActor;
use crate::utils::touch_file_or_quit;
use compact_jwt::{JwsHs256Signer, JwsSigner};
use kanidm_proto::internal::OperationError;
use kanidmd_lib::be::{Backend, BackendConfig, BackendTransaction};
use kanidmd_lib::idm::ldap::LdapServer;
use kanidmd_lib::prelude::*;
use kanidmd_lib::schema::Schema;
use kanidmd_lib::status::StatusActor;
use kanidmd_lib::value::CredentialType;
#[cfg(not(target_family = "windows"))]
use libc::umask;
use std::fmt::{Display, Formatter};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio::sync::Notify;
use tokio::task;

// === internal setup helpers

fn setup_backend(config: &Configuration, schema: &Schema) -> Result<Backend, OperationError> {
    setup_backend_vacuum(config, schema, false)
}

fn setup_backend_vacuum(
    config: &Configuration,
    schema: &Schema,
    vacuum: bool,
) -> Result<Backend, OperationError> {
    // Limit the scope of the schema txn.
    // let schema_txn = task::block_on(schema.write());
    let schema_txn = schema.write();
    let idxmeta = schema_txn.reload_idxmeta();

    let pool_size: u32 = config.threads as u32;

    let cfg = BackendConfig::new(
        config.db_path.as_deref(),
        pool_size,
        config.db_fs_type.unwrap_or_default(),
        config.db_arc_size,
    );

    Backend::new(cfg, idxmeta, vacuum)
}

// TODO #54: We could move most of the be/schema/qs setup and startup
// outside of this call, then pass in "what we need" in a cloneable
// form, this way we could have separate Idm vs Qs threads, and dedicated
// threads for write vs read
async fn setup_qs_idms(
    be: Backend,
    schema: Schema,
    config: &Configuration,
) -> Result<(QueryServer, IdmServer, IdmServerDelayed, IdmServerAudit), OperationError> {
    let curtime = duration_from_epoch_now();
    // Create a query_server implementation
    let query_server = QueryServer::new(be, schema, config.domain.clone(), curtime)?;

    // TODO #62: Should the IDM parts be broken out to the IdmServer?
    // What's important about this initial setup here is that it also triggers
    // the schema and acp reload, so they are now configured correctly!
    // Initialise the schema core.
    //
    // Now search for the schema itself, and validate that the system
    // in memory matches the BE on disk, and that it's syntactically correct.
    // Write it out if changes are needed.
    query_server
        .initialise_helper(curtime, DOMAIN_TGT_LEVEL)
        .await?;

    // We generate a SINGLE idms only!
    let is_integration_test = config.integration_test_config.is_some();
    let (idms, idms_delayed, idms_audit) = IdmServer::new(
        query_server.clone(),
        &config.origin,
        is_integration_test,
        curtime,
    )
    .await?;

    Ok((query_server, idms, idms_delayed, idms_audit))
}

async fn setup_qs(
    be: Backend,
    schema: Schema,
    config: &Configuration,
) -> Result<QueryServer, OperationError> {
    let curtime = duration_from_epoch_now();
    // Create a query_server implementation
    let query_server = QueryServer::new(be, schema, config.domain.clone(), curtime)?;

    // TODO #62: Should the IDM parts be broken out to the IdmServer?
    // What's important about this initial setup here is that it also triggers
    // the schema and acp reload, so they are now configured correctly!
    // Initialise the schema core.
    //
    // Now search for the schema itself, and validate that the system
    // in memory matches the BE on disk, and that it's syntactically correct.
    // Write it out if changes are needed.
    query_server
        .initialise_helper(curtime, DOMAIN_TGT_LEVEL)
        .await?;

    Ok(query_server)
}

macro_rules! dbscan_setup_be {
    (
        $config:expr
    ) => {{
        let schema = match Schema::new() {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to setup in memory schema: {:?}", e);
                std::process::exit(1);
            }
        };

        match setup_backend($config, &schema) {
            Ok(be) => be,
            Err(e) => {
                error!("Failed to setup BE: {:?}", e);
                return;
            }
        }
    }};
}

pub fn dbscan_list_indexes_core(config: &Configuration) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.list_indexes() {
        Ok(mut idx_list) => {
            idx_list.sort_unstable();
            idx_list.iter().for_each(|idx_name| {
                println!("{}", idx_name);
            })
        }
        Err(e) => {
            error!("Failed to retrieve index list: {:?}", e);
        }
    };
}

pub fn dbscan_list_id2entry_core(config: &Configuration) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.list_id2entry() {
        Ok(mut id_list) => {
            id_list.sort_unstable_by_key(|k| k.0);
            id_list.iter().for_each(|(id, value)| {
                println!("{:>8}: {}", id, value);
            })
        }
        Err(e) => {
            error!("Failed to retrieve id2entry list: {:?}", e);
        }
    };
}

pub fn dbscan_list_index_analysis_core(config: &Configuration) {
    let _be = dbscan_setup_be!(config);
    // TBD in after slopes merge.
}

pub fn dbscan_list_index_core(config: &Configuration, index_name: &str) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.list_index_content(index_name) {
        Ok(mut idx_list) => {
            idx_list.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            idx_list.iter().for_each(|(key, value)| {
                println!("{:>50}: {:?}", key, value);
            })
        }
        Err(e) => {
            error!("Failed to retrieve index list: {:?}", e);
        }
    };
}

pub fn dbscan_get_id2entry_core(config: &Configuration, id: u64) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.get_id2entry(id) {
        Ok((id, value)) => println!("{:>8}: {}", id, value),
        Err(e) => {
            error!("Failed to retrieve id2entry value: {:?}", e);
        }
    };
}

pub fn dbscan_quarantine_id2entry_core(config: &Configuration, id: u64) {
    let be = dbscan_setup_be!(config);
    let mut be_wrtxn = match be.write() {
        Ok(txn) => txn,
        Err(err) => {
            error!(
                ?err,
                "Unable to proceed, backend write transaction failure."
            );
            return;
        }
    };

    match be_wrtxn
        .quarantine_entry(id)
        .and_then(|_| be_wrtxn.commit())
    {
        Ok(()) => {
            println!("quarantined - {:>8}", id)
        }
        Err(e) => {
            error!("Failed to quarantine id2entry value: {:?}", e);
        }
    };
}

pub fn dbscan_list_quarantined_core(config: &Configuration) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.list_quarantined() {
        Ok(mut id_list) => {
            id_list.sort_unstable_by_key(|k| k.0);
            id_list.iter().for_each(|(id, value)| {
                println!("{:>8}: {}", id, value);
            })
        }
        Err(e) => {
            error!("Failed to retrieve id2entry list: {:?}", e);
        }
    };
}

pub fn dbscan_restore_quarantined_core(config: &Configuration, id: u64) {
    let be = dbscan_setup_be!(config);
    let mut be_wrtxn = match be.write() {
        Ok(txn) => txn,
        Err(err) => {
            error!(
                ?err,
                "Unable to proceed, backend write transaction failure."
            );
            return;
        }
    };

    match be_wrtxn
        .restore_quarantined(id)
        .and_then(|_| be_wrtxn.commit())
    {
        Ok(()) => {
            println!("restored - {:>8}", id)
        }
        Err(e) => {
            error!("Failed to restore quarantined id2entry value: {:?}", e);
        }
    };
}

pub fn backup_server_core(config: &Configuration, dst_path: &Path) {
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    let be = match setup_backend(config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };

    let mut be_ro_txn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    let r = be_ro_txn.backup(dst_path);
    match r {
        Ok(_) => info!("Backup success!"),
        Err(e) => {
            error!("Backup failed: {:?}", e);
            std::process::exit(1);
        }
    };
    // Let the txn abort, even on success.
}

pub async fn restore_server_core(config: &Configuration, dst_path: &Path) {
    // If it's an in memory database, we don't need to touch anything
    if let Some(db_path) = config.db_path.as_ref() {
        touch_file_or_quit(db_path);
    }

    // First, we provide the in-memory schema so that core attrs are indexed correctly.
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    let be = match setup_backend(config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup backend: {:?}", e);
            return;
        }
    };

    let mut be_wr_txn = match be.write() {
        Ok(txn) => txn,
        Err(err) => {
            error!(
                ?err,
                "Unable to proceed, backend write transaction failure."
            );
            return;
        }
    };
    let r = be_wr_txn.restore(dst_path).and_then(|_| be_wr_txn.commit());

    if r.is_err() {
        error!("Failed to restore database: {:?}", r);
        std::process::exit(1);
    }
    info!("Database loaded successfully");

    reindex_inner(be, schema, config).await;

    info!("✅ Restore Success!");
}

pub async fn reindex_server_core(config: &Configuration) {
    info!("Start Index Phase 1 ...");
    // First, we provide the in-memory schema so that core attrs are indexed correctly.
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    let be = match setup_backend(config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };

    reindex_inner(be, schema, config).await;

    info!("✅ Reindex Success!");
}

async fn reindex_inner(be: Backend, schema: Schema, config: &Configuration) {
    // Reindex only the core schema attributes to bootstrap the process.
    let mut be_wr_txn = match be.write() {
        Ok(txn) => txn,
        Err(err) => {
            error!(
                ?err,
                "Unable to proceed, backend write transaction failure."
            );
            return;
        }
    };

    let r = be_wr_txn.reindex(true).and_then(|_| be_wr_txn.commit());

    // Now that's done, setup a minimal qs and reindex from that.
    if r.is_err() {
        error!("Failed to reindex database: {:?}", r);
        std::process::exit(1);
    }
    info!("Index Phase 1 Success!");

    info!("Attempting to init query server ...");

    let (qs, _idms, _idms_delayed, _idms_audit) = match setup_qs_idms(be, schema, config).await {
        Ok(t) => t,
        Err(e) => {
            error!("Unable to setup query server or idm server -> {:?}", e);
            return;
        }
    };
    info!("Init Query Server Success!");

    info!("Start Index Phase 2 ...");

    let Ok(mut qs_write) = qs.write(duration_from_epoch_now()).await else {
        error!("Unable to acquire write transaction");
        return;
    };
    let r = qs_write.reindex(true).and_then(|_| qs_write.commit());

    match r {
        Ok(_) => info!("Index Phase 2 Success!"),
        Err(e) => {
            error!("Reindex failed: {:?}", e);
            std::process::exit(1);
        }
    };
}

pub fn vacuum_server_core(config: &Configuration) {
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    // The schema doesn't matter here. Vacuum is run as part of db open to avoid
    // locking.
    let r = setup_backend_vacuum(config, &schema, true);

    match r {
        Ok(_) => eprintln!("Vacuum Success!"),
        Err(e) => {
            eprintln!("Vacuum failed: {:?}", e);
            std::process::exit(1);
        }
    };
}

pub async fn domain_rename_core(config: &Configuration) {
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    // Start the backend.
    let be = match setup_backend(config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };

    // Setup the qs, and perform any migrations and changes we may have.
    let qs = match setup_qs(be, schema, config).await {
        Ok(t) => t,
        Err(e) => {
            error!("Unable to setup query server -> {:?}", e);
            return;
        }
    };

    let new_domain_name = config.domain.as_str();

    // make sure we're actually changing the domain name...
    match qs.read().await.map(|qs| qs.get_domain_name().to_string()) {
        Ok(old_domain_name) => {
            admin_info!(?old_domain_name, ?new_domain_name);
            if old_domain_name == new_domain_name {
                admin_info!("Domain name not changing, stopping.");
                return;
            }
            admin_debug!(
                "Domain name is changing from {:?} to {:?}",
                old_domain_name,
                new_domain_name
            );
        }
        Err(e) => {
            admin_error!("Failed to query domain name, quitting! -> {:?}", e);
            return;
        }
    }

    let Ok(mut qs_write) = qs.write(duration_from_epoch_now()).await else {
        error!("Unable to acquire write transaction");
        return;
    };
    let r = qs_write
        .danger_domain_rename(new_domain_name)
        .and_then(|_| qs_write.commit());

    match r {
        Ok(_) => info!("Domain Rename Success!"),
        Err(e) => {
            error!("Domain Rename Failed - Rollback has occurred: {:?}", e);
            std::process::exit(1);
        }
    };
}

pub async fn verify_server_core(config: &Configuration) {
    let curtime = duration_from_epoch_now();
    // setup the qs - without initialise!
    let schema_mem = match Schema::new() {
        Ok(sc) => sc,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            return;
        }
    };
    // Setup the be
    let be = match setup_backend(config, &schema_mem) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };

    let server = match QueryServer::new(be, schema_mem, config.domain.clone(), curtime) {
        Ok(qs) => qs,
        Err(err) => {
            error!(?err, "Failed to setup query server");
            return;
        }
    };

    // Run verifications.
    let r = server.verify().await;

    if r.is_empty() {
        eprintln!("Verification passed!");
        std::process::exit(0);
    } else {
        for er in r {
            error!("{:?}", er);
        }
        std::process::exit(1);
    }

    // Now add IDM server verifications?
}

pub fn cert_generate_core(config: &Configuration) {
    // Get the cert root

    let (tls_key_path, tls_chain_path) = match &config.tls_config {
        Some(tls_config) => (tls_config.key.as_path(), tls_config.chain.as_path()),
        None => {
            error!("Unable to find TLS configuration");
            std::process::exit(1);
        }
    };

    if tls_key_path.exists() && tls_chain_path.exists() {
        info!(
            "TLS key and chain already exist - remove them first if you intend to regenerate these"
        );
        return;
    }

    let origin = match Url::parse(&config.origin) {
        Ok(url) => url,
        Err(e) => {
            error!(err = ?e, "Unable to parse origin URL - refusing to start. You must correct the value for origin. {:?}", config.origin);
            std::process::exit(1);
        }
    };

    let origin_domain = if let Some(d) = origin.domain() {
        d
    } else {
        error!("origin does not contain a valid domain");
        std::process::exit(1);
    };

    let cert_root = match tls_key_path.parent() {
        Some(parent) => parent,
        None => {
            error!("Unable to find parent directory of {:?}", tls_key_path);
            std::process::exit(1);
        }
    };

    let ca_cert = cert_root.join("ca.pem");
    let ca_key = cert_root.join("cakey.pem");
    let tls_cert_path = cert_root.join("cert.pem");

    let ca_handle = if !ca_cert.exists() || !ca_key.exists() {
        // Generate the CA again.
        let ca_handle = match crypto::build_ca(None) {
            Ok(ca_handle) => ca_handle,
            Err(e) => {
                error!(err = ?e, "Failed to build CA");
                std::process::exit(1);
            }
        };

        if crypto::write_ca(ca_key, ca_cert, &ca_handle).is_err() {
            error!("Failed to write CA");
            std::process::exit(1);
        }

        ca_handle
    } else {
        match crypto::load_ca(ca_key, ca_cert) {
            Ok(ca_handle) => ca_handle,
            Err(_) => {
                error!("Failed to load CA");
                std::process::exit(1);
            }
        }
    };

    if !tls_key_path.exists() || !tls_chain_path.exists() || !tls_cert_path.exists() {
        // Generate the cert from the ca.
        let cert_handle = match crypto::build_cert(origin_domain, &ca_handle, None, None) {
            Ok(cert_handle) => cert_handle,
            Err(e) => {
                error!(err = ?e, "Failed to build certificate");
                std::process::exit(1);
            }
        };

        if crypto::write_cert(tls_key_path, tls_chain_path, tls_cert_path, &cert_handle).is_err() {
            error!("Failed to write certificates");
            std::process::exit(1);
        }
    }
    info!("certificate generation complete");
}

#[derive(Clone, Debug)]
pub enum CoreAction {
    Shutdown,
}

pub(crate) enum TaskName {
    AdminSocket,
    AuditdActor,
    BackupActor,
    DelayedActionActor,
    HttpsServer,
    IntervalActor,
    LdapActor,
    Replication,
    TlsAcceptorReload,
}

impl Display for TaskName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TaskName::AdminSocket => "Admin Socket",
                TaskName::AuditdActor => "Auditd Actor",
                TaskName::BackupActor => "Backup Actor",
                TaskName::DelayedActionActor => "Delayed Action Actor",
                TaskName::HttpsServer => "HTTPS Server",
                TaskName::IntervalActor => "Interval Actor",
                TaskName::LdapActor => "LDAP Acceptor Actor",
                TaskName::Replication => "Replication",
                TaskName::TlsAcceptorReload => "TlsAcceptor Reload Monitor",
            }
        )
    }
}

pub struct CoreHandle {
    clean_shutdown: bool,
    tx: broadcast::Sender<CoreAction>,
    tls_acceptor_reload_notify: Arc<Notify>,
    /// This stores a name for the handle, and the handle itself so we can tell which failed/succeeded at the end.
    handles: Vec<(TaskName, task::JoinHandle<()>)>,
}

impl CoreHandle {
    pub fn subscribe(&mut self) -> broadcast::Receiver<CoreAction> {
        self.tx.subscribe()
    }

    pub async fn shutdown(&mut self) {
        if self.tx.send(CoreAction::Shutdown).is_err() {
            eprintln!("No receivers acked shutdown request. Treating as unclean.");
            return;
        }

        // Wait on the handles.
        while let Some((handle_name, handle)) = self.handles.pop() {
            if let Err(error) = handle.await {
                eprintln!("Task {} failed to finish: {:?}", handle_name, error);
            }
        }

        self.clean_shutdown = true;
    }

    pub async fn tls_acceptor_reload(&mut self) {
        self.tls_acceptor_reload_notify.notify_one()
    }
}

impl Drop for CoreHandle {
    fn drop(&mut self) {
        if !self.clean_shutdown {
            eprintln!("⚠️  UNCLEAN SHUTDOWN OCCURRED ⚠️ ");
        }
        // Can't enable yet until we clean up unix_int cache layer test
        // debug_assert!(self.clean_shutdown);
    }
}

pub async fn create_server_core(
    config: Configuration,
    config_test: bool,
) -> Result<CoreHandle, ()> {
    // Until this point, we probably want to write to the log macro fns.
    let (broadcast_tx, mut broadcast_rx) = broadcast::channel(4);

    if config.integration_test_config.is_some() {
        warn!("RUNNING IN INTEGRATION TEST MODE.");
        warn!("IF YOU SEE THIS IN PRODUCTION YOU MUST CONTACT SUPPORT IMMEDIATELY.");
    } else if config.tls_config.is_none() {
        // TLS is great! We won't run without it.
        error!("Running without TLS is not supported! Quitting!");
        return Err(());
    }

    info!(
        "Starting kanidm with {}configuration: {}",
        if config_test { "TEST " } else { "" },
        config
    );
    // Setup umask, so that every we touch or create is secure.
    #[cfg(not(target_family = "windows"))]
    unsafe {
        umask(0o0027)
    };

    // Similar, create a stats task which aggregates statistics from the
    // server as they come in.
    let status_ref = StatusActor::start();

    // Setup TLS (if any)
    let maybe_tls_acceptor = match crypto::setup_tls(&config.tls_config) {
        Ok(tls_acc) => tls_acc,
        Err(err) => {
            error!(?err, "Failed to configure TLS acceptor");
            return Err(());
        }
    };

    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            return Err(());
        }
    };

    // Setup the be for the qs.
    let be = match setup_backend(&config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE -> {:?}", e);
            return Err(());
        }
    };
    // Start the IDM server.
    let (_qs, idms, mut idms_delayed, mut idms_audit) =
        match setup_qs_idms(be, schema, &config).await {
            Ok(t) => t,
            Err(e) => {
                error!("Unable to setup query server or idm server -> {:?}", e);
                return Err(());
            }
        };

    // Extract any configuration from the IDMS that we may need.
    // For now we just do this per run, but we need to extract this from the db later.
    let jws_signer = match JwsHs256Signer::generate_hs256() {
        Ok(k) => k.set_sign_option_embed_kid(false),
        Err(e) => {
            error!("Unable to setup jws signer -> {:?}", e);
            return Err(());
        }
    };

    // Any pre-start tasks here.
    if let Some(itc) = &config.integration_test_config {
        let Ok(mut idms_prox_write) = idms.proxy_write(duration_from_epoch_now()).await else {
            error!("Unable to acquire write transaction");
            return Err(());
        };
        // We need to set the admin pw.
        match idms_prox_write.recover_account(&itc.admin_user, Some(&itc.admin_password)) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Unable to configure INTEGRATION TEST {} account -> {:?}",
                    &itc.admin_user, e
                );
                return Err(());
            }
        };
        // set the idm_admin account password
        match idms_prox_write.recover_account(&itc.idm_admin_user, Some(&itc.idm_admin_password)) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Unable to configure INTEGRATION TEST {} account -> {:?}",
                    &itc.idm_admin_user, e
                );
                return Err(());
            }
        };

        // Add admin to idm_admins to allow tests more flexibility wrt to permissions.
        // This way our default access controls can be stricter to prevent lateral
        // movement.
        match idms_prox_write.qs_write.internal_modify_uuid(
            UUID_IDM_ADMINS,
            &ModifyList::new_append(Attribute::Member, Value::Refer(UUID_ADMIN)),
        ) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Unable to configure INTEGRATION TEST admin as member of idm_admins -> {:?}",
                    e
                );
                return Err(());
            }
        };

        match idms_prox_write.qs_write.internal_modify_uuid(
            UUID_IDM_ALL_PERSONS,
            &ModifyList::new_purge_and_set(
                Attribute::CredentialTypeMinimum,
                CredentialType::Any.into(),
            ),
        ) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Unable to configure INTEGRATION TEST default credential policy -> {:?}",
                    e
                );
                return Err(());
            }
        };

        match idms_prox_write.commit() {
            Ok(_) => {}
            Err(e) => {
                error!("Unable to commit INTEGRATION TEST setup -> {:?}", e);
                return Err(());
            }
        }
    }

    let ldap = match LdapServer::new(&idms).await {
        Ok(l) => l,
        Err(e) => {
            error!("Unable to start LdapServer -> {:?}", e);
            return Err(());
        }
    };

    // Arc the idms and ldap
    let idms_arc = Arc::new(idms);
    let ldap_arc = Arc::new(ldap);

    // Pass it to the actor for threading.
    // Start the read query server with the given be path: future config
    let server_read_ref = QueryServerReadV1::start_static(idms_arc.clone(), ldap_arc.clone());

    // Create the server async write entry point.
    let server_write_ref = QueryServerWriteV1::start_static(idms_arc.clone());

    let delayed_handle = task::spawn(async move {
        let mut buffer = Vec::with_capacity(DELAYED_ACTION_BATCH_SIZE);
        loop {
            tokio::select! {
                added = idms_delayed.recv_many(&mut buffer) => {
                    if added == 0 {
                        // Channel has closed, stop the task.
                        break
                    }
                    server_write_ref.handle_delayedaction(&mut buffer).await;
                }
                Ok(action) = broadcast_rx.recv() => {
                    match action {
                        CoreAction::Shutdown => break,
                    }
                }
            }
        }
        info!("Stopped {}", TaskName::DelayedActionActor);
    });

    let mut broadcast_rx = broadcast_tx.subscribe();

    let auditd_handle = task::spawn(async move {
        loop {
            tokio::select! {
                Ok(action) = broadcast_rx.recv() => {
                    match action {
                        CoreAction::Shutdown => break,
                    }
                }
                audit_event = idms_audit.audit_rx().recv() => {
                    match serde_json::to_string(&audit_event) {
                        Ok(audit_event) => {
                            warn!(%audit_event);
                        }
                        Err(e) => {
                            error!(err=?e, "Unable to process audit event to json.");
                            warn!(?audit_event, json=false);
                        }
                    }

                }
            }
        }
        info!("Stopped {}", TaskName::AuditdActor);
    });

    // Setup a TLS Acceptor Reload trigger.

    let mut broadcast_rx = broadcast_tx.subscribe();
    let tls_acceptor_reload_notify = Arc::new(Notify::new());
    let tls_accepter_reload_task_notify = tls_acceptor_reload_notify.clone();
    let tls_config = config.tls_config.clone();

    let ldap_configured = config.ldapbindaddress.is_some();
    let (ldap_tls_acceptor_reload_tx, ldap_tls_acceptor_reload_rx) = mpsc::channel(1);
    let (http_tls_acceptor_reload_tx, http_tls_acceptor_reload_rx) = mpsc::channel(1);

    let tls_acceptor_reload_handle = task::spawn(async move {
        loop {
            tokio::select! {
                Ok(action) = broadcast_rx.recv() => {
                    match action {
                        CoreAction::Shutdown => break,
                    }
                }
                _ = tls_accepter_reload_task_notify.notified() => {
                    let tls_acceptor = match crypto::setup_tls(&tls_config) {
                        Ok(Some(tls_acc)) => tls_acc,
                        Ok(None) => {
                            warn!("TLS not configured, ignoring reload request.");
                            continue;
                        }
                        Err(err) => {
                            error!(?err, "Failed to configure and reload TLS acceptor");
                            continue;
                        }
                    };

                    // We don't log here as the receivers will notify when they have completed
                    // the reload.
                    if ldap_configured &&
                        ldap_tls_acceptor_reload_tx.send(tls_acceptor.clone()).await.is_err() {
                            error!("ldap tls acceptor did not accept the reload, the server may have failed!");
                        };
                    if http_tls_acceptor_reload_tx.send(tls_acceptor.clone()).await.is_err() {
                        error!("http tls acceptor did not accept the reload, the server may have failed!");
                        break;
                    };
                }
            }
        }
        info!("Stopped {}", TaskName::TlsAcceptorReload);
    });

    // Setup timed events associated to the write thread
    let interval_handle = IntervalActor::start(server_write_ref, broadcast_tx.subscribe());
    // Setup timed events associated to the read thread
    let maybe_backup_handle = match &config.online_backup {
        Some(online_backup_config) => {
            if online_backup_config.enabled {
                let handle = IntervalActor::start_online_backup(
                    server_read_ref,
                    online_backup_config,
                    broadcast_tx.subscribe(),
                )?;
                Some(handle)
            } else {
                debug!("Backups disabled");
                None
            }
        }
        None => {
            debug!("Online backup not requested, skipping");
            None
        }
    };

    // If we have been requested to init LDAP, configure it now.
    let maybe_ldap_acceptor_handle = match &config.ldapbindaddress {
        Some(la) => {
            let opt_ldap_ssl_acceptor = maybe_tls_acceptor.clone();

            let h = ldaps::create_ldap_server(
                la.as_str(),
                opt_ldap_ssl_acceptor,
                server_read_ref,
                broadcast_tx.subscribe(),
                ldap_tls_acceptor_reload_rx,
                config.ldap_client_address_info.trusted_proxy_v2(),
            )
            .await?;
            Some(h)
        }
        None => {
            debug!("LDAP not requested, skipping");
            None
        }
    };

    // If we have replication configured, setup the listener with its initial replication
    // map (if any).
    let (maybe_repl_handle, maybe_repl_ctrl_tx) = match &config.repl_config {
        Some(rc) => {
            if !config_test {
                // ⚠️  only start the sockets and listeners in non-config-test modes.
                let (h, repl_ctrl_tx) =
                    repl::create_repl_server(idms_arc.clone(), rc, broadcast_tx.subscribe())
                        .await?;
                (Some(h), Some(repl_ctrl_tx))
            } else {
                (None, None)
            }
        }
        None => {
            debug!("Replication not requested, skipping");
            (None, None)
        }
    };

    let maybe_http_acceptor_handle = if config_test {
        admin_info!("This config rocks! 🪨 ");
        None
    } else {
        let h: task::JoinHandle<()> = match https::create_https_server(
            config.clone(),
            jws_signer,
            status_ref,
            server_write_ref,
            server_read_ref,
            broadcast_tx.clone(),
            maybe_tls_acceptor,
            http_tls_acceptor_reload_rx,
        )
        .await
        {
            Ok(h) => h,
            Err(e) => {
                error!("Failed to start HTTPS server -> {:?}", e);
                return Err(());
            }
        };
        if config.role != ServerRole::WriteReplicaNoUI {
            admin_info!("ready to rock! 🪨  UI available at: {}", config.origin);
        } else {
            admin_info!("ready to rock! 🪨 ");
        }
        Some(h)
    };

    // If we are NOT in integration test mode, start the admin socket now
    let maybe_admin_sock_handle = if config.integration_test_config.is_none() {
        let broadcast_rx = broadcast_tx.subscribe();

        let admin_handle = AdminActor::create_admin_sock(
            config.adminbindpath.as_str(),
            server_write_ref,
            server_read_ref,
            broadcast_rx,
            maybe_repl_ctrl_tx,
        )
        .await?;

        Some(admin_handle)
    } else {
        None
    };

    let mut handles: Vec<(TaskName, task::JoinHandle<()>)> = vec![
        (TaskName::IntervalActor, interval_handle),
        (TaskName::DelayedActionActor, delayed_handle),
        (TaskName::AuditdActor, auditd_handle),
        (TaskName::TlsAcceptorReload, tls_acceptor_reload_handle),
    ];

    if let Some(backup_handle) = maybe_backup_handle {
        handles.push((TaskName::BackupActor, backup_handle))
    }

    if let Some(admin_sock_handle) = maybe_admin_sock_handle {
        handles.push((TaskName::AdminSocket, admin_sock_handle))
    }

    if let Some(ldap_handle) = maybe_ldap_acceptor_handle {
        handles.push((TaskName::LdapActor, ldap_handle))
    }

    if let Some(http_handle) = maybe_http_acceptor_handle {
        handles.push((TaskName::HttpsServer, http_handle))
    }

    if let Some(repl_handle) = maybe_repl_handle {
        handles.push((TaskName::Replication, repl_handle))
    }

    Ok(CoreHandle {
        clean_shutdown: false,
        tls_acceptor_reload_notify,
        tx: broadcast_tx,
        handles,
    })
}
