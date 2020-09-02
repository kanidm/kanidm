mod https;
mod ldaps;
use libc::umask;

// use crossbeam::channel::unbounded;
use std::sync::Arc;
use tokio::sync::mpsc::unbounded_channel as unbounded;

use crate::config::Configuration;

// SearchResult
// use self::ctx::ServerCtx;
use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_write::QueryServerWriteV1;
use crate::async_log;
use crate::audit::AuditScope;
use crate::be::{Backend, BackendTransaction, FsType};
use crate::crypto::setup_tls;
use crate::idm::server::{IdmServer, IdmServerDelayed};
use crate::interval::IntervalActor;
use crate::ldap::LdapServer;
use crate::schema::Schema;
use crate::server::QueryServer;
use crate::status::StatusActor;
use crate::utils::duration_from_epoch_now;

use kanidm_proto::v1::OperationError;

use async_std::task;

// === internal setup helpers

fn setup_backend(config: &Configuration, schema: &Schema) -> Result<Backend, OperationError> {
    // Limit the scope of the schema txn.
    // let schema_txn = task::block_on(schema.write());
    let schema_txn = schema.write();
    let idxmeta = schema_txn.reload_idxmeta();

    let mut audit_be = AuditScope::new("backend_setup", uuid::Uuid::new_v4(), config.log_level);
    let pool_size: u32 = config.threads as u32;
    let fstype: FsType = if config
        .db_fs_type
        .as_ref()
        .map(|s| s == "zfs")
        .unwrap_or(false)
    {
        FsType::ZFS
    } else {
        FsType::Generic
    };

    let be = Backend::new(
        &mut audit_be,
        config.db_path.as_str(),
        pool_size,
        fstype,
        idxmeta,
    );
    // debug!
    audit_be.write_log();
    be
}

// TODO #54: We could move most of the be/schema/qs setup and startup
// outside of this call, then pass in "what we need" in a cloneable
// form, this way we could have seperate Idm vs Qs threads, and dedicated
// threads for write vs read
fn setup_qs_idms(
    audit: &mut AuditScope,
    be: Backend,
    schema: Schema,
) -> Result<(QueryServer, IdmServer, IdmServerDelayed), OperationError> {
    // Create a query_server implementation
    let query_server = QueryServer::new(be, schema);

    // TODO #62: Should the IDM parts be broken out to the IdmServer?
    // What's important about this initial setup here is that it also triggers
    // the schema and acp reload, so they are now configured correctly!
    // Initialise the schema core.
    //
    // Now search for the schema itself, and validate that the system
    // in memory matches the BE on disk, and that it's syntactically correct.
    // Write it out if changes are needed.
    query_server.initialise_helper(audit, duration_from_epoch_now())?;

    // We generate a SINGLE idms only!

    let (idms, idms_delayed) = IdmServer::new(query_server.clone());

    Ok((query_server, idms, idms_delayed))
}

pub fn backup_server_core(config: &Configuration, dst_path: &str) {
    let mut audit = AuditScope::new("backend_backup", uuid::Uuid::new_v4(), config.log_level);
    let schema = match Schema::new(&mut audit) {
        Ok(s) => s,
        Err(e) => {
            audit.write_log();
            error!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    let be = match setup_backend(&config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };

    let be_ro_txn = be.read();
    let r = be_ro_txn.backup(&mut audit, dst_path);
    audit.write_log();
    match r {
        Ok(_) => info!("Backup success!"),
        Err(e) => {
            error!("Backup failed: {:?}", e);
            std::process::exit(1);
        }
    };
    // Let the txn abort, even on success.
}

pub fn restore_server_core(config: &Configuration, dst_path: &str) {
    let mut audit = AuditScope::new("backend_restore", uuid::Uuid::new_v4(), config.log_level);

    // First, we provide the in-memory schema so that core attrs are indexed correctly.
    let schema = match Schema::new(&mut audit) {
        Ok(s) => s,
        Err(e) => {
            audit.write_log();
            error!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    let be = match setup_backend(&config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };

    let be_wr_txn = be.write();
    let r = be_wr_txn
        .restore(&mut audit, dst_path)
        .and_then(|_| be_wr_txn.commit(&mut audit));

    if r.is_err() {
        audit.write_log();
        error!("Failed to restore database: {:?}", r);
        std::process::exit(1);
    }
    info!("Database loaded successfully");

    info!("Attempting to init query server ...");

    let (qs, _idms, _idms_delayed) = match setup_qs_idms(&mut audit, be, schema) {
        Ok(t) => t,
        Err(e) => {
            audit.write_log();
            error!("Unable to setup query server or idm server -> {:?}", e);
            return;
        }
    };
    info!("Success!");

    info!("Start reindex phase ...");

    let qs_write = task::block_on(qs.write_async(duration_from_epoch_now()));
    let r = qs_write
        .reindex(&mut audit)
        .and_then(|_| qs_write.commit(&mut audit));

    match r {
        Ok(_) => info!("Reindex Success!"),
        Err(e) => {
            audit.write_log();
            error!("Restore failed: {:?}", e);
            std::process::exit(1);
        }
    };

    info!("✅ Restore Success!");
}

pub fn reindex_server_core(config: &Configuration) {
    let mut audit = AuditScope::new("server_reindex", uuid::Uuid::new_v4(), config.log_level);
    eprintln!("Start Index Phase 1 ...");
    // First, we provide the in-memory schema so that core attrs are indexed correctly.
    let schema = match Schema::new(&mut audit) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    let be = match setup_backend(&config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };

    // Reindex only the core schema attributes to bootstrap the process.
    let be_wr_txn = be.write();
    let r = be_wr_txn
        .reindex(&mut audit)
        .and_then(|_| be_wr_txn.commit(&mut audit));

    // Now that's done, setup a minimal qs and reindex from that.
    if r.is_err() {
        audit.write_log();
        eprintln!("Failed to reindex database: {:?}", r);
        std::process::exit(1);
    }
    eprintln!("Index Phase 1 Success!");

    audit.write_log();
    let mut audit = AuditScope::new("server_reindex", uuid::Uuid::new_v4(), config.log_level);

    eprintln!("Attempting to init query server ...");

    let (qs, _idms, _idms_delayed) = match setup_qs_idms(&mut audit, be, schema) {
        Ok(t) => t,
        Err(e) => {
            audit.write_log();
            error!("Unable to setup query server or idm server -> {:?}", e);
            return;
        }
    };
    eprintln!("Init Query Server Success!");

    audit.write_log();
    let mut audit = AuditScope::new("server_reindex", uuid::Uuid::new_v4(), config.log_level);

    eprintln!("Start Index Phase 2 ...");

    let qs_write = task::block_on(qs.write_async(duration_from_epoch_now()));
    let r = qs_write
        .reindex(&mut audit)
        .and_then(|_| qs_write.commit(&mut audit));

    audit.write_log();

    match r {
        Ok(_) => eprintln!("Index Phase 2 Success!"),
        Err(e) => {
            eprintln!("Reindex failed: {:?}", e);
            std::process::exit(1);
        }
    };
}

pub fn domain_rename_core(config: &Configuration, new_domain_name: &str) {
    let mut audit = AuditScope::new("domain_rename", uuid::Uuid::new_v4(), config.log_level);

    let schema = match Schema::new(&mut audit) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    // Start the backend.
    let be = match setup_backend(&config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };
    // setup the qs - *with* init of the migrations and schema.
    let (qs, _idms, _idms_delayed) = match setup_qs_idms(&mut audit, be, schema) {
        Ok(t) => t,
        Err(e) => {
            audit.write_log();
            error!("Unable to setup query server or idm server -> {:?}", e);
            return;
        }
    };

    let qs_write = task::block_on(qs.write_async(duration_from_epoch_now()));
    let r = qs_write
        .domain_rename(&mut audit, new_domain_name)
        .and_then(|_| qs_write.commit(&mut audit));

    match r {
        Ok(_) => info!("Domain Rename Success!"),
        Err(e) => {
            error!("Domain Rename Failed - Rollback has occured: {:?}", e);
            std::process::exit(1);
        }
    };
}

/*
pub fn reset_sid_core(config: Configuration) {
    let mut audit = AuditScope::new("reset_sid_core", uuid::Uuid::new_v4());
    // Setup the be
    let be = match setup_backend(&config) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };
    let nsid = be.reset_db_s_uuid(&mut audit);
    audit.write_log();
    info!("New Server ID: {:?}", nsid);
}
*/

pub fn verify_server_core(config: &Configuration) {
    let mut audit = AuditScope::new("server_verify", uuid::Uuid::new_v4(), config.log_level);
    // setup the qs - without initialise!
    let schema_mem = match Schema::new(&mut audit) {
        Ok(sc) => sc,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            return;
        }
    };
    // Setup the be
    let be = match setup_backend(&config, &schema_mem) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };
    let server = QueryServer::new(be, schema_mem);

    // Run verifications.
    let r = server.verify(&mut audit);

    audit.write_log();

    if r.is_empty() {
        info!("Verification passed!");
        std::process::exit(0);
    } else {
        for er in r {
            error!("{:?}", er);
        }
        std::process::exit(1);
    }

    // Now add IDM server verifications?
}

pub fn recover_account_core(config: &Configuration, name: &str, password: &str) {
    let mut audit = AuditScope::new("recover_account", uuid::Uuid::new_v4(), config.log_level);

    let schema = match Schema::new(&mut audit) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    // Start the backend.
    let be = match setup_backend(&config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };
    // setup the qs - *with* init of the migrations and schema.
    let (_qs, idms, _idms_delayed) = match setup_qs_idms(&mut audit, be, schema) {
        Ok(t) => t,
        Err(e) => {
            audit.write_log();
            error!("Unable to setup query server or idm server -> {:?}", e);
            return;
        }
    };

    // Run the password change.
    let mut idms_prox_write = task::block_on(idms.proxy_write_async(duration_from_epoch_now()));
    match idms_prox_write.recover_account(&mut audit, &name, &password) {
        Ok(_) => match idms_prox_write.commit(&mut audit) {
            Ok(()) => {
                audit.write_log();
                info!("Password reset!");
            }
            Err(e) => {
                error!("A critical error during commit occured {:?}", e);
                audit.write_log();
                std::process::exit(1);
            }
        },
        Err(e) => {
            error!("Error during password reset -> {:?}", e);
            audit.write_log();
            // abort the txn
            std::mem::drop(idms_prox_write);
            std::process::exit(1);
        }
    };
}

pub async fn create_server_core(config: Configuration) -> Result<(), ()> {
    // Until this point, we probably want to write to the log macro fns.

    if config.integration_test_config.is_some() {
        warn!("RUNNING IN INTEGRATION TEST MODE.");
        warn!("IF YOU SEE THIS IN PRODUCTION YOU MUST CONTACT SUPPORT IMMEDIATELY.");
    }

    info!("Starting kanidm with configuration: {}", config);
    // Setup umask, so that every we touch or create is secure.
    let _ = unsafe { umask(0o0027) };

    // The log task is spawned. It will only consume a single thread at a time.
    let (log_tx, log_rx) = unbounded();
    tokio::spawn(async_log::run(log_rx));

    // Similar, create a stats task which aggregates statistics from the
    // server as they come in.
    let status_ref = StatusActor::start(log_tx.clone(), config.log_level);

    // Setup TLS (if any)
    let opt_tls_params = match setup_tls(&config) {
        Ok(opt_tls_params) => opt_tls_params,
        Err(e) => {
            error!("Failed to configure TLS parameters -> {:?}", e);
            return Err(());
        }
    };

    let mut audit = AuditScope::new("setup_qs_idms", uuid::Uuid::new_v4(), config.log_level);

    let schema = match Schema::new(&mut audit) {
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
    let (qs, idms, mut idms_delayed) = match setup_qs_idms(&mut audit, be, schema) {
        Ok(t) => t,
        Err(e) => {
            audit.write_log();
            error!("Unable to setup query server or idm server -> {:?}", e);
            return Err(());
        }
    };

    // Any pre-start tasks here.
    match &config.integration_test_config {
        Some(itc) => {
            let mut idms_prox_write =
                task::block_on(idms.proxy_write_async(duration_from_epoch_now()));
            match idms_prox_write.recover_account(&mut audit, "admin", &itc.admin_password) {
                Ok(_) => {}
                Err(e) => {
                    audit.write_log();
                    error!(
                        "Unable to configure INTERGATION TEST admin account -> {:?}",
                        e
                    );
                    return Err(());
                }
            };
            match idms_prox_write.commit(&mut audit) {
                Ok(_) => {}
                Err(e) => {
                    audit.write_log();
                    error!("Unable to commit INTERGATION TEST setup -> {:?}", e);
                    return Err(());
                }
            }
        }
        None => {}
    }

    let ldap = match LdapServer::new(&mut audit, &idms) {
        Ok(l) => l,
        Err(e) => {
            audit.write_log();
            error!("Unable to start LdapServer -> {:?}", e);
            return Err(());
        }
    };

    log_tx.send(audit).unwrap_or_else(|_| {
        error!("CRITICAL: UNABLE TO COMMIT LOGS");
    });

    // Arc the idms and ldap
    let idms_arc = Arc::new(idms);
    let ldap_arc = Arc::new(ldap);

    // Pass it to the actor for threading.
    // Start the read query server with the given be path: future config
    let server_read_ref = QueryServerReadV1::start_static(
        log_tx.clone(),
        config.log_level,
        qs.clone(),
        idms_arc.clone(),
        ldap_arc.clone(),
    );

    // Create the server async write entry point.
    let server_write_ref = QueryServerWriteV1::start_static(
        log_tx.clone(),
        config.log_level,
        qs.clone(),
        idms_arc.clone(),
    );

    // TODO #314: For now we just drop everything from the delayed queue until we rewrite to be async.
    tokio::spawn(async move {
        idms_delayed.process_all(server_write_ref).await;
    });

    // Setup timed events associated to the write thread
    IntervalActor::start(server_write_ref);

    // If we have been requested to init LDAP, configure it now.
    match &config.ldapaddress {
        Some(la) => {
            let opt_ldap_tls_params = match setup_tls(&config) {
                Ok(t) => t,
                Err(e) => {
                    error!("Failed to configure LDAP TLS parameters -> {:?}", e);
                    return Err(());
                }
            };
            ldaps::create_ldap_server(la.as_str(), opt_ldap_tls_params, server_read_ref).await?;
        }
        None => {
            debug!("LDAP not requested, skipping");
        }
    }

    // TODO: Remove these when we go to auth bearer!
    // Copy the max size
    let _secure_cookies = config.secure_cookies;
    // domain will come from the qs now!
    let cookie_key: [u8; 32] = config.cookie_key;

    self::https::create_https_server(
        config.address,
        opt_tls_params,
        &cookie_key,
        status_ref,
        server_write_ref,
        server_read_ref,
    );

    info!("ready to rock! 🧱");

    Ok(())
}
