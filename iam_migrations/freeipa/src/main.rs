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

use crate::config::Config;
use clap::Parser;
use std::fs::metadata;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread;
use tokio::runtime;
use tracing::{debug, error, info, warn};
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use kanidm_client::KanidmClientBuilder;
use kanidm_proto::scim_v1::{ScimSyncRequest, ScimSyncState};
use kanidmd_lib::utils::file_permissions_readonly;

use users::{get_current_gid, get_current_uid, get_effective_gid, get_effective_uid};

use ldap3_client::{proto, LdapClientBuilder, LdapSyncRepl};

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

    let cookie = match scim_sync_status {
        ScimSyncState::Initial => None,
        ScimSyncState::Active { cookie } => Some(cookie.0),
    };

    debug!(ipa_sync_base_dn = ?sync_config.ipa_sync_base_dn, ?cookie, ?mode);
    let sync_result = match ipa_client
        .syncrepl(sync_config.ipa_sync_base_dn, cookie, mode)
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
    let scim_sync_request = match process_ipa_sync_result(sync_result).await {
        Ok(ssr) => ssr,
        Err(()) => return,
    };

    if opt.proto_dump {
        let stdout = std::io::stdout();
        // write it out.
        if let Err(e) = serde_json::to_writer_pretty(stdout, &scim_sync_request) {
            error!(?e, "Failed to serialise scim sync request");
        };
    } else {
        todo!();
    }
    // done!
}

async fn process_ipa_sync_result(_sync_result: LdapSyncRepl) -> Result<ScimSyncRequest, ()> {
    Err(())
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

    info!("Success!");
}
