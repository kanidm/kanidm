#![deny(warnings)]
#![warn(unused_extern_crates)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[cfg(not(target_family = "windows"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[macro_use]
extern crate tracing;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use uuid::Uuid;

use crate::ds::DirectoryServer;
use crate::kani::{KaniHttpServer, KaniLdapServer};

mod data;
mod ds;
mod kani;
mod ldap;
mod preprocess;
mod profile;
mod runner;
mod setup;

include!("./opt.rs");

impl OrcaOpt {
    pub fn debug(&self) -> bool {
        match self {
            OrcaOpt::PreProc(opt) => opt.copt.debug,
            OrcaOpt::Setup(opt) => opt.copt.debug,
            OrcaOpt::Run(opt) => opt.copt.debug,
        }
    }
}

pub enum TargetServerBuilder {
    Kanidm(String, String),
    KanidmLdap(String, String, String, String),
    DirSrv(String, String, String),
}

impl TargetServerBuilder {
    #[allow(clippy::result_unit_err)]
    pub fn build(self) -> Result<TargetServer, ()> {
        match self {
            TargetServerBuilder::Kanidm(a, b) => KaniHttpServer::build(a, b),
            TargetServerBuilder::KanidmLdap(a, b, c, d) => KaniLdapServer::build(a, b, c, d),
            TargetServerBuilder::DirSrv(a, b, c) => DirectoryServer::build(a, b, c),
        }
    }
}

pub enum TargetServer {
    Kanidm(KaniHttpServer),
    KanidmLdap(Box<KaniLdapServer>),
    DirSrv(DirectoryServer),
}

impl TargetServer {
    fn info(&self) -> String {
        match self {
            TargetServer::Kanidm(k) => k.info(),
            TargetServer::KanidmLdap(k) => k.info(),
            TargetServer::DirSrv(k) => k.info(),
        }
    }

    fn rname(&self) -> &str {
        match self {
            TargetServer::Kanidm(_) => "kanidm_http",
            TargetServer::KanidmLdap(_) => "kanidm_ldap",
            TargetServer::DirSrv(_) => "directory_server",
        }
    }

    fn builder(&self) -> TargetServerBuilder {
        match self {
            TargetServer::Kanidm(k) => k.builder(),
            TargetServer::KanidmLdap(k) => k.builder(),
            TargetServer::DirSrv(k) => k.builder(),
        }
    }

    async fn open_admin_connection(&self) -> Result<(), ()> {
        match self {
            TargetServer::Kanidm(k) => k.open_admin_connection().await,
            TargetServer::KanidmLdap(k) => k.open_admin_connection().await,
            TargetServer::DirSrv(k) => k.open_admin_connection().await,
        }
    }

    async fn setup_admin_delete_uuids(&self, targets: &[Uuid]) -> Result<(), ()> {
        match self {
            TargetServer::Kanidm(k) => k.setup_admin_delete_uuids(targets).await,
            TargetServer::KanidmLdap(k) => k.setup_admin_delete_uuids(targets).await,
            TargetServer::DirSrv(k) => k.setup_admin_delete_uuids(targets).await,
        }
    }

    async fn setup_admin_precreate_entities(
        &self,
        targets: &HashSet<Uuid>,
        all_entities: &HashMap<Uuid, data::Entity>,
    ) -> Result<(), ()> {
        match self {
            TargetServer::Kanidm(k) => {
                k.setup_admin_precreate_entities(targets, all_entities)
                    .await
            }
            TargetServer::KanidmLdap(k) => {
                k.setup_admin_precreate_entities(targets, all_entities)
                    .await
            }
            TargetServer::DirSrv(k) => {
                k.setup_admin_precreate_entities(targets, all_entities)
                    .await
            }
        }
    }

    async fn setup_access_controls(
        &self,
        access: &HashMap<Uuid, Vec<data::EntityType>>,
        all_entities: &HashMap<Uuid, data::Entity>,
    ) -> Result<(), ()> {
        match self {
            TargetServer::Kanidm(k) => k.setup_access_controls(access, all_entities).await,
            TargetServer::KanidmLdap(k) => k.setup_access_controls(access, all_entities).await,
            TargetServer::DirSrv(k) => k.setup_access_controls(access, all_entities).await,
        }
    }

    async fn open_user_connection(
        &self,
        test_start: Instant,
        name: &str,
        pw: &str,
    ) -> Result<(Duration, Duration), ()> {
        match self {
            TargetServer::Kanidm(k) => k.open_user_connection(test_start, name, pw).await,
            TargetServer::KanidmLdap(k) => k.open_user_connection(test_start, name, pw).await,
            TargetServer::DirSrv(k) => k.open_user_connection(test_start, name, pw).await,
        }
    }

    async fn close_connection(&self) {
        match self {
            TargetServer::Kanidm(k) => k.close_connection().await,
            TargetServer::KanidmLdap(k) => k.close_connection().await,
            TargetServer::DirSrv(k) => k.close_connection().await,
        }
    }

    async fn search(
        &self,
        test_start: Instant,
        ids: &[String],
    ) -> Result<(Duration, Duration, usize), ()> {
        match self {
            TargetServer::Kanidm(k) => k.search(test_start, ids).await,
            TargetServer::KanidmLdap(k) => k.search(test_start, ids).await,
            TargetServer::DirSrv(k) => k.search(test_start, ids).await,
        }
    }
}

#[tokio::main]
async fn main() {
    let opt = OrcaOpt::parse();

    if opt.debug() {
        ::std::env::set_var(
            "RUST_LOG",
            "orca=debug,kanidm=debug,kanidm_client=debug,webauthn=debug",
        );
    }
    tracing_subscriber::fmt::init();

    info!("Orca - the Kanidm Load Testing Utility.");
    debug!("cli -> {:?}", opt);
    match opt {
        OrcaOpt::PreProc(opt) => preprocess::doit(&opt.input_path, &opt.output_path),
        OrcaOpt::Setup(opt) => {
            let _ = setup::doit(&opt.target, &opt.profile_path).await;
        }
        OrcaOpt::Run(opt) => {
            let _ = runner::doit(&opt.test_type, &opt.target, &opt.profile_path).await;
            // read the profile that we are going to be using/testing
            // load the related data (if any) or generate it
            // run the test!
        }
    };
    info!("Success");
}
