// #![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[cfg(all(jemallocator, not(test)))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;

use crate::kani::KaniHttpServer;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use structopt::StructOpt;
use uuid::Uuid;

mod data;
mod kani;
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
}

impl TargetServerBuilder {
    pub fn build(self) -> Result<TargetServer, ()> {
        match self {
            TargetServerBuilder::Kanidm(a, b) => KaniHttpServer::build(a, b),
        }
    }
}

pub enum TargetServer {
    Kanidm(KaniHttpServer),
}

impl TargetServer {
    fn info(&self) -> String {
        match self {
            TargetServer::Kanidm(k) => k.info(),
        }
    }

    fn rname(&self) -> &str {
        match self {
            TargetServer::Kanidm(k) => "kanidm_http",
        }
    }

    fn builder(&self) -> TargetServerBuilder {
        match self {
            TargetServer::Kanidm(k) => k.builder(),
        }
    }

    async fn open_user_connection(&self, name: &str, pw: &str) -> Result<(), ()> {
        match self {
            TargetServer::Kanidm(k) => k.open_user_connection(name, pw).await,
        }
    }

    async fn open_admin_connection(&self) -> Result<(), ()> {
        match self {
            TargetServer::Kanidm(k) => k.open_admin_connection().await,
        }
    }

    async fn setup_admin_delete_uuids(&self, targets: &[Uuid]) -> Result<(), ()> {
        match self {
            TargetServer::Kanidm(k) => k.setup_admin_delete_uuids(targets).await,
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
        }
    }

    async fn setup_access_controls(
        &self,
        access: &HashMap<Uuid, Vec<data::EntityType>>,
        all_entities: &HashMap<Uuid, data::Entity>,
    ) -> Result<(), ()> {
        match self {
            TargetServer::Kanidm(k) => k.setup_access_controls(access, all_entities).await,
        }
    }

    async fn search(
        &self,
        test_start: Instant,
        ids: &[String],
    ) -> Result<(Duration, Duration, usize), ()> {
        match self {
            TargetServer::Kanidm(k) => k.search(test_start, ids).await,
        }
    }
}

#[tokio::main]
async fn main() {
    let opt = OrcaOpt::from_args();

    if opt.debug() {
        ::std::env::set_var(
            "RUST_LOG",
            "orca=debug,kanidm=debug,kanidm_client=debug,webauthn=debug",
        );
    } else {
        ::std::env::set_var(
            "RUST_LOG",
            "orca=info,kanidm=info,kanidm_client=info,webauthn=info",
        );
    }
    env_logger::init();

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
