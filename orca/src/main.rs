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

use async_trait::async_trait;
use std::path::PathBuf;
use structopt::StructOpt;
use std::collections::HashMap;
use uuid::Uuid;

mod name;
mod data;
mod kani;
mod preprocess;
mod profile;
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

#[async_trait]
pub trait TargetServer {
    fn info(&self) -> String;

    async fn open_admin_connection(&mut self) -> Result<(), ()>;

    async fn setup_admin_delete_uuids(&self, targets: &[Uuid]) -> Result<(), ()>;

    // async fn setup_admin_precreate_entities(&self, targets: &[data::Entity]) -> Result<(), ()>;
    async fn setup_admin_precreate_entities(&self, targets: &[Uuid], all_entities: &HashMap<Uuid, data::Entity>) -> Result<(), ()>;
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
            // read the profile that we are going to be using/testing
            // load the related data (if any) or generate it
            // run the test!
        }
    };
    info!("Success");
}
