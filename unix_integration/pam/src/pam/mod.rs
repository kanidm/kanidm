//! Interface to the pluggable authentication module framework (PAM).
//!
//! The goal of this library is to provide a type-safe API that can be used to
//! interact with PAM.  The library is incomplete - currently it supports
//! a subset of functions for use in a pam authentication module.  A pam module
//! is a shared library that is invoked to authenticate a user, or to perform
//! other functions.
//!
//! For general information on writing pam modules, see
//! [The Linux-PAM Module Writers' Guide][module-guide]
//!
//! [module-guide]: http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_MWG.html
//!
//! A typical authentication module will define an external function called
//! `pam_sm_authenticate()`, which will use functions in this library to
//! interrogate the program that requested authentication for more information,
//! and to render a result.  For a working example that uses this library, see
//! [toznyauth-pam][].
//!
//! [toznyauth-pam]: https://github.com/tozny/toznyauth-pam
//!
//! Note that constants that are normally read from pam header files are
//! hard-coded in the `constants` module.  The values there are taken from
//! a Linux system.  That means that it might take some work to get this library
//! to work on other platforms.

pub mod constants;
pub mod conv;
pub mod items;
#[doc(hidden)]
pub mod macros;
pub mod module;

use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::ffi::CStr;

use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;

use crate::core::{self, RequestOptions};
use crate::pam::constants::*;
use crate::pam::module::{PamHandle, PamHooks};
use crate::pam_hooks;
use constants::PamResultCode;
use time::OffsetDateTime;

use tracing::debug;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

pub fn get_cfg() -> Result<KanidmUnixdConfig, PamResultCode> {
    KanidmUnixdConfig::new()
        .read_options_from_optional_config(DEFAULT_CONFIG_PATH)
        .map_err(|_| PamResultCode::PAM_SERVICE_ERR)
}

fn install_subscriber(debug: bool) {
    let fmt_layer = fmt::layer().with_target(false);

    let filter_layer = if debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::ERROR
    };

    let _ = tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .try_init();
}

#[derive(Debug, Default)]
pub struct ModuleOptions {
    pub debug: bool,
    pub use_first_pass: bool,
    pub ignore_unknown_user: bool,
}

impl TryFrom<&Vec<&CStr>> for ModuleOptions {
    type Error = ();

    fn try_from(args: &Vec<&CStr>) -> Result<Self, Self::Error> {
        let opts: Result<BTreeSet<&str>, _> = args.iter().map(|cs| cs.to_str()).collect();
        let gopts = match opts {
            Ok(o) => o,
            Err(e) => {
                println!("Error in module args -> {:?}", e);
                return Err(());
            }
        };

        Ok(ModuleOptions {
            debug: gopts.contains("debug"),
            use_first_pass: gopts.contains("use_first_pass"),
            ignore_unknown_user: gopts.contains("ignore_unknown_user"),
        })
    }
}

pub struct PamKanidm;

pam_hooks!(PamKanidm);

impl PamHooks for PamKanidm {
    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match ModuleOptions::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "acct_mgmt");

        let current_time = OffsetDateTime::now_utc();

        let req_opt = RequestOptions::Main {
            config_path: DEFAULT_CONFIG_PATH,
        };

        core::sm_authenticate(pamh, &opts, req_opt, current_time)
    }

    fn acct_mgmt(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match ModuleOptions::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "acct_mgmt");

        let current_time = OffsetDateTime::now_utc();

        let req_opt = RequestOptions::Main {
            config_path: DEFAULT_CONFIG_PATH,
        };

        core::acct_mgmt(pamh, &opts, req_opt, current_time)
    }

    fn sm_open_session(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match ModuleOptions::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "sm_open_session");

        let req_opt = RequestOptions::Main {
            config_path: DEFAULT_CONFIG_PATH,
        };

        core::sm_open_session(pamh, &opts, req_opt)
    }

    fn sm_close_session(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match ModuleOptions::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "sm_close_session");

        core::sm_close_session(pamh, &opts)
    }

    fn sm_chauthtok(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match ModuleOptions::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "sm_chauthtok");

        core::sm_chauthtok(pamh, &opts)
    }

    fn sm_setcred(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match ModuleOptions::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "sm_setcred");

        core::sm_setcred(pamh, &opts)
    }
}
