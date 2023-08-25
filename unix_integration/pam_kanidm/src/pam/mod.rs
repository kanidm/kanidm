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

use kanidm_unix_common::client_sync::DaemonClientBlocking;
use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{
    ClientRequest, ClientResponse, PamAuthRequest, PamAuthResponse,
};

use crate::pam::constants::*;
use crate::pam::conv::PamConv;
use crate::pam::module::{PamHandle, PamHooks};
use crate::pam_hooks;
use constants::PamResultCode;

pub fn get_cfg() -> Result<KanidmUnixdConfig, PamResultCode> {
    KanidmUnixdConfig::new()
        .read_options_from_optional_config(DEFAULT_CONFIG_PATH)
        .map_err(|_| PamResultCode::PAM_SERVICE_ERR)
}

#[derive(Debug)]
struct Options {
    debug: bool,
    use_first_pass: bool,
    ignore_unknown_user: bool,
}

impl TryFrom<&Vec<&CStr>> for Options {
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

        Ok(Options {
            debug: gopts.contains("debug"),
            use_first_pass: gopts.contains("use_first_pass"),
            ignore_unknown_user: gopts.contains("ignore_unknown_user"),
        })
    }
}

pub struct PamKanidm;

pam_hooks!(PamKanidm);

impl PamHooks for PamKanidm {
    fn acct_mgmt(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        let tty = pamh.get_tty();
        let rhost = pamh.get_rhost();

        if opts.debug {
            println!("acct_mgmt");
            println!("args -> {:?}", args);
            println!("opts -> {:?}", opts);
            println!("tty -> {:?} rhost -> {:?}", tty, rhost);
        }

        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(e) => {
                if opts.debug {
                    println!("Error get_user -> {:?}", e);
                }
                return e;
            }
        };

        let cfg = match get_cfg() {
            Ok(cfg) => cfg,
            Err(e) => return e,
        };
        let req = ClientRequest::PamAccountAllowed(account_id);
        // PamResultCode::PAM_IGNORE

        let mut daemon_client =
            match DaemonClientBlocking::new(cfg.sock_path.as_str(), cfg.unix_sock_timeout) {
                Ok(dc) => dc,
                Err(e) => {
                    if opts.debug {
                        println!("Error DaemonClientBlocking::new() -> {:?}", e);
                    }
                    return PamResultCode::PAM_SERVICE_ERR;
                }
            };

        match daemon_client.call_and_wait(&req) {
            Ok(r) => match r {
                ClientResponse::PamStatus(Some(true)) => {
                    if opts.debug {
                        println!("PamResultCode::PAM_SUCCESS");
                    }
                    PamResultCode::PAM_SUCCESS
                }
                ClientResponse::PamStatus(Some(false)) => {
                    // println!("PAM_IGNORE");
                    if opts.debug {
                        println!("PamResultCode::PAM_AUTH_ERR");
                    }
                    PamResultCode::PAM_AUTH_ERR
                }
                ClientResponse::PamStatus(None) => {
                    if opts.ignore_unknown_user {
                        if opts.debug {
                            println!("PamResultCode::PAM_IGNORE");
                        }
                        PamResultCode::PAM_IGNORE
                    } else {
                        if opts.debug {
                            println!("PamResultCode::PAM_USER_UNKNOWN");
                        }
                        PamResultCode::PAM_USER_UNKNOWN
                    }
                }
                _ => {
                    // unexpected response.
                    if opts.debug {
                        println!("PamResultCode::PAM_IGNORE -> {:?}", r);
                    }
                    PamResultCode::PAM_IGNORE
                }
            },
            Err(e) => {
                if opts.debug {
                    println!("PamResultCode::PAM_IGNORE  -> {:?}", e);
                }
                PamResultCode::PAM_IGNORE
            }
        }
    }

    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        // This will == "Ok(Some("ssh"))" on remote auth.
        let tty = pamh.get_tty();
        let rhost = pamh.get_rhost();

        if opts.debug {
            println!("sm_authenticate");
            println!("args -> {:?}", args);
            println!("opts -> {:?}", opts);
            println!("tty -> {:?} rhost -> {:?}", tty, rhost);
        }

        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(e) => {
                println!("Error get_user -> {:?}", e);
                return e;
            }
        };

        let cfg = match get_cfg() {
            Ok(cfg) => cfg,
            Err(e) => return e,
        };

        let mut daemon_client =
            match DaemonClientBlocking::new(cfg.sock_path.as_str(), cfg.unix_sock_timeout) {
                Ok(dc) => dc,
                Err(e) => {
                    if opts.debug {
                        println!("Error DaemonClientBlocking::new() -> {:?}", e);
                    }
                    return PamResultCode::PAM_SERVICE_ERR;
                }
            };

        // Later we may need to move this to a function and call it as a oneshot for auth methods
        // that don't require any authtoks at all. For example, imagine a user authed and they
        // needed to follow a URL to continue. In that case, they would fail here because they
        // didn't enter an authtok that they didn't need!
        let mut authtok = match pamh.get_authtok() {
            Ok(Some(v)) => Some(v),
            Ok(None) => {
                if opts.use_first_pass {
                    if opts.debug {
                        println!("Don't have an authtok, returning PAM_AUTH_ERR");
                    }
                    return PamResultCode::PAM_AUTH_ERR;
                }
                None
            }
            Err(e) => {
                if opts.debug {
                    println!("Error get_authtok -> {:?}", e);
                }
                return e;
            }
        };

        let conv = match pamh.get_item::<PamConv>() {
            Ok(conv) => conv,
            Err(err) => {
                if opts.debug {
                    println!("Couldn't get pam_conv");
                }
                return err;
            }
        };

        let mut req = ClientRequest::PamAuthenticateInit(account_id);

        loop {
            match daemon_client.call_and_wait(&req) {
                Ok(r) => match r {
                    ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Success) => {
                        return PamResultCode::PAM_SUCCESS;
                    }
                    ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Denied) => {
                        return PamResultCode::PAM_AUTH_ERR;
                    }
                    ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Unknown) => {
                        if opts.ignore_unknown_user {
                            return PamResultCode::PAM_IGNORE;
                        } else {
                            return PamResultCode::PAM_USER_UNKNOWN;
                        }
                    }
                    ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Password) => {
                        let mut consume_authtok = None;
                        // Swap the authtok out with a None, so it can only be consumed once.
                        // If it's already been swapped, we are just swapping two null pointers
                        // here effectively.
                        std::mem::swap(&mut authtok, &mut consume_authtok);
                        let cred = if let Some(cred) = consume_authtok {
                            cred
                        } else {
                            match conv.send(PAM_PROMPT_ECHO_OFF, "Password: ") {
                                Ok(password) => match password {
                                    Some(cred) => cred,
                                    None => {
                                        if opts.debug {
                                            println!("No password");
                                        }
                                        return PamResultCode::PAM_CRED_INSUFFICIENT;
                                    }
                                },
                                Err(err) => {
                                    if opts.debug {
                                        println!("Couldn't get password");
                                    }
                                    return err;
                                }
                            }
                        };

                        // Now setup the request for the next loop.
                        req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Password { cred });
                        continue;
                    }
                    _ => {
                        // unexpected response.
                        if opts.debug {
                            println!("PAM_IGNORE -> {:?}", r);
                        }
                        return PamResultCode::PAM_IGNORE;
                    }
                },
                Err(e) => {
                    if opts.debug {
                        println!("PAM_IGNORE -> {:?}", e);
                    }
                    return PamResultCode::PAM_IGNORE;
                }
            }
        } // while true, continue calling PamAuthenticateStep until we get a decision.
    }

    fn sm_chauthtok(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        if opts.debug {
            println!("sm_chauthtok");
            println!("args -> {:?}", args);
            println!("opts -> {:?}", opts);
        }
        PamResultCode::PAM_IGNORE
    }

    fn sm_close_session(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        if opts.debug {
            println!("sm_close_session");
            println!("args -> {:?}", args);
            println!("opts -> {:?}", opts);
        }
        PamResultCode::PAM_SUCCESS
    }

    fn sm_open_session(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        if opts.debug {
            println!("sm_open_session");
            println!("args -> {:?}", args);
            println!("opts -> {:?}", opts);
        }

        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(e) => {
                if opts.debug {
                    println!("Error get_user -> {:?}", e);
                }
                return e;
            }
        };

        let cfg = match get_cfg() {
            Ok(cfg) => cfg,
            Err(e) => return e,
        };
        let req = ClientRequest::PamAccountBeginSession(account_id);

        let mut daemon_client =
            match DaemonClientBlocking::new(cfg.sock_path.as_str(), cfg.unix_sock_timeout) {
                Ok(dc) => dc,
                Err(e) => {
                    if opts.debug {
                        println!("Error DaemonClientBlocking::new() -> {:?}", e);
                    }
                    return PamResultCode::PAM_SERVICE_ERR;
                }
            };

        match daemon_client.call_and_wait(&req) {
            Ok(ClientResponse::Ok) => {
                // println!("PAM_SUCCESS");
                PamResultCode::PAM_SUCCESS
            }
            other => {
                if opts.debug {
                    println!("PAM_IGNORE  -> {:?}", other);
                }
                PamResultCode::PAM_IGNORE
            }
        }
    }

    fn sm_setcred(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        if opts.debug {
            println!("sm_setcred");
            println!("args -> {:?}", args);
            println!("opts -> {:?}", opts);
        }
        PamResultCode::PAM_SUCCESS
    }
}
