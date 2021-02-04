#![deny(warnings)]
#![warn(unused_extern_crates)]
// In this file, we do want to panic on these faults.
// #![deny(clippy::unwrap_used)]
// #![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

// extern crate libc;

mod pam;
use crate::pam::constants::*;
use crate::pam::conv::PamConv;
use crate::pam::module::{PamHandle, PamHooks};

use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::ffi::CStr;
// use std::os::raw::c_char;
use kanidm_unix_common::client::call_daemon_blocking;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};

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

fn get_cfg() -> Result<KanidmUnixdConfig, PamResultCode> {
    KanidmUnixdConfig::new()
        .read_options_from_optional_config("/etc/kanidm/unixd")
        .map_err(|_| PamResultCode::PAM_SERVICE_ERR)
}

struct PamKanidm;
pam_hooks!(PamKanidm);

impl PamHooks for PamKanidm {
    fn acct_mgmt(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        if opts.debug {
            println!("acct_mgmt");
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
        let req = ClientRequest::PamAccountAllowed(account_id);
        // PamResultCode::PAM_IGNORE

        match call_daemon_blocking(cfg.sock_path.as_str(), req) {
            Ok(r) => match r {
                ClientResponse::PamStatus(Some(true)) => {
                    // println!("PAM_SUCCESS");
                    PamResultCode::PAM_SUCCESS
                }
                ClientResponse::PamStatus(Some(false)) => {
                    // println!("PAM_IGNORE");
                    PamResultCode::PAM_AUTH_ERR
                }
                ClientResponse::PamStatus(None) => {
                    if opts.ignore_unknown_user {
                        PamResultCode::PAM_IGNORE
                    } else {
                        PamResultCode::PAM_USER_UNKNOWN
                    }
                }
                _ => {
                    // unexpected response.
                    if opts.debug {
                        println!("PAM_IGNORE -> {:?}", r);
                    }
                    PamResultCode::PAM_IGNORE
                }
            },
            Err(e) => {
                if opts.debug {
                    println!("PAM_IGNORE  -> {:?}", e);
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

        if opts.debug {
            println!("sm_authenticate");
            println!("args -> {:?}", args);
            println!("opts -> {:?}", opts);
        }

        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(e) => {
                println!("Error get_user -> {:?}", e);
                return e;
            }
        };

        let authtok = match pamh.get_authtok() {
            Ok(atok) => atok,
            Err(e) => {
                if opts.debug {
                    println!("Error get_authtok -> {:?}", e);
                }
                return e;
            }
        };

        let authtok = match authtok {
            Some(v) => v,
            None => {
                if opts.use_first_pass {
                    if opts.debug {
                        println!("Don't have an authtok, returning PAM_AUTH_ERR");
                    }
                    return PamResultCode::PAM_AUTH_ERR;
                } else {
                    let conv = match pamh.get_item::<PamConv>() {
                        Ok(conv) => conv,
                        Err(err) => {
                            if opts.debug {
                                println!("Couldn't get pam_conv");
                            }
                            return err;
                        }
                    };
                    match conv.send(PAM_PROMPT_ECHO_OFF, "Password: ") {
                        Ok(password) => match password {
                            Some(pw) => pw,
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
                } // end opts.use_first_pass
            }
        };

        let cfg = match get_cfg() {
            Ok(cfg) => cfg,
            Err(e) => return e,
        };
        let req = ClientRequest::PamAuthenticate(account_id, authtok);

        match call_daemon_blocking(cfg.sock_path.as_str(), req) {
            Ok(r) => match r {
                ClientResponse::PamStatus(Some(true)) => {
                    // println!("PAM_SUCCESS");
                    PamResultCode::PAM_SUCCESS
                }
                ClientResponse::PamStatus(Some(false)) => {
                    // println!("PAM_AUTH_ERR");
                    PamResultCode::PAM_AUTH_ERR
                }
                ClientResponse::PamStatus(None) => {
                    // println!("PAM_USER_UNKNOWN");
                    if opts.ignore_unknown_user {
                        PamResultCode::PAM_IGNORE
                    } else {
                        PamResultCode::PAM_USER_UNKNOWN
                    }
                }
                _ => {
                    // unexpected response.
                    if opts.debug {
                        println!("PAM_IGNORE -> {:?}", r);
                    }
                    PamResultCode::PAM_IGNORE
                }
            },
            Err(e) => {
                if opts.debug {
                    println!("PAM_IGNORE -> {:?}", e);
                }
                PamResultCode::PAM_IGNORE
            }
        }
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

        match call_daemon_blocking(cfg.sock_path.as_str(), req) {
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
