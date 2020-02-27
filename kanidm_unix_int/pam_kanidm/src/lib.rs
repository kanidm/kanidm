extern crate libc;

mod pam;
use crate::pam::constants::*;
use crate::pam::conv::PamConv;
use crate::pam::module::{PamHandle, PamHooks};

use std::ffi::CStr;
use std::os::raw::c_char;

// use futures::executor::block_on;
use tokio::runtime::Runtime;

use kanidm_unix_common::client::call_daemon;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};

fn get_cfg() -> Result<KanidmUnixdConfig, PamResultCode> {
    KanidmUnixdConfig::new()
        .read_options_from_optional_config("/etc/kanidm/unixd")
        .map_err(|_| PamResultCode::PAM_SERVICE_ERR)
}

struct PamKanidm;
pam_hooks!(PamKanidm);

impl PamHooks for PamKanidm {
    fn acct_mgmt(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        // println!("acct_mgmt");
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
        let req = ClientRequest::PamAccountAllowed(account_id);
        // PamResultCode::PAM_IGNORE

        let mut rt = match Runtime::new() {
            Ok(rt) => rt,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        match rt.block_on(call_daemon(cfg.sock_path.as_str(), req)) {
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
                    // println!("PAM_USER_UNKNOWN");
                    PamResultCode::PAM_USER_UNKNOWN
                }
                _ => {
                    // unexpected response.
                    println!("PAM_IGNORE -> {:?}", r);
                    PamResultCode::PAM_IGNORE
                }
            },
            Err(e) => {
                println!("PAM_IGNORE  -> {:?}", e);
                PamResultCode::PAM_IGNORE
            }
        }
    }

    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        // println!("sm_authenticate");
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
                println!("Error get_authtok -> {:?}", e);
                return e;
            }
        };

        let authtok = match authtok {
            Some(v) => v,
            None => {
                let conv = match pamh.get_item::<PamConv>() {
                    Ok(conv) => conv,
                    Err(err) => {
                        println!("Couldn't get pam_conv");
                        return err;
                    }
                };
                match conv.send(PAM_PROMPT_ECHO_OFF, "Password: ") {
                    Ok(password) => match password {
                        Some(pw) => pw,
                        None => {
                            println!("No password");
                            return PamResultCode::PAM_CRED_INSUFFICIENT;
                        }
                    },
                    Err(err) => {
                        println!("Couldn't get password");
                        return err;
                    }
                }
            }
        };

        let cfg = match get_cfg() {
            Ok(cfg) => cfg,
            Err(e) => return e,
        };
        let req = ClientRequest::PamAuthenticate(account_id, authtok);

        let mut rt = match Runtime::new() {
            Ok(rt) => rt,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        match rt.block_on(call_daemon(cfg.sock_path.as_str(), req)) {
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
                    PamResultCode::PAM_USER_UNKNOWN
                }
                _ => {
                    // unexpected response.
                    println!("PAM_IGNORE -> {:?}", r);
                    PamResultCode::PAM_IGNORE
                }
            },
            Err(e) => {
                println!("PAM_IGNORE -> {:?}", e);
                PamResultCode::PAM_IGNORE
            }
        }
    }

    fn sm_chauthtok(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        // println!("sm_chauthtok");
        PamResultCode::PAM_IGNORE
    }

    fn sm_close_session(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        // println!("sm_close_session");
        PamResultCode::PAM_SUCCESS
    }

    fn sm_open_session(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        // println!("sm_open_session");
        PamResultCode::PAM_SUCCESS
    }

    fn sm_setcred(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        // println!("sm_setcred");
        PamResultCode::PAM_SUCCESS
    }
}
