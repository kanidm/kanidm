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

use tracing::{debug, error};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use std::thread;
use std::time::Duration;

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

macro_rules! match_sm_auth_client_response {
    ($expr:expr, $opts:ident, $($pat:pat => $result:expr),*) => {
        match $expr {
            Ok(r) => match r {
                $($pat => $result),*
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Success) => {
                    return PamResultCode::PAM_SUCCESS;
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Denied) => {
                    return PamResultCode::PAM_AUTH_ERR;
                }
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Unknown) => {
                    if $opts.ignore_unknown_user {
                        return PamResultCode::PAM_IGNORE;
                    } else {
                        return PamResultCode::PAM_USER_UNKNOWN;
                    }
                }
                _ => {
                    // unexpected response.
                    error!(err = ?r, "PAM_IGNORE, unexpected resolver response");
                    return PamResultCode::PAM_IGNORE;
                }
            },
            Err(err) => {
                error!(?err, "PAM_IGNORE");
                return PamResultCode::PAM_IGNORE;
            }
        }
    }
}

impl PamHooks for PamKanidm {
    fn acct_mgmt(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        let tty = pamh.get_tty();
        let rhost = pamh.get_rhost();

        debug!(?args, ?opts, ?tty, ?rhost, "acct_mgmt");

        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(e) => {
                error!(err = ?e, "get_user");
                return e;
            }
        };

        let cfg = match get_cfg() {
            Ok(cfg) => cfg,
            Err(e) => return e,
        };
        let req = ClientRequest::PamAccountAllowed(account_id);
        // PamResultCode::PAM_IGNORE

        let mut daemon_client = match DaemonClientBlocking::new(cfg.sock_path.as_str()) {
            Ok(dc) => dc,
            Err(e) => {
                error!(err = ?e, "Error DaemonClientBlocking::new()");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        match daemon_client.call_and_wait(&req, cfg.unix_sock_timeout) {
            Ok(r) => match r {
                ClientResponse::PamStatus(Some(true)) => {
                    debug!("PamResultCode::PAM_SUCCESS");
                    PamResultCode::PAM_SUCCESS
                }
                ClientResponse::PamStatus(Some(false)) => {
                    debug!("PamResultCode::PAM_AUTH_ERR");
                    PamResultCode::PAM_AUTH_ERR
                }
                ClientResponse::PamStatus(None) => {
                    if opts.ignore_unknown_user {
                        debug!("PamResultCode::PAM_IGNORE");
                        PamResultCode::PAM_IGNORE
                    } else {
                        debug!("PamResultCode::PAM_USER_UNKNOWN");
                        PamResultCode::PAM_USER_UNKNOWN
                    }
                }
                _ => {
                    // unexpected response.
                    error!(err = ?r, "PAM_IGNORE, unexpected resolver response");
                    PamResultCode::PAM_IGNORE
                }
            },
            Err(e) => {
                error!(err = ?e, "PamResultCode::PAM_IGNORE");
                PamResultCode::PAM_IGNORE
            }
        }
    }

    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        // This will == "Ok(Some("ssh"))" on remote auth.
        let tty = pamh.get_tty();
        let rhost = pamh.get_rhost();

        debug!(?args, ?opts, ?tty, ?rhost, "sm_authenticate");

        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(e) => {
                error!(err = ?e, "get_user");
                return e;
            }
        };

        let cfg = match get_cfg() {
            Ok(cfg) => cfg,
            Err(e) => return e,
        };

        let mut timeout = cfg.unix_sock_timeout;
        let mut daemon_client = match DaemonClientBlocking::new(cfg.sock_path.as_str()) {
            Ok(dc) => dc,
            Err(e) => {
                error!(err = ?e, "Error DaemonClientBlocking::new()");
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
                    debug!("Don't have an authtok, returning PAM_AUTH_ERR");
                    return PamResultCode::PAM_AUTH_ERR;
                }
                None
            }
            Err(e) => {
                error!(err = ?e, "get_authtok");
                return e;
            }
        };

        let conv = match pamh.get_item::<PamConv>() {
            Ok(conv) => conv,
            Err(err) => {
                error!(?err, "pam_conv");
                return err;
            }
        };

        let mut req = ClientRequest::PamAuthenticateInit(account_id);

        loop {
            match_sm_auth_client_response!(daemon_client.call_and_wait(&req, timeout), opts,
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
                                    debug!("no password");
                                    return PamResultCode::PAM_CRED_INSUFFICIENT;
                                }
                            },
                            Err(err) => {
                                debug!("unable to get password");
                                return err;
                            }
                        }
                    };

                    // Now setup the request for the next loop.
                    timeout = cfg.unix_sock_timeout;
                    req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Password { cred });
                    continue;
                },
                ClientResponse::PamAuthenticateStepResponse(
                    PamAuthResponse::DeviceAuthorizationGrant { data },
                ) => {
                    let msg = match &data.message {
                        Some(msg) => msg.clone(),
                        None => format!("Using a browser on another device, visit:\n{}\nAnd enter the code:\n{}",
                                        data.verification_uri, data.user_code)
                    };
                    match conv.send(PAM_TEXT_INFO, &msg) {
                        Ok(_) => {}
                        Err(err) => {
                            if opts.debug {
                                println!("Message prompt failed");
                            }
                            return err;
                        }
                    }

                    timeout = u64::from(data.expires_in);
                    req = ClientRequest::PamAuthenticateStep(
                        PamAuthRequest::DeviceAuthorizationGrant { data },
                    );
                    continue;
                },
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::MFACode {
                    msg,
                }) => {
                    match conv.send(PAM_TEXT_INFO, &msg) {
                        Ok(_) => {}
                        Err(err) => {
                            if opts.debug {
                                println!("Message prompt failed");
                            }
                            return err;
                        }
                    }
                    let cred = match conv.send(PAM_PROMPT_ECHO_OFF, "Code: ") {
                        Ok(password) => match password {
                            Some(cred) => cred,
                            None => {
                                debug!("no mfa code");
                                return PamResultCode::PAM_CRED_INSUFFICIENT;
                            }
                        },
                        Err(err) => {
                            debug!("unable to get mfa code");
                            return err;
                        }
                    };

                    // Now setup the request for the next loop.
                    timeout = cfg.unix_sock_timeout;
                    req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFACode {
                        cred,
                    });
                    continue;
                },
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::MFAPoll {
                    msg,
                    polling_interval,
                }) => {
                    match conv.send(PAM_TEXT_INFO, &msg) {
                        Ok(_) => {}
                        Err(err) => {
                            if opts.debug {
                                println!("Message prompt failed");
                            }
                            return err;
                        }
                    }

                    loop {
                        thread::sleep(Duration::from_secs(polling_interval.into()));
                        timeout = cfg.unix_sock_timeout;
                        req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFAPoll);

                        // Counter intuitive, but we don't need a max poll attempts here because
                        // if the resolver goes away, then this will error on the sock and
                        // will shutdown. This allows the resolver to dynamically extend the
                        // timeout if needed, and removes logic from the front end.
                        match_sm_auth_client_response!(
                            daemon_client.call_and_wait(&req, timeout), opts,
                            ClientResponse::PamAuthenticateStepResponse(
                                    PamAuthResponse::MFAPollWait,
                            ) => {
                                // Continue polling if the daemon says to wait
                                continue;
                            }
                        );

                    }
                },
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::SetupPin {
                    msg,
                }) => {
                    match conv.send(PAM_TEXT_INFO, &msg) {
                        Ok(_) => {}
                        Err(err) => {
                            if opts.debug {
                                println!("Message prompt failed");
                            }
                            return err;
                        }
                    }

                    let mut pin;
                    let mut confirm;
                    loop {
                        pin = match conv.send(PAM_PROMPT_ECHO_OFF, "New PIN: ") {
                            Ok(password) => match password {
                                Some(cred) => cred,
                                None => {
                                    debug!("no pin");
                                    return PamResultCode::PAM_CRED_INSUFFICIENT;
                                }
                            },
                            Err(err) => {
                                debug!("unable to get pin");
                                return err;
                            }
                        };

                        confirm = match conv.send(PAM_PROMPT_ECHO_OFF, "Confirm PIN: ") {
                            Ok(password) => match password {
                                Some(cred) => cred,
                                None => {
                                    debug!("no confirmation pin");
                                    return PamResultCode::PAM_CRED_INSUFFICIENT;
                                }
                            },
                            Err(err) => {
                                debug!("unable to get confirmation pin");
                                return err;
                            }
                        };

                        if pin == confirm {
                            break;
                        } else {
                            match conv.send(PAM_TEXT_INFO, "Inputs did not match. Try again.") {
                                Ok(_) => {}
                                Err(err) => {
                                    if opts.debug {
                                        println!("Message prompt failed");
                                    }
                                    return err;
                                }
                            }
                        }
                    }

                    // Now setup the request for the next loop.
                    timeout = cfg.unix_sock_timeout;
                    req = ClientRequest::PamAuthenticateStep(PamAuthRequest::SetupPin {
                        pin,
                    });
                    continue;
                },
                ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Pin) => {
                    let mut consume_authtok = None;
                    // Swap the authtok out with a None, so it can only be consumed once.
                    // If it's already been swapped, we are just swapping two null pointers
                    // here effectively.
                    std::mem::swap(&mut authtok, &mut consume_authtok);
                    let cred = if let Some(cred) = consume_authtok {
                        cred
                    } else {
                        match conv.send(PAM_PROMPT_ECHO_OFF, "PIN: ") {
                            Ok(password) => match password {
                                Some(cred) => cred,
                                None => {
                                    debug!("no pin");
                                    return PamResultCode::PAM_CRED_INSUFFICIENT;
                                }
                            },
                            Err(err) => {
                                debug!("unable to get pin");
                                return err;
                            }
                        }
                    };

                    // Now setup the request for the next loop.
                    timeout = cfg.unix_sock_timeout;
                    req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Pin { cred });
                    continue;
                }
            );
        } // while true, continue calling PamAuthenticateStep until we get a decision.
    }

    fn sm_chauthtok(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "sm_chauthtok");

        PamResultCode::PAM_IGNORE
    }

    fn sm_close_session(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "sm_close_session");

        PamResultCode::PAM_SUCCESS
    }

    fn sm_open_session(pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "sm_open_session");

        let account_id = match pamh.get_user(None) {
            Ok(aid) => aid,
            Err(err) => {
                error!(?err, "get_user");
                return err;
            }
        };

        let cfg = match get_cfg() {
            Ok(cfg) => cfg,
            Err(e) => return e,
        };
        let req = ClientRequest::PamAccountBeginSession(account_id);

        let mut daemon_client = match DaemonClientBlocking::new(cfg.sock_path.as_str()) {
            Ok(dc) => dc,
            Err(e) => {
                error!(err = ?e, "Error DaemonClientBlocking::new()");
                return PamResultCode::PAM_SERVICE_ERR;
            }
        };

        match daemon_client.call_and_wait(&req, cfg.unix_sock_timeout) {
            Ok(ClientResponse::Ok) => {
                // println!("PAM_SUCCESS");
                PamResultCode::PAM_SUCCESS
            }
            other => {
                debug!(err = ?other, "PAM_IGNORE");
                PamResultCode::PAM_IGNORE
            }
        }
    }

    fn sm_setcred(_pamh: &PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let opts = match Options::try_from(&args) {
            Ok(o) => o,
            Err(_) => return PamResultCode::PAM_SERVICE_ERR,
        };

        install_subscriber(opts.debug);

        debug!(?args, ?opts, "sm_setcred");

        PamResultCode::PAM_SUCCESS
    }
}
