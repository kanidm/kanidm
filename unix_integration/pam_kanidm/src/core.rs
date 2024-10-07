use crate::constants::PamResultCode;
use crate::module::PamResult;
use crate::pam::module::PamHandle;
use crate::pam::ModuleOptions;
use kanidm_unix_common::client_sync::DaemonClientBlocking;
use kanidm_unix_common::client_sync::UnixStream;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_passwd::{
    read_etc_passwd_file, read_etc_shadow_file, EtcShadow, EtcUser,
};
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};
use kanidm_unix_common::unix_proto::{
    DeviceAuthorizationResponse, PamAuthRequest, PamAuthResponse, PamServiceInfo,
};
use std::time::Duration;
use time::OffsetDateTime;

use tracing::{debug, error};

pub enum RequestOptions {
    Main {
        config_path: &'static str,
    },
    #[cfg(test)]
    Test {
        socket: Option<UnixStream>,
        users: Vec<EtcUser>,
        // groups: Vec<EtcGroup>,
        shadow: Vec<EtcShadow>,
    },
}

enum Source {
    Daemon(DaemonClientBlocking),
    Fallback {
        users: Vec<EtcUser>,
        // groups: Vec<EtcGroup>,
        shadow: Vec<EtcShadow>,
    },
}

impl RequestOptions {
    fn connect_to_daemon(self) -> Source {
        match self {
            RequestOptions::Main { config_path } => {
                let maybe_client = KanidmUnixdConfig::new()
                    .read_options_from_optional_config(config_path)
                    .ok()
                    .and_then(|cfg| {
                        DaemonClientBlocking::new(cfg.sock_path.as_str(), cfg.unix_sock_timeout)
                            .ok()
                    });

                if let Some(client) = maybe_client {
                    Source::Daemon(client)
                } else {
                    let users = read_etc_passwd_file("/etc/passwd").unwrap_or_default();
                    // let groups = read_etc_group_file("/etc/group").unwrap_or_default();
                    let shadow = read_etc_shadow_file("/etc/shadow").unwrap_or_default();
                    Source::Fallback {
                        users,
                        // groups,
                        shadow,
                    }
                }
            }
            #[cfg(test)]
            RequestOptions::Test {
                socket,
                users,
                // groups,
                shadow,
            } => {
                if let Some(socket) = socket {
                    Source::Daemon(DaemonClientBlocking::from(socket))
                } else {
                    Source::Fallback { users, shadow }
                }
            }
        }
    }
}

pub trait PamHandler {
    fn account_id(&self) -> PamResult<String>;

    fn service_info(&self) -> PamResult<PamServiceInfo>;

    fn consume_authtok(&self) -> PamResult<Option<String>>;

    /// Display a message to the user.
    fn message(&self, prompt: &str) -> PamResult<()>;

    /// Display a device grant request to the user.
    fn message_device_grant(&self, data: &DeviceAuthorizationResponse) -> PamResult<()>;

    /// Request a password from the user.
    fn prompt_for_password(&self) -> PamResult<Option<String>>;

    fn prompt_for_pin(&self) -> PamResult<Option<String>>;

    fn prompt_for_mfacode(&self) -> PamResult<Option<String>>;
}

impl PamHandler for PamHandle {
    fn account_id(&self) -> PamResult<String> {
        self.get_user(None)
    }

    fn service_info(&self) -> PamResult<PamServiceInfo> {
        self.get_pam_info()
    }

    fn consume_authtok(&self) -> PamResult<Option<String>> {
        todo!();
        /*
        let mut consume_authtok = None;
        std::mem::swap(&mut authtok, &mut consume_authtok);
        match pamh.get_authtok() {
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
        */
    }

    fn message(&self, prompt: &str) -> PamResult<()> {
        todo!();
    }

    fn prompt_for_password(&self) -> PamResult<Option<String>> {
        /*
        let conv = match pamh.get_item::<PamConv>() {
            Ok(conv) => conv,
            Err(err) => {
                error!(?err, "pam_conv");
                return err;
            }
        };
        conv.send(PAM_PROMPT_ECHO_OFF, "Password: ")
        */
        todo!();
    }

    fn prompt_for_mfacode(&self) -> PamResult<Option<String>> {
        /*
        conv.send(PAM_PROMPT_ECHO_OFF, "Code: ")
        */
        todo!();
    }

    fn prompt_for_pin(&self) -> PamResult<Option<String>> {
        /*
        conv.send(PAM_PROMPT_ECHO_OFF, "PIN: ")
        */
        todo!();
    }

    fn message_device_grant(&self, data: &DeviceAuthorizationResponse) -> PamResult<()> {
        /*
        let msg = match &data.message {
            Some(msg) => msg.clone(),
            None => format!("Using a browser on another device, visit:\n{}\nAnd enter the code:\n{}",
                            data.verification_uri, data.user_code)
        };
        conv.send(PAM_TEXT_INFO, &msg)
        */
        todo!();
    }
}

pub fn sm_authenticate_connected<P: PamHandler>(
    pamh: &P,
    opts: &ModuleOptions,
    current_time: OffsetDateTime,
    mut daemon_client: DaemonClientBlocking,
) -> PamResultCode {
    let info = match pamh.service_info() {
        Ok(info) => info,
        Err(e) => {
            error!(err = ?e, "get_pam_info");
            return e;
        }
    };

    let account_id = match pamh.account_id() {
        Ok(acc) => acc,
        Err(err) => return err,
    };

    let mut timeout: Option<u64> = None;
    let mut active_polling_interval = Duration::from_secs(1);

    let mut req = ClientRequest::PamAuthenticateInit { account_id, info };

    loop {
        let client_response = match daemon_client.call_and_wait(&req, timeout) {
            Ok(r) => r,
            Err(err) => {
                // Something unrecoverable occured, bail and stop everything
                error!(?err, "PAM_AUTH_ERR");
                return PamResultCode::PAM_AUTH_ERR;
            }
        };

        match client_response {
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
                let authtok = if opts.use_first_pass {
                    match pamh.consume_authtok() {
                        Ok(authtok) => authtok,
                        Err(err) => return err,
                    }
                } else {
                    None
                };

                let cred = if let Some(cred) = authtok {
                    cred
                } else {
                    match pamh.prompt_for_password() {
                        Ok(Some(cred)) => cred,
                        Ok(None) => return PamResultCode::PAM_CRED_INSUFFICIENT,
                        Err(err) => return err,
                    }
                };

                // Now setup the request for the next loop.
                timeout = None;
                req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Password { cred });
                continue;
            }
            ClientResponse::PamAuthenticateStepResponse(
                PamAuthResponse::DeviceAuthorizationGrant { data },
            ) => {
                if let Err(err) = pamh.message_device_grant(&data) {
                    return err;
                };

                timeout = Some(u64::from(data.expires_in));
                req =
                    ClientRequest::PamAuthenticateStep(PamAuthRequest::DeviceAuthorizationGrant {
                        data,
                    });
                continue;
            }
            ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::MFACode { msg }) => {
                let cred = match pamh.prompt_for_mfacode() {
                    Ok(Some(cred)) => cred,
                    Ok(None) => return PamResultCode::PAM_CRED_INSUFFICIENT,
                    Err(err) => return err,
                };

                // Now setup the request for the next loop.
                timeout = None;
                req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFACode { cred });
                continue;
            }
            ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::MFAPoll {
                msg,
                polling_interval,
            }) => {
                if let Err(err) = pamh.message(msg.as_str()) {
                    if opts.debug {
                        println!("Message prompt failed");
                    }
                    return err;
                }

                active_polling_interval = Duration::from_secs(polling_interval.into());

                timeout = None;
                req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFAPoll);
                // We don't need to actually sleep here as we immediately will poll and then go
                // into the MFAPollWait response below.
            }
            ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::MFAPollWait) => {
                // Counter intuitive, but we don't need a max poll attempts here because
                // if the resolver goes away, then this will error on the sock and
                // will shutdown. This allows the resolver to dynamically extend the
                // timeout if needed, and removes logic from the front end.
                std::thread::sleep(active_polling_interval);
                timeout = None;
                req = ClientRequest::PamAuthenticateStep(PamAuthRequest::MFAPoll);
            }

            ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::SetupPin { msg: _ }) => {
                /*
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
                timeout = None;
                req = ClientRequest::PamAuthenticateStep(PamAuthRequest::SetupPin {
                    pin,
                });
                continue;
                */
                todo!();
            }
            ClientResponse::PamAuthenticateStepResponse(PamAuthResponse::Pin) => {
                let authtok = if opts.use_first_pass {
                    match pamh.consume_authtok() {
                        Ok(authtok) => authtok,
                        Err(err) => return err,
                    }
                } else {
                    None
                };

                let cred = if let Some(cred) = authtok {
                    cred
                } else {
                    match pamh.prompt_for_pin() {
                        Ok(Some(cred)) => cred,
                        Ok(None) => return PamResultCode::PAM_CRED_INSUFFICIENT,
                        Err(err) => return err,
                    }
                };

                // Now setup the request for the next loop.
                timeout = None;
                req = ClientRequest::PamAuthenticateStep(PamAuthRequest::Pin { cred });
                continue;
            }

            ClientResponse::Ok
            | ClientResponse::Error
            | ClientResponse::SshKeys(_)
            | ClientResponse::NssAccounts(_)
            | ClientResponse::NssAccount(_)
            | ClientResponse::NssGroups(_)
            | ClientResponse::PamStatus(_)
            | ClientResponse::ProviderStatus(_)
            | ClientResponse::PamStatus(_)
            | ClientResponse::NssGroup(_) => {
                debug!("PamResultCode::PAM_AUTH_ERR");
                return PamResultCode::PAM_AUTH_ERR;
            }
        }
    } // while true, continue calling PamAuthenticateStep until we get a decision.
}

pub fn sm_authenticate_fallback<P: PamHandler>(
    pamh: &P,
    opts: &ModuleOptions,
    current_time: OffsetDateTime,
    users: Vec<EtcUser>,
    shadow: Vec<EtcShadow>,
) -> PamResultCode {
    todo!();
}

pub fn sm_authenticate<P: PamHandler>(
    pamh: &P,
    opts: &ModuleOptions,
    req_opt: RequestOptions,
    current_time: OffsetDateTime,
) -> PamResultCode {
    match req_opt.connect_to_daemon() {
        Source::Daemon(mut daemon_client) => {
            sm_authenticate_connected(pamh, opts, current_time, daemon_client)
        }
        Source::Fallback { users, shadow } => {
            sm_authenticate_fallback(pamh, opts, current_time, users, shadow)
        }
    }
}

pub fn acct_mgmt<P: PamHandler>(
    pamh: &P,
    opts: &ModuleOptions,
    req_opt: RequestOptions,
    current_time: OffsetDateTime,
) -> PamResultCode {
    let account_id = match pamh.account_id() {
        Ok(acc) => acc,
        Err(err) => return err,
    };

    match req_opt.connect_to_daemon() {
        Source::Daemon(mut daemon_client) => {
            let req = ClientRequest::PamAccountAllowed(account_id);
            match daemon_client.call_and_wait(&req, None) {
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
        Source::Fallback { users, shadow } => {
            let user = users
                .into_iter()
                .filter(|etcuser| etcuser.name == account_id)
                .next();

            let shadow = shadow
                .into_iter()
                .filter(|etcshadow| etcshadow.name == account_id)
                .next();

            let (user, shadow) = match (user, shadow) {
                (Some(user), Some(shadow)) => (user, shadow),
                _ => {
                    if opts.ignore_unknown_user {
                        debug!("PamResultCode::PAM_IGNORE");
                        return PamResultCode::PAM_IGNORE;
                    } else {
                        debug!("PamResultCode::PAM_USER_UNKNOWN");
                        return PamResultCode::PAM_USER_UNKNOWN;
                    }
                }
            };

            let expiration_date = shadow
                .epoch_expire_date
                .map(|expire| OffsetDateTime::UNIX_EPOCH + time::Duration::days(expire));

            if let Some(expire) = expiration_date {
                if current_time >= expire {
                    debug!("PamResultCode::PAM_ACCT_EXPIRED");
                    return PamResultCode::PAM_ACCT_EXPIRED;
                }
            };

            // All checks passed!

            debug!("PAM_SUCCESS");
            PamResultCode::PAM_SUCCESS
        }
    }
}

pub fn sm_open_session<P: PamHandler>(
    pamh: &P,
    _opts: &ModuleOptions,
    req_opt: RequestOptions,
) -> PamResultCode {
    let account_id = match pamh.account_id() {
        Ok(acc) => acc,
        Err(err) => return err,
    };

    match req_opt.connect_to_daemon() {
        Source::Daemon(mut daemon_client) => {
            let req = ClientRequest::PamAccountBeginSession(account_id);

            match daemon_client.call_and_wait(&req, None) {
                Ok(ClientResponse::Ok) => {
                    debug!("PAM_SUCCESS");
                    PamResultCode::PAM_SUCCESS
                }
                other => {
                    debug!(err = ?other, "PAM_IGNORE");
                    PamResultCode::PAM_IGNORE
                }
            }
        }
        Source::Fallback {
            users: _,
            shadow: _,
        } => {
            debug!("PAM_SUCCESS");
            PamResultCode::PAM_SUCCESS
        }
    }
}

pub fn sm_close_session<P: PamHandler>(_pamh: &P, _opts: &ModuleOptions) -> PamResultCode {
    PamResultCode::PAM_SUCCESS
}

pub fn sm_chauthtok<P: PamHandler>(_pamh: &P, _opts: &ModuleOptions) -> PamResultCode {
    PamResultCode::PAM_IGNORE
}

pub fn sm_setcred<P: PamHandler>(_pamh: &P, _opts: &ModuleOptions) -> PamResultCode {
    PamResultCode::PAM_SUCCESS
}
