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

    fn tty(&self) -> PamResult<Option<String>>;

    fn rhost(&self) -> PamResult<Option<String>>;
}

impl PamHandler for PamHandle {
    fn account_id(&self) -> PamResult<String> {
        self.get_user(None)
    }

    fn tty(&self) -> PamResult<Option<String>> {
        self.get_tty()
    }

    fn rhost(&self) -> PamResult<Option<String>> {
        self.get_rhost()
    }
}

pub fn acct_mgmt<P: PamHandler>(
    pamh: &P,
    opts: &ModuleOptions,
    req_opt: RequestOptions,
    current_time: OffsetDateTime,
) -> PamResultCode {
    let tty = match pamh.tty() {
        Ok(t) => t,
        Err(err) => return err,
    };

    let rhost = match pamh.rhost() {
        Ok(r) => r,
        Err(err) => return err,
    };

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

            if !opts.fallback_allow_local_accounts && user.uid > 0 {
                debug!("PamResultCode::PAM_PERM_DENIED");
                return PamResultCode::PAM_PERM_DENIED;
            }

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
