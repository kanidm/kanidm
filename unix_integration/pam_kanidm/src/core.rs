use crate::constants::PamResultCode;
use crate::module::PamResult;
use crate::pam::module::PamHandle;
use crate::pam::ModuleOptions;
use kanidm_unix_common::client_sync::DaemonClientBlocking;
use kanidm_unix_common::client_sync::UnixStream;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};
use tracing::debug;

pub enum RequestOptions {
    Main {
        config_path: &'static str,
    },
    #[cfg(test)]
    Test {
        socket: Option<UnixStream>,
        // shadow: Vec<EtcShadow>,
    },
}

enum Source {
    Daemon(DaemonClientBlocking),
    Fallback {
        // users: Vec<EtcUser>,
        // groups: Vec<EtcGroup>,
        // shadow: Vec<EtcShadow>,
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
                    // let users = read_etc_passwd_file("/etc/passwd").unwrap_or_default();

                    // let groups = read_etc_group_file("/etc/group").unwrap_or_default();

                    Source::Fallback {}
                }
            }
            #[cfg(test)]
            RequestOptions::Test {
                socket,
                // users,
                // groups,
            } => {
                if let Some(socket) = socket {
                    Source::Daemon(DaemonClientBlocking::from(socket))
                } else {
                    Source::Fallback {}
                }
            }
        }
    }
}

pub trait PamHandler {
    fn account_id(&self) -> PamResult<String>;
}

impl PamHandler for PamHandle {
    fn account_id(&self) -> PamResult<String> {
        self.get_user(None)
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
        Source::Fallback {} => {
            todo!();
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
