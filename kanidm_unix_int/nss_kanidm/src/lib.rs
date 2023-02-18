#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[cfg(target_os_family = "unix")]
#[macro_use]
extern crate libnss;
#[cfg(target_os_family = "unix")]
#[macro_use]
extern crate lazy_static;

#[cfg(target_os_family = "unix")]
use kanidm_unix_common::client_sync::call_daemon_blocking;
#[cfg(target_os_family = "unix")]
use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
#[cfg(target_os_family = "unix")]
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
#[cfg(target_os_family = "unix")]
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse, NssGroup, NssUser};
#[cfg(target_os_family = "unix")]
use libnss::group::{Group, GroupHooks};
#[cfg(target_os_family = "unix")]
use libnss::interop::Response;
#[cfg(target_os_family = "unix")]
use libnss::passwd::{Passwd, PasswdHooks};

#[cfg(target_os_family = "unix")]
struct KanidmPasswd;
#[cfg(target_os_family = "unix")]
libnss_passwd_hooks!(kanidm, KanidmPasswd);

#[cfg(target_os_family = "unix")]
impl PasswdHooks for KanidmPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        let cfg =
            match KanidmUnixdConfig::new().read_options_from_optional_config(DEFAULT_CONFIG_PATH) {
                Ok(c) => c,
                Err(_) => {
                    return Response::Unavail;
                }
            };
        let req = ClientRequest::NssAccounts;
        call_daemon_blocking(cfg.sock_path.as_str(), &req, cfg.unix_sock_timeout)
            .map(|r| match r {
                ClientResponse::NssAccounts(l) => l.into_iter().map(passwd_from_nssuser).collect(),
                _ => Vec::new(),
            })
            .map(Response::Success)
            .unwrap_or_else(|_| Response::Success(vec![]))
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        let cfg =
            match KanidmUnixdConfig::new().read_options_from_optional_config(DEFAULT_CONFIG_PATH) {
                Ok(c) => c,
                Err(_) => {
                    return Response::Unavail;
                }
            };
        let req = ClientRequest::NssAccountByUid(uid);
        call_daemon_blocking(cfg.sock_path.as_str(), &req, cfg.unix_sock_timeout)
            .map(|r| match r {
                ClientResponse::NssAccount(opt) => opt
                    .map(passwd_from_nssuser)
                    .map(Response::Success)
                    .unwrap_or_else(|| Response::NotFound),
                _ => Response::NotFound,
            })
            .unwrap_or_else(|_| Response::NotFound)
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        let cfg =
            match KanidmUnixdConfig::new().read_options_from_optional_config(DEFAULT_CONFIG_PATH) {
                Ok(c) => c,
                Err(_) => {
                    return Response::Unavail;
                }
            };
        let req = ClientRequest::NssAccountByName(name);
        call_daemon_blocking(cfg.sock_path.as_str(), &req, cfg.unix_sock_timeout)
            .map(|r| match r {
                ClientResponse::NssAccount(opt) => opt
                    .map(passwd_from_nssuser)
                    .map(Response::Success)
                    .unwrap_or_else(|| Response::NotFound),
                _ => Response::NotFound,
            })
            .unwrap_or_else(|_| Response::NotFound)
    }
}

#[cfg(target_os_family = "unix")]
struct KanidmGroup;
#[cfg(target_os_family = "unix")]
libnss_group_hooks!(kanidm, KanidmGroup);

#[cfg(target_os_family = "unix")]
impl GroupHooks for KanidmGroup {
    fn get_all_entries() -> Response<Vec<Group>> {
        let cfg =
            match KanidmUnixdConfig::new().read_options_from_optional_config(DEFAULT_CONFIG_PATH) {
                Ok(c) => c,
                Err(_) => {
                    return Response::Unavail;
                }
            };
        let req = ClientRequest::NssGroups;
        call_daemon_blocking(cfg.sock_path.as_str(), &req, cfg.unix_sock_timeout)
            .map(|r| match r {
                ClientResponse::NssGroups(l) => l.into_iter().map(group_from_nssgroup).collect(),
                _ => Vec::new(),
            })
            .map(Response::Success)
            .unwrap_or_else(|_| Response::Success(vec![]))
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> Response<Group> {
        let cfg =
            match KanidmUnixdConfig::new().read_options_from_optional_config(DEFAULT_CONFIG_PATH) {
                Ok(c) => c,
                Err(_) => {
                    return Response::Unavail;
                }
            };
        let req = ClientRequest::NssGroupByGid(gid);
        call_daemon_blocking(cfg.sock_path.as_str(), &req, cfg.unix_sock_timeout)
            .map(|r| match r {
                ClientResponse::NssGroup(opt) => opt
                    .map(group_from_nssgroup)
                    .map(Response::Success)
                    .unwrap_or_else(|| Response::NotFound),
                _ => Response::NotFound,
            })
            .unwrap_or_else(|_| Response::NotFound)
    }

    fn get_entry_by_name(name: String) -> Response<Group> {
        let cfg =
            match KanidmUnixdConfig::new().read_options_from_optional_config(DEFAULT_CONFIG_PATH) {
                Ok(c) => c,
                Err(_) => {
                    return Response::Unavail;
                }
            };
        let req = ClientRequest::NssGroupByName(name);
        call_daemon_blocking(cfg.sock_path.as_str(), &req, cfg.unix_sock_timeout)
            .map(|r| match r {
                ClientResponse::NssGroup(opt) => opt
                    .map(group_from_nssgroup)
                    .map(Response::Success)
                    .unwrap_or_else(|| Response::NotFound),
                _ => Response::NotFound,
            })
            .unwrap_or_else(|_| Response::NotFound)
    }
}

#[cfg(target_os_family = "unix")]
fn passwd_from_nssuser(nu: NssUser) -> Passwd {
    Passwd {
        name: nu.name,
        gecos: nu.gecos,
        passwd: "x".to_string(),
        uid: nu.gid,
        gid: nu.gid,
        dir: nu.homedir,
        shell: nu.shell,
    }
}

#[cfg(target_os_family = "unix")]
fn group_from_nssgroup(ng: NssGroup) -> Group {
    Group {
        name: ng.name,
        passwd: "x".to_string(),
        gid: ng.gid,
        members: ng.members,
    }
}
