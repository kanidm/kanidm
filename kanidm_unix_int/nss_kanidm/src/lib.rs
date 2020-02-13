#[macro_use]
extern crate libnss;
#[macro_use]
extern crate lazy_static;

use kanidm_unix_common::unix_proto::{
    ClientRequest,
    ClientResponse,
    NssUser,
    NssGroup
};
use kanidm_unix_common::client::call_daemon_blocking;
use kanidm_unix_common::constants::DEFAULT_SOCK_PATH;

use libnss::group::{Group, GroupHooks};
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::interop::Response;

use libc;

struct KanidmPasswd;
libnss_passwd_hooks!(kanidm, KanidmPasswd);

impl PasswdHooks for KanidmPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        let req = ClientRequest::NssAccounts;
        call_daemon_blocking(DEFAULT_SOCK_PATH, req)
            .map(|r| {
                match r {
                    ClientResponse::NssAccounts(l) => l.into_iter().map(passwd_from_nssuser).collect(),
                    _ => Vec::new(),
                }
            })
            .map(|v| {
                Response::Success(v)
            })
            .unwrap_or_else(|_| {
                Response::Success(vec![])
            })
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        let req = ClientRequest::NssAccountByUid(uid);
        call_daemon_blocking(DEFAULT_SOCK_PATH, req)
            .map(|r| {
                match r {
                    ClientResponse::NssAccount(opt) => {
                        opt
                            .map(passwd_from_nssuser)
                            .map(|p| Response::Success(p))
                            .unwrap_or_else(|| Response::NotFound)
                    }
                    _ => Response::NotFound,
                }
            })
            .unwrap_or_else(|_| {
                Response::NotFound
            })
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        let req = ClientRequest::NssAccountByName(name);
        call_daemon_blocking(DEFAULT_SOCK_PATH, req)
            .map(|r| {
                match r {
                    ClientResponse::NssAccount(opt) => {
                        opt
                            .map(passwd_from_nssuser)
                            .map(|p| Response::Success(p))
                            .unwrap_or_else(|| Response::NotFound)
                    }
                    _ => Response::NotFound,
                }
            })
            .unwrap_or_else(|_| {
                Response::NotFound
            })
    }
}

struct KanidmGroup;
libnss_group_hooks!(kanidm, KanidmGroup);

impl GroupHooks for KanidmGroup {
    fn get_all_entries() -> Response<Vec<Group>> {
        let req = ClientRequest::NssGroups;
        call_daemon_blocking(DEFAULT_SOCK_PATH, req)
            .map(|r| {
                match r {
                    ClientResponse::NssGroups(l) => l.into_iter().map(group_from_nssgroup).collect(),
                    _ => Vec::new(),
                }
            })
            .map(|v| {
                Response::Success(v)
            })
            .unwrap_or_else(|_| {
                Response::Success(vec![])
            })
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> Response<Group> {
        let req = ClientRequest::NssGroupByGid(gid);
        call_daemon_blocking(DEFAULT_SOCK_PATH, req)
            .map(|r| {
                match r {
                    ClientResponse::NssGroup(opt) => {
                        opt
                            .map(group_from_nssgroup)
                            .map(|p| Response::Success(p))
                            .unwrap_or_else(|| Response::NotFound)
                    }
                    _ => Response::NotFound,
                }
            })
            .unwrap_or_else(|_| {
                Response::NotFound
            })
    }

    fn get_entry_by_name(name: String) -> Response<Group> {
        let req = ClientRequest::NssGroupByName(name);
        call_daemon_blocking(DEFAULT_SOCK_PATH, req)
            .map(|r| {
                match r {
                    ClientResponse::NssGroup(opt) => {
                        opt
                            .map(group_from_nssgroup)
                            .map(|p| Response::Success(p))
                            .unwrap_or_else(|| Response::NotFound)
                    }
                    _ => Response::NotFound,
                }
            })
            .unwrap_or_else(|_| {
                Response::NotFound
            })
    }
}

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

fn group_from_nssgroup(ng: NssGroup) -> Group {
    Group {
        name: ng.name,
        passwd: "x".to_string(),
        gid: ng.gid,
        members: ng.members,
    }
}

