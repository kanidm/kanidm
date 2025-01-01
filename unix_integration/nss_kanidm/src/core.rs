use kanidm_unix_common::client_sync::DaemonClientBlocking;
use kanidm_unix_common::unix_config::KanidmUnixdConfig;
use kanidm_unix_common::unix_passwd::{
    read_etc_group_file, read_etc_passwd_file, EtcGroup, EtcUser,
};
use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse, NssGroup, NssUser};

use libnss::group::Group;
use libnss::interop::Response;
use libnss::passwd::Passwd;

#[cfg(test)]
use kanidm_unix_common::client_sync::UnixStream;

pub enum RequestOptions {
    Main {
        config_path: &'static str,
    },
    #[cfg(test)]
    Test {
        socket: Option<UnixStream>,
        users: Vec<EtcUser>,
        groups: Vec<EtcGroup>,
    },
}

enum Source {
    Daemon(DaemonClientBlocking),
    Fallback {
        users: Vec<EtcUser>,
        groups: Vec<EtcGroup>,
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

                    let groups = read_etc_group_file("/etc/group").unwrap_or_default();

                    Source::Fallback { users, groups }
                }
            }
            #[cfg(test)]
            RequestOptions::Test {
                socket,
                users,
                groups,
            } => {
                if let Some(socket) = socket {
                    Source::Daemon(DaemonClientBlocking::from(socket))
                } else {
                    Source::Fallback { users, groups }
                }
            }
        }
    }
}

pub fn get_all_user_entries(req_options: RequestOptions) -> Response<Vec<Passwd>> {
    match req_options.connect_to_daemon() {
        Source::Daemon(mut daemon_client) => {
            let req = ClientRequest::NssAccounts;

            daemon_client
                .call_and_wait(&req, None)
                .map(|r| match r {
                    ClientResponse::NssAccounts(l) => {
                        l.into_iter().map(passwd_from_nssuser).collect()
                    }
                    _ => Vec::new(),
                })
                .map(Response::Success)
                .unwrap_or_else(|_| Response::Success(vec![]))
        }
        Source::Fallback { users, groups: _ } => {
            if users.is_empty() {
                return Response::Unavail;
            }

            let users = users.into_iter().map(passwd_from_etcuser).collect();

            Response::Success(users)
        }
    }
}

pub fn get_user_entry_by_uid(uid: libc::uid_t, req_options: RequestOptions) -> Response<Passwd> {
    match req_options.connect_to_daemon() {
        Source::Daemon(mut daemon_client) => {
            let req = ClientRequest::NssAccountByUid(uid);
            daemon_client
                .call_and_wait(&req, None)
                .map(|r| match r {
                    ClientResponse::NssAccount(opt) => opt
                        .map(passwd_from_nssuser)
                        .map(Response::Success)
                        .unwrap_or_else(|| Response::NotFound),
                    _ => Response::NotFound,
                })
                .unwrap_or_else(|_| Response::NotFound)
        }
        Source::Fallback { users, groups: _ } => {
            if users.is_empty() {
                return Response::Unavail;
            }

            let user = users
                .into_iter()
                .filter_map(|etcuser| {
                    if etcuser.uid == uid {
                        Some(passwd_from_etcuser(etcuser))
                    } else {
                        None
                    }
                })
                .next();

            if let Some(user) = user {
                Response::Success(user)
            } else {
                Response::NotFound
            }
        }
    }
}

pub fn get_user_entry_by_name(name: String, req_options: RequestOptions) -> Response<Passwd> {
    match req_options.connect_to_daemon() {
        Source::Daemon(mut daemon_client) => {
            let req = ClientRequest::NssAccountByName(name);
            daemon_client
                .call_and_wait(&req, None)
                .map(|r| match r {
                    ClientResponse::NssAccount(opt) => opt
                        .map(passwd_from_nssuser)
                        .map(Response::Success)
                        .unwrap_or_else(|| Response::NotFound),
                    _ => Response::NotFound,
                })
                .unwrap_or_else(|_| Response::NotFound)
        }
        Source::Fallback { users, groups: _ } => {
            if users.is_empty() {
                return Response::Unavail;
            }

            let user = users
                .into_iter()
                .filter_map(|etcuser| {
                    if etcuser.name == name {
                        Some(passwd_from_etcuser(etcuser))
                    } else {
                        None
                    }
                })
                .next();

            if let Some(user) = user {
                Response::Success(user)
            } else {
                Response::NotFound
            }
        }
    }
}

pub fn get_all_group_entries(req_options: RequestOptions) -> Response<Vec<Group>> {
    match req_options.connect_to_daemon() {
        Source::Daemon(mut daemon_client) => {
            let req = ClientRequest::NssGroups;
            daemon_client
                .call_and_wait(&req, None)
                .map(|r| match r {
                    ClientResponse::NssGroups(l) => {
                        l.into_iter().map(group_from_nssgroup).collect()
                    }
                    _ => Vec::new(),
                })
                .map(Response::Success)
                .unwrap_or_else(|_| Response::Success(vec![]))
        }
        Source::Fallback { users: _, groups } => {
            if groups.is_empty() {
                return Response::Unavail;
            }

            let groups = groups.into_iter().map(group_from_etcgroup).collect();

            Response::Success(groups)
        }
    }
}

pub fn get_group_entry_by_gid(gid: libc::gid_t, req_options: RequestOptions) -> Response<Group> {
    match req_options.connect_to_daemon() {
        Source::Daemon(mut daemon_client) => {
            let req = ClientRequest::NssGroupByGid(gid);
            daemon_client
                .call_and_wait(&req, None)
                .map(|r| match r {
                    ClientResponse::NssGroup(opt) => opt
                        .map(group_from_nssgroup)
                        .map(Response::Success)
                        .unwrap_or_else(|| Response::NotFound),
                    _ => Response::NotFound,
                })
                .unwrap_or_else(|_| Response::NotFound)
        }
        Source::Fallback { users: _, groups } => {
            if groups.is_empty() {
                return Response::Unavail;
            }

            let group = groups
                .into_iter()
                .filter_map(|etcgroup| {
                    if etcgroup.gid == gid {
                        Some(group_from_etcgroup(etcgroup))
                    } else {
                        None
                    }
                })
                .next();

            if let Some(group) = group {
                Response::Success(group)
            } else {
                Response::NotFound
            }
        }
    }
}

pub fn get_group_entry_by_name(name: String, req_options: RequestOptions) -> Response<Group> {
    match req_options.connect_to_daemon() {
        Source::Daemon(mut daemon_client) => {
            let req = ClientRequest::NssGroupByName(name);
            daemon_client
                .call_and_wait(&req, None)
                .map(|r| match r {
                    ClientResponse::NssGroup(opt) => opt
                        .map(group_from_nssgroup)
                        .map(Response::Success)
                        .unwrap_or_else(|| Response::NotFound),
                    _ => Response::NotFound,
                })
                .unwrap_or_else(|_| Response::NotFound)
        }
        Source::Fallback { users: _, groups } => {
            if groups.is_empty() {
                return Response::Unavail;
            }

            let group = groups
                .into_iter()
                .filter_map(|etcgroup| {
                    if etcgroup.name == name {
                        Some(group_from_etcgroup(etcgroup))
                    } else {
                        None
                    }
                })
                .next();

            if let Some(group) = group {
                Response::Success(group)
            } else {
                Response::NotFound
            }
        }
    }
}

pub fn get_group_entries_by_member(member: String, req_options: RequestOptions) -> Response<Vec<Group>> {
    match req_options.connect_to_daemon() {
        Source::Daemon(mut daemon_client) => {
            let req = ClientRequest::NssGroupsByMember(member);
            daemon_client
                .call_and_wait(&req, None)
                .map(|r| match r {
                    ClientResponse::NssGroups(l) => {
                        l.into_iter().map(group_from_nssgroup).collect()
                    }
                    _ => Vec::new(),
                })
                .map(Response::Success)
                .unwrap_or_else(|_| Response::Success(vec![]))
        }
        Source::Fallback { users: _, groups } => {
            if groups.is_empty() {
                return Response::Unavail;
            }

            let membergroups = groups
                .into_iter()
                .filter_map(|etcgroup| {
                    if etcgroup.members.contains(&member) {
                        Some(group_from_etcgroup(etcgroup))
                    } else {
                        None
                    }
                })
                .collect();

            Response::Success(membergroups)
        }
    }
}

fn passwd_from_etcuser(etc: EtcUser) -> Passwd {
    Passwd {
        name: etc.name,
        gecos: etc.gecos,
        passwd: "x".to_string(),
        uid: etc.uid,
        gid: etc.gid,
        dir: etc.homedir,
        shell: etc.shell,
    }
}

fn passwd_from_nssuser(nu: NssUser) -> Passwd {
    Passwd {
        name: nu.name,
        gecos: nu.gecos,
        passwd: "x".to_string(),
        uid: nu.uid,
        gid: nu.gid,
        dir: nu.homedir,
        shell: nu.shell,
    }
}

fn group_from_etcgroup(etc: EtcGroup) -> Group {
    Group {
        name: etc.name,
        passwd: "x".to_string(),
        gid: etc.gid,
        members: etc.members,
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
