#[macro_use]
extern crate libnss;
#[macro_use]
extern crate lazy_static;

use kanidm_unix_common::unix_proto::{ClientRequest, ClientResponse};

use libnss::group::{Group, GroupHooks};
use libnss::passwd::{Passwd, PasswdHooks};
use libnss::interop::Response;

use libc;

struct KanidmPasswd;
libnss_passwd_hooks!(kanidm, KanidmPasswd);

impl PasswdHooks for KanidmPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        Response::Success(vec![])
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        Response::NotFound
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        Response::NotFound
    }
}

struct KanidmGroup;
libnss_group_hooks!(kanidm, KanidmGroup);

impl GroupHooks for KanidmGroup {
    fn get_all_entries() -> Response<Vec<Group>> {
        Response::Success(vec![])
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> Response<Group> {
        Response::NotFound
    }

    fn get_entry_by_name(name: String) -> Response<Group> {
        Response::NotFound
    }
}

