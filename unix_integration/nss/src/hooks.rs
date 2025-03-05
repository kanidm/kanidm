use crate::core::{self, RequestOptions};
use kanidm_unix_common::constants::DEFAULT_CONFIG_PATH;
use libnss::group::{Group, GroupHooks};
use libnss::interop::Response;
use libnss::passwd::{Passwd, PasswdHooks};

struct KanidmPasswd;
libnss_passwd_hooks!(kanidm, KanidmPasswd);

impl PasswdHooks for KanidmPasswd {
    fn get_all_entries() -> Response<Vec<Passwd>> {
        let req_opt = RequestOptions::Main {
            config_path: DEFAULT_CONFIG_PATH,
        };

        core::get_all_user_entries(req_opt)
    }

    fn get_entry_by_uid(uid: libc::uid_t) -> Response<Passwd> {
        let req_opt = RequestOptions::Main {
            config_path: DEFAULT_CONFIG_PATH,
        };

        core::get_user_entry_by_uid(uid, req_opt)
    }

    fn get_entry_by_name(name: String) -> Response<Passwd> {
        let req_opt = RequestOptions::Main {
            config_path: DEFAULT_CONFIG_PATH,
        };

        core::get_user_entry_by_name(name, req_opt)
    }
}

struct KanidmGroup;
libnss_group_hooks!(kanidm, KanidmGroup);

impl GroupHooks for KanidmGroup {
    fn get_all_entries() -> Response<Vec<Group>> {
        let req_opt = RequestOptions::Main {
            config_path: DEFAULT_CONFIG_PATH,
        };

        core::get_all_group_entries(req_opt)
    }

    fn get_entry_by_gid(gid: libc::gid_t) -> Response<Group> {
        let req_opt = RequestOptions::Main {
            config_path: DEFAULT_CONFIG_PATH,
        };

        core::get_group_entry_by_gid(gid, req_opt)
    }

    fn get_entry_by_name(name: String) -> Response<Group> {
        let req_opt = RequestOptions::Main {
            config_path: DEFAULT_CONFIG_PATH,
        };

        core::get_group_entry_by_name(name, req_opt)
    }
}
