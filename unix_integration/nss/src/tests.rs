use crate::core::{self, RequestOptions};
use kanidm_unix_common::unix_passwd::{EtcGroup, EtcUser};
use libnss::interop::Response;

impl RequestOptions {
    fn fallback_fixture() -> Self {
        RequestOptions::Test {
            socket: None,
            users: vec![
                EtcUser {
                    name: "root".to_string(),
                    password: "a".to_string(),
                    uid: 0,
                    gid: 0,
                    gecos: "Root".to_string(),
                    homedir: "/root".to_string(),
                    shell: "/bin/bash".to_string(),
                },
                EtcUser {
                    name: "tobias".to_string(),
                    password: "a".to_string(),
                    uid: 1000,
                    gid: 1000,
                    gecos: "Tobias".to_string(),
                    homedir: "/home/tobias".to_string(),
                    shell: "/bin/zsh".to_string(),
                },
                EtcUser {
                    name: "ellie".to_string(),
                    password: "a".to_string(),
                    uid: 1001,
                    gid: 1001,
                    gecos: "Ellie".to_string(),
                    homedir: "/home/ellie".to_string(),
                    shell: "/bin/tcsh".to_string(),
                },
            ],
            groups: vec![
                EtcGroup {
                    name: "root".to_string(),
                    password: "a".to_string(),
                    gid: 0,
                    members: vec!["root".to_string()],
                },
                EtcGroup {
                    name: "tobias".to_string(),
                    password: "a".to_string(),
                    gid: 1000,
                    members: vec!["tobias".to_string()],
                },
                EtcGroup {
                    name: "ellie".to_string(),
                    password: "a".to_string(),
                    gid: 1001,
                    members: vec!["ellie".to_string()],
                },
            ],
        }
    }

    fn fallback_unavail() -> Self {
        RequestOptions::Test {
            socket: None,
            users: vec![],
            groups: vec![],
        }
    }
}

#[test]
fn nss_fallback_unavail() {
    let req_opt = RequestOptions::fallback_unavail();
    let Response::Unavail = core::get_all_user_entries(req_opt) else {
        unreachable!();
    };

    let req_opt = RequestOptions::fallback_unavail();
    let Response::Unavail = core::get_user_entry_by_uid(0, req_opt) else {
        unreachable!();
    };

    let req_opt = RequestOptions::fallback_unavail();
    let Response::Unavail = core::get_user_entry_by_name("root".to_string(), req_opt) else {
        unreachable!();
    };

    let req_opt = RequestOptions::fallback_unavail();
    let Response::Unavail = core::get_all_group_entries(req_opt) else {
        unreachable!();
    };

    let req_opt = RequestOptions::fallback_unavail();
    let Response::Unavail = core::get_group_entry_by_gid(0, req_opt) else {
        unreachable!();
    };

    let req_opt = RequestOptions::fallback_unavail();
    let Response::Unavail = core::get_group_entry_by_name("root".to_string(), req_opt) else {
        unreachable!();
    };
}

#[test]
fn nss_fallback_all_user_entries() {
    let req_opt = RequestOptions::fallback_fixture();

    let Response::Success(users) = core::get_all_user_entries(req_opt) else {
        unreachable!();
    };

    assert_eq!(users.len(), 3);
    assert_eq!(users[0].name, "root");
    assert_eq!(users[0].passwd, "x");
    assert_eq!(users[0].uid, 0);
    assert_eq!(users[0].gid, 0);

    assert_eq!(users[1].name, "tobias");
    assert_eq!(users[1].passwd, "x");
    assert_eq!(users[1].uid, 1000);
    assert_eq!(users[1].gid, 1000);

    assert_eq!(users[2].name, "ellie");
    assert_eq!(users[2].passwd, "x");
    assert_eq!(users[2].uid, 1001);
    assert_eq!(users[2].gid, 1001);
}

#[test]
fn nss_fallback_user_entry_by_uid() {
    let req_opt = RequestOptions::fallback_fixture();
    let Response::Success(user) = core::get_user_entry_by_uid(0, req_opt) else {
        unreachable!();
    };

    assert_eq!(user.name, "root");
    assert_eq!(user.passwd, "x");
    assert_eq!(user.uid, 0);
    assert_eq!(user.gid, 0);

    let req_opt = RequestOptions::fallback_fixture();
    let Response::Success(user) = core::get_user_entry_by_uid(1000, req_opt) else {
        unreachable!();
    };

    assert_eq!(user.name, "tobias");
    assert_eq!(user.passwd, "x");
    assert_eq!(user.uid, 1000);
    assert_eq!(user.gid, 1000);

    let req_opt = RequestOptions::fallback_fixture();
    let Response::NotFound = core::get_user_entry_by_uid(10, req_opt) else {
        unreachable!();
    };
}

#[test]
fn nss_fallback_user_entry_by_name() {
    let req_opt = RequestOptions::fallback_fixture();
    let Response::Success(user) = core::get_user_entry_by_name("root".to_string(), req_opt) else {
        unreachable!();
    };

    assert_eq!(user.name, "root");
    assert_eq!(user.passwd, "x");
    assert_eq!(user.uid, 0);
    assert_eq!(user.gid, 0);

    let req_opt = RequestOptions::fallback_fixture();
    let Response::Success(user) = core::get_user_entry_by_name("ellie".to_string(), req_opt) else {
        unreachable!();
    };

    assert_eq!(user.name, "ellie");
    assert_eq!(user.passwd, "x");
    assert_eq!(user.uid, 1001);
    assert_eq!(user.gid, 1001);

    let req_opt = RequestOptions::fallback_fixture();
    let Response::NotFound = core::get_user_entry_by_name("william".to_string(), req_opt) else {
        unreachable!();
    };
}

#[test]
fn nss_fallback_all_group_entries() {
    let req_opt = RequestOptions::fallback_fixture();

    let Response::Success(groups) = core::get_all_group_entries(req_opt) else {
        unreachable!();
    };

    assert_eq!(groups.len(), 3);
    assert_eq!(groups[0].name, "root");
    assert_eq!(groups[0].passwd, "x");
    assert_eq!(groups[0].gid, 0);

    assert_eq!(groups[1].name, "tobias");
    assert_eq!(groups[1].passwd, "x");
    assert_eq!(groups[1].gid, 1000);

    assert_eq!(groups[2].name, "ellie");
    assert_eq!(groups[2].passwd, "x");
    assert_eq!(groups[2].gid, 1001);
}

#[test]
fn nss_fallback_group_entry_by_uid() {
    let req_opt = RequestOptions::fallback_fixture();
    let Response::Success(group) = core::get_group_entry_by_gid(0, req_opt) else {
        unreachable!();
    };

    assert_eq!(group.name, "root");
    assert_eq!(group.passwd, "x");
    assert_eq!(group.gid, 0);

    let req_opt = RequestOptions::fallback_fixture();
    let Response::Success(group) = core::get_group_entry_by_gid(1000, req_opt) else {
        unreachable!();
    };

    assert_eq!(group.name, "tobias");
    assert_eq!(group.passwd, "x");
    assert_eq!(group.gid, 1000);

    let req_opt = RequestOptions::fallback_fixture();
    let Response::NotFound = core::get_group_entry_by_gid(10, req_opt) else {
        unreachable!();
    };
}

#[test]
fn nss_fallback_group_entry_by_name() {
    let req_opt = RequestOptions::fallback_fixture();
    let Response::Success(group) = core::get_group_entry_by_name("root".to_string(), req_opt)
    else {
        unreachable!();
    };

    assert_eq!(group.name, "root");
    assert_eq!(group.passwd, "x");
    assert_eq!(group.gid, 0);

    let req_opt = RequestOptions::fallback_fixture();
    let Response::Success(group) = core::get_group_entry_by_name("ellie".to_string(), req_opt)
    else {
        unreachable!();
    };

    assert_eq!(group.name, "ellie");
    assert_eq!(group.passwd, "x");
    assert_eq!(group.gid, 1001);

    let req_opt = RequestOptions::fallback_fixture();
    let Response::NotFound = core::get_group_entry_by_name("william".to_string(), req_opt) else {
        unreachable!();
    };
}
