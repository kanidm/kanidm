use crate::constants::PamResultCode;
use crate::core::PamHandler;
use crate::core::{self, RequestOptions};
use crate::module::PamResult;
use crate::pam::ModuleOptions;
use kanidm_unix_common::unix_passwd::{EtcShadow, EtcUser};
use std::collections::VecDeque;
use time::OffsetDateTime;

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
            ],
            // groups: vec![],
            shadow: vec![
                EtcShadow {
                    name: "root".to_string(),
                    password: "x".to_string(),
                    ..Default::default()
                },
                EtcShadow {
                    name: "tobias".to_string(),
                    password: "x".to_string(),
                    epoch_expire_date: Some(10),
                    ..Default::default()
                },
            ],
        }
    }
}

struct TestHandler {
    account_id: String,
    response_queue: VecDeque<()>,
}

impl Default for TestHandler {
    fn default() -> Self {
        TestHandler {
            account_id: "tobias".to_string(),
            response_queue: VecDeque::default(),
        }
    }
}

impl TestHandler {
    fn set_account_id(&mut self, account_id: String) {
        self.account_id = account_id
    }
}

impl PamHandler for TestHandler {
    fn account_id(&self) -> PamResult<String> {
        Ok(self.account_id.clone())
    }

    fn tty(&self) -> PamResult<Option<String>> {
        Ok(None)
    }

    fn rhost(&self) -> PamResult<Option<String>> {
        Ok(None)
    }
}

#[test]
fn pam_fallback_acct_mgmt_default() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let pamh = TestHandler::default();
    let test_time = OffsetDateTime::UNIX_EPOCH;

    assert_eq!(
        core::acct_mgmt(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_PERM_DENIED
    );
}

#[test]
fn pam_fallback_acct_mgmt_deny_unknown() {
    let req_opt = RequestOptions::fallback_fixture();
    let mut mod_opts = ModuleOptions::default();
    mod_opts.fallback_allow_local_accounts = true;
    let mut pamh = TestHandler::default();
    pamh.set_account_id("nonexist".to_string());
    let test_time = OffsetDateTime::UNIX_EPOCH;

    assert_eq!(
        core::acct_mgmt(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_USER_UNKNOWN
    );
}

#[test]
fn pam_fallback_acct_mgmt_ignore_unknown() {
    let req_opt = RequestOptions::fallback_fixture();
    let mut mod_opts = ModuleOptions::default();
    mod_opts.fallback_allow_local_accounts = true;
    mod_opts.ignore_unknown_user = true;
    let mut pamh = TestHandler::default();
    pamh.set_account_id("nonexist".to_string());
    let test_time = OffsetDateTime::UNIX_EPOCH;

    assert_eq!(
        core::acct_mgmt(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_IGNORE
    );
}

#[test]
fn pam_fallback_acct_mgmt_compat() {
    let req_opt = RequestOptions::fallback_fixture();
    let mut mod_opts = ModuleOptions::default();
    mod_opts.fallback_allow_local_accounts = true;
    let pamh = TestHandler::default();
    let test_time = OffsetDateTime::UNIX_EPOCH;

    assert_eq!(
        core::acct_mgmt(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_SUCCESS
    );
}

#[test]
fn pam_fallback_acct_mgmt_expired() {
    let req_opt = RequestOptions::fallback_fixture();
    let mut mod_opts = ModuleOptions::default();
    mod_opts.fallback_allow_local_accounts = true;
    let pamh = TestHandler::default();
    let test_time = OffsetDateTime::UNIX_EPOCH + time::Duration::days(16);

    assert_eq!(
        core::acct_mgmt(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_ACCT_EXPIRED
    );
}

#[test]
fn pam_fallback_acct_mgmt_root() {
    // Test that root can always access the system even if local
    // users are denied in fallback mode.
    let req_opt = RequestOptions::fallback_fixture();
    let mut mod_opts = ModuleOptions::default();
    let mut pamh = TestHandler::default();
    pamh.set_account_id("root".to_string());
    let test_time = OffsetDateTime::UNIX_EPOCH;

    assert_eq!(
        core::acct_mgmt(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_SUCCESS
    );
}

#[test]
fn pam_fallback_sm_open_session() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let pamh = TestHandler::default();

    assert_eq!(
        core::sm_open_session(&pamh, &mod_opts, req_opt),
        PamResultCode::PAM_SUCCESS
    );
}

#[test]
fn pam_fallback_sm_close_session() {
    // let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let pamh = TestHandler::default();

    assert_eq!(
        core::sm_close_session(&pamh, &mod_opts),
        PamResultCode::PAM_SUCCESS
    );
}

#[test]
fn pam_fallback_sm_chauthtok() {
    // let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let pamh = TestHandler::default();

    assert_eq!(
        core::sm_chauthtok(&pamh, &mod_opts),
        PamResultCode::PAM_IGNORE
    );
}

#[test]
fn pam_fallback_sm_setcred() {
    // let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let pamh = TestHandler::default();

    assert_eq!(
        core::sm_setcred(&pamh, &mod_opts),
        PamResultCode::PAM_SUCCESS
    );
}
