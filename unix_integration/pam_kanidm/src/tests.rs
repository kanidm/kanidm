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
}

/// Show that a user can authenticate with the correct password
#[test]
fn pam_fallback_sm_authenticate_default() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let pamh = TestHandler::default();
    let test_time = OffsetDateTime::UNIX_EPOCH;

    assert_eq!(
        core::sm_authenticate(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_SUCCESS
    );
}

/// Show that incorrect pw fails
#[test]
fn pam_fallback_sm_authenticate_incorrect_pw() {
    todo!();
}

/// Show that root can authenticate with the correct password
#[test]
fn pam_fallback_sm_authenticate_root() {
    todo!();
}

/// Show that incorrect root pw fails
#[test]
fn pam_fallback_sm_authenticate_root_incorrect_pw() {
    todo!();
}

/// Show that an expired account does not prompt for pw at all.
#[test]
fn pam_fallback_sm_authenticate_expired() {
    todo!();
}

/// Show that unknown users are denied
#[test]
fn pam_fallback_sm_authenticate_unknown_denied() {
    todo!();
}

/// Show that unknown users are ignored when the setting is enabled.
#[test]
fn pam_fallback_sm_authenticate_unknown_ignore() {
    todo!();
}

/// If there is no stacked credential in pam, then one is prompted for
#[test]
fn pam_fallback_sm_authenticate_no_stacked_cred() {
    todo!();
}

/// Show that by default, the account "tobias" can login during
/// fallback mode (matching the behaviour of the daemon)
#[test]
fn pam_fallback_acct_mgmt_default() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let pamh = TestHandler::default();
    let test_time = OffsetDateTime::UNIX_EPOCH;

    assert_eq!(
        core::acct_mgmt(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_SUCCESS
    );
}

/// Test that root can always access the system
#[test]
fn pam_fallback_acct_mgmt_root() {
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

/// Unknown accounts are denied access
#[test]
fn pam_fallback_acct_mgmt_deny_unknown() {
    let req_opt = RequestOptions::fallback_fixture();
    let mut mod_opts = ModuleOptions::default();
    let mut pamh = TestHandler::default();
    pamh.set_account_id("nonexist".to_string());
    let test_time = OffsetDateTime::UNIX_EPOCH;

    assert_eq!(
        core::acct_mgmt(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_USER_UNKNOWN
    );
}

/// Unknown account returns 'ignore' when this option is set
#[test]
fn pam_fallback_acct_mgmt_ignore_unknown() {
    let req_opt = RequestOptions::fallback_fixture();
    let mut mod_opts = ModuleOptions::default();
    mod_opts.ignore_unknown_user = true;
    let mut pamh = TestHandler::default();
    pamh.set_account_id("nonexist".to_string());
    let test_time = OffsetDateTime::UNIX_EPOCH;

    assert_eq!(
        core::acct_mgmt(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_IGNORE
    );
}

/// Exipired accounts are denied
#[test]
fn pam_fallback_acct_mgmt_expired() {
    // Show that an expired account is unable to login.
    let req_opt = RequestOptions::fallback_fixture();
    let mut mod_opts = ModuleOptions::default();
    let pamh = TestHandler::default();
    let test_time = OffsetDateTime::UNIX_EPOCH + time::Duration::days(16);

    assert_eq!(
        core::acct_mgmt(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_ACCT_EXPIRED
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
