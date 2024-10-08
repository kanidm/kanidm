use crate::constants::PamResultCode;
use crate::core::PamHandler;
use crate::core::{self, RequestOptions};
use crate::module::PamResult;
use crate::pam::ModuleOptions;
use kanidm_unix_common::unix_passwd::{CryptPw, EtcShadow, EtcUser};
use kanidm_unix_common::unix_proto::{DeviceAuthorizationResponse, PamServiceInfo};
use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::Mutex;
use time::OffsetDateTime;

impl RequestOptions {
    fn fallback_fixture() -> Self {
        RequestOptions::Test {
            socket: None,
            users: vec![
                EtcUser {
                    name: "root".to_string(),
                    password: "x".to_string(),
                    uid: 0,
                    gid: 0,
                    gecos: "Root".to_string(),
                    homedir: "/root".to_string(),
                    shell: "/bin/bash".to_string(),
                },
                EtcUser {
                    name: "tobias".to_string(),
                    password: "x".to_string(),
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
                    // The very secure password, 'a'
                    password: CryptPw::from_str("$6$5.bXZTIXuVv.xI3.$sAubscCJPwnBWwaLt2JR33lo539UyiDku.aH5WVSX0Tct9nGL2ePMEmrqT3POEdBlgNQ12HJBwskewGu2dpF//").unwrap(),
                    ..Default::default()
                },
                EtcShadow {
                    name: "tobias".to_string(),
                    // The very secure password, 'a'
                    password: CryptPw::from_str("$6$5.bXZTIXuVv.xI3.$sAubscCJPwnBWwaLt2JR33lo539UyiDku.aH5WVSX0Tct9nGL2ePMEmrqT3POEdBlgNQ12HJBwskewGu2dpF//").unwrap(),
                    epoch_expire_date: Some(10),
                    ..Default::default()
                },
            ],
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
enum Event {
    Account(&'static str),
    ServiceInfo(PamServiceInfo),
    PromptPassword(&'static str),
    StackedAuthtok(Option<&'static str>),
}

struct TestHandler {
    response_queue: Mutex<VecDeque<Event>>,
}

impl Default for TestHandler {
    fn default() -> Self {
        TestHandler {
            response_queue: Default::default(),
        }
    }
}

impl From<Vec<Event>> for TestHandler {
    fn from(v: Vec<Event>) -> Self {
        TestHandler {
            response_queue: Mutex::new(v.into_iter().collect()),
        }
    }
}

impl Drop for TestHandler {
    fn drop(&mut self) {
        let q = self.response_queue.lock().unwrap();
        assert!(q.is_empty());
    }
}

impl PamHandler for TestHandler {
    fn account_id(&self) -> PamResult<String> {
        let mut q = self.response_queue.lock().unwrap();
        match q.pop_front() {
            Some(Event::Account(name)) => Ok(name.to_string()),
            e => {
                eprintln!("{:?}", e);
                panic!("Invalid event transition");
            }
        }
    }

    fn service_info(&self) -> PamResult<PamServiceInfo> {
        let mut q = self.response_queue.lock().unwrap();
        match q.pop_front() {
            Some(Event::ServiceInfo(info)) => Ok(info),
            e => {
                eprintln!("{:?}", e);
                panic!("Invalid event transition");
            }
        }
    }

    fn authtok(&self) -> PamResult<Option<String>> {
        let mut q = self.response_queue.lock().unwrap();
        match q.pop_front() {
            Some(Event::StackedAuthtok(Some(v))) => Ok(Some(v.to_string())),
            Some(Event::StackedAuthtok(None)) => Ok(None),
            e => {
                eprintln!("{:?}", e);
                panic!("Invalid event transition");
            }
        }
    }

    /// Display a message to the user.
    fn message(&self, _prompt: &str) -> PamResult<()> {
        let mut q = self.response_queue.lock().unwrap();
        match q.pop_front() {
            e => {
                eprintln!("{:?}", e);
                panic!("Invalid event transition");
            }
        }
    }

    /// Display a device grant request to the user.
    fn message_device_grant(&self, _data: &DeviceAuthorizationResponse) -> PamResult<()> {
        let mut q = self.response_queue.lock().unwrap();
        match q.pop_front() {
            e => {
                eprintln!("{:?}", e);
                panic!("Invalid event transition");
            }
        }
    }

    /// Request a password from the user.
    fn prompt_for_password(&self) -> PamResult<Option<String>> {
        let mut q = self.response_queue.lock().unwrap();
        match q.pop_front() {
            Some(Event::PromptPassword(value)) => Ok(Some(value.to_string())),
            e => {
                eprintln!("{:?}", e);
                panic!("Invalid event transition");
            }
        }
    }

    fn prompt_for_pin(&self) -> PamResult<Option<String>> {
        let mut q = self.response_queue.lock().unwrap();
        match q.pop_front() {
            e => {
                eprintln!("{:?}", e);
                panic!("Invalid event transition");
            }
        }
    }

    fn prompt_for_mfacode(&self) -> PamResult<Option<String>> {
        let mut q = self.response_queue.lock().unwrap();
        match q.pop_front() {
            e => {
                eprintln!("{:?}", e);
                panic!("Invalid event transition");
            }
        }
    }
}

/// Show that a user can authenticate with the correct password
#[test]
fn pam_fallback_sm_authenticate_default() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let test_time = OffsetDateTime::UNIX_EPOCH;

    let pamh = TestHandler::from(vec![Event::Account("tobias"), Event::PromptPassword("a")]);

    assert_eq!(
        core::sm_authenticate(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_SUCCESS
    );
}

/// Show that incorrect pw fails
#[test]
fn pam_fallback_sm_authenticate_incorrect_pw() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let test_time = OffsetDateTime::UNIX_EPOCH;

    let pamh = TestHandler::from(vec![
        Event::Account("tobias"),
        Event::PromptPassword("wrong"),
    ]);

    assert_eq!(
        core::sm_authenticate(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_AUTH_ERR
    );
}

/// Show that root can authenticate with the correct password
#[test]
fn pam_fallback_sm_authenticate_root() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let test_time = OffsetDateTime::UNIX_EPOCH;

    let pamh = TestHandler::from(vec![Event::Account("root"), Event::PromptPassword("a")]);

    assert_eq!(
        core::sm_authenticate(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_SUCCESS
    );
}

/// Show that incorrect root pw fails
#[test]
fn pam_fallback_sm_authenticate_root_incorrect_pw() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let test_time = OffsetDateTime::UNIX_EPOCH;

    let pamh = TestHandler::from(vec![Event::Account("root"), Event::PromptPassword("wrong")]);

    assert_eq!(
        core::sm_authenticate(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_AUTH_ERR
    );
}

/// Show that an expired account does not prompt for pw at all.
#[test]
fn pam_fallback_sm_authenticate_expired() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let test_time = OffsetDateTime::UNIX_EPOCH + time::Duration::days(16);

    let pamh = TestHandler::from(vec![Event::Account("tobias")]);

    assert_eq!(
        core::sm_authenticate(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_ACCT_EXPIRED
    );
}

/// Show that unknown users are denied
#[test]
fn pam_fallback_sm_authenticate_unknown_denied() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let test_time = OffsetDateTime::UNIX_EPOCH;

    let pamh = TestHandler::from(vec![Event::Account("nonexist")]);

    assert_eq!(
        core::sm_authenticate(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_USER_UNKNOWN
    );
}

/// Show that unknown users are ignored when the setting is enabled.
#[test]
fn pam_fallback_sm_authenticate_unknown_ignore() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions {
        ignore_unknown_user: true,
        ..Default::default()
    };
    let test_time = OffsetDateTime::UNIX_EPOCH;

    let pamh = TestHandler::from(vec![Event::Account("nonexist")]);

    assert_eq!(
        core::sm_authenticate(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_IGNORE
    );
}

/// If there is a stacked cred and use_first_pass is set, it is consumed.
#[test]
fn pam_fallback_sm_authenticate_stacked_cred() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions {
        use_first_pass: true,
        ..Default::default()
    };
    let test_time = OffsetDateTime::UNIX_EPOCH;

    let pamh = TestHandler::from(vec![
        Event::Account("tobias"),
        Event::StackedAuthtok(Some("a")),
    ]);

    assert_eq!(
        core::sm_authenticate(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_SUCCESS
    );
}

/// If there is no stacked credential in pam, then one is prompted for
#[test]
fn pam_fallback_sm_authenticate_no_stacked_cred() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions {
        use_first_pass: true,
        ..Default::default()
    };
    let test_time = OffsetDateTime::UNIX_EPOCH;

    let pamh = TestHandler::from(vec![
        Event::Account("tobias"),
        Event::StackedAuthtok(None),
        Event::PromptPassword("a"),
    ]);

    assert_eq!(
        core::sm_authenticate(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_SUCCESS
    );
}

/// Show that by default, the account "tobias" can login during
/// fallback mode (matching the behaviour of the daemon)
#[test]
fn pam_fallback_acct_mgmt_default() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let test_time = OffsetDateTime::UNIX_EPOCH;

    let pamh = TestHandler::from(vec![Event::Account("tobias")]);

    assert_eq!(
        core::acct_mgmt(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_SUCCESS
    );
}

/// Test that root can always access the system
#[test]
fn pam_fallback_acct_mgmt_root() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let test_time = OffsetDateTime::UNIX_EPOCH;

    let pamh = TestHandler::from(vec![Event::Account("root")]);

    assert_eq!(
        core::acct_mgmt(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_SUCCESS
    );
}

/// Unknown accounts are denied access
#[test]
fn pam_fallback_acct_mgmt_deny_unknown() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();
    let test_time = OffsetDateTime::UNIX_EPOCH;

    let pamh = TestHandler::from(vec![Event::Account("nonexist")]);

    assert_eq!(
        core::acct_mgmt(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_USER_UNKNOWN
    );
}

/// Unknown account returns 'ignore' when this option is set
#[test]
fn pam_fallback_acct_mgmt_ignore_unknown() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions {
        ignore_unknown_user: true,
        ..Default::default()
    };
    let test_time = OffsetDateTime::UNIX_EPOCH;

    let pamh = TestHandler::from(vec![Event::Account("nonexist")]);

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
    let mod_opts = ModuleOptions::default();
    let test_time = OffsetDateTime::UNIX_EPOCH + time::Duration::days(16);

    let pamh = TestHandler::from(vec![Event::Account("tobias")]);

    assert_eq!(
        core::acct_mgmt(&pamh, &mod_opts, req_opt, test_time),
        PamResultCode::PAM_ACCT_EXPIRED
    );
}

#[test]
fn pam_fallback_sm_open_session() {
    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();

    let pamh = TestHandler::from(vec![Event::Account("tobias")]);

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
