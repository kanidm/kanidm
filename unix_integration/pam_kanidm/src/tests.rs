use crate::constants::PamResultCode;
use crate::core::PamHandler;
use crate::core::{self, RequestOptions};
use crate::module::PamResult;
use crate::pam::ModuleOptions;

impl RequestOptions {
    fn fallback_fixture() -> Self {
        RequestOptions::Test { socket: None }
    }
}

#[test]
fn pam_fallback_sm_setcred() {
    struct TestHandler {}

    impl PamHandler for TestHandler {
        fn account_id(&self) -> PamResult<String> {
            Ok("test_account".to_string())
        }
    }

    let req_opt = RequestOptions::fallback_fixture();
    let mod_opts = ModuleOptions::default();

    assert_eq!(
        core::sm_open_session(&TestHandler {}, &mod_opts, req_opt),
        PamResultCode::PAM_SUCCESS
    );
}
