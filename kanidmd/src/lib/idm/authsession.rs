use crate::audit::AuditScope;
use crate::idm::account::Account;
use crate::idm::claim::Claim;
use crate::idm::AuthState;
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::{AuthAllowed, AuthCredential, AuthMech};

use crate::credential::{totp::TOTP, Credential, CredentialType, Password};

use crate::idm::delayed::{DelayedAction, PasswordUpgrade, WebauthnCounterIncrement};
// use crossbeam::channel::Sender;
use tokio::sync::mpsc::UnboundedSender as Sender;

use crate::credential::webauthn::WebauthnDomainConfig;
use std::time::Duration;
use uuid::Uuid;
// use webauthn_rs::proto::Credential as WebauthnCredential;
use webauthn_rs::proto::RequestChallengeResponse;
use webauthn_rs::{AuthenticationState, Webauthn};

// Each CredHandler takes one or more credentials and determines if the
// handlers requirements can be 100% fufilled. This is where MFA or other
// auth policies would exist, but each credHandler has to be a whole
// encapsulated unit of function.

const BAD_PASSWORD_MSG: &str = "incorrect password";
const BAD_TOTP_MSG: &str = "incorrect totp";
const BAD_WEBAUTHN_MSG: &str = "invalid webauthn authentication";
const BAD_AUTH_TYPE_MSG: &str = "invalid authentication method in this context";
const BAD_CREDENTIALS: &str = "invalid credential message";
const ACCOUNT_EXPIRED: &str = "account expired";

enum CredState {
    Success(Vec<Claim>),
    Continue(Vec<AuthAllowed>),
    Denied(&'static str),
}

#[derive(Clone, Debug, PartialEq)]
enum CredVerifyState {
    Init,
    Success,
    Fail,
}

#[derive(Clone, Debug)]
struct CredTotpPw {
    pw: Password,
    pw_state: CredVerifyState,
    totp: TOTP,
    totp_state: CredVerifyState,
}

#[derive(Clone, Debug)]
struct CredWebauthn {
    chal: RequestChallengeResponse,
    wan_state: AuthenticationState,
    state: CredVerifyState,
}

#[derive(Clone, Debug)]
enum CredHandler {
    Anonymous,
    // AppPassword (?)
    Password(Password),
    PasswordMFA(CredTotpPw),
    Webauthn(CredWebauthn),
    // Webauthn + Password
}

impl CredHandler {
    // Is there a nicer implementation of this?
    fn try_from(
        au: &mut AuditScope,
        c: &Credential,
        webauthn: &Webauthn<WebauthnDomainConfig>,
    ) -> Result<Self, ()> {
        match &c.type_ {
            CredentialType::Password(pw) | CredentialType::GeneratedPassword(pw) => {
                Ok(CredHandler::Password(pw.clone()))
            }
            CredentialType::PasswordMFA(pw, Some(totp), _) => {
                Ok(CredHandler::PasswordMFA(CredTotpPw {
                    pw: pw.clone(),
                    pw_state: CredVerifyState::Init,
                    totp: totp.clone(),
                    totp_state: CredVerifyState::Init,
                }))
            }
            CredentialType::PasswordMFA(_, None, _) => Err(()),
            CredentialType::Webauthn(wan) => webauthn
                .generate_challenge_authenticate(wan.values().cloned().collect())
                .map(|(chal, wan_state)| {
                    CredHandler::Webauthn(CredWebauthn {
                        chal,
                        wan_state,
                        state: CredVerifyState::Init,
                    })
                })
                .map_err(|e| {
                    lsecurity!(
                        au,
                        "Unable to create webauthn authentication challenge -> {:?}",
                        e
                    );
                    // maps to unit.
                }),
        }
    }
}

impl CredHandler {
    fn maybe_pw_upgrade(
        au: &mut AuditScope,
        pw: &Password,
        who: Uuid,
        cleartext: &str,
        async_tx: &Sender<DelayedAction>,
    ) {
        if pw.requires_upgrade() {
            if let Err(_e) = async_tx.send(DelayedAction::PwUpgrade(PasswordUpgrade {
                target_uuid: who,
                existing_password: cleartext.to_string(),
                appid: None,
            })) {
                ladmin_warning!(au, "unable to queue delayed pwupgrade, continuing ... ");
            };
        }
    }

    fn validate_anonymous(au: &mut AuditScope, cred: &AuthCredential) -> CredState {
        match cred {
            AuthCredential::Anonymous => {
                // For anonymous, no claims will ever be issued.
                lsecurity!(au, "Handler::Anonymous -> Result::Success");
                CredState::Success(Vec::new())
            }
            _ => {
                lsecurity!(
                    au,
                    "Handler::Anonymous -> Result::Denied - invalid cred type for handler"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    fn validate_password(
        au: &mut AuditScope,
        cred: &AuthCredential,
        pw: &mut Password,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
    ) -> CredState {
        match cred {
            AuthCredential::Password(cleartext) => {
                if pw.verify(cleartext.as_str()).unwrap_or(false) {
                    lsecurity!(au, "Handler::Password -> Result::Success");
                    Self::maybe_pw_upgrade(au, pw, who, cleartext.as_str(), async_tx);
                    CredState::Success(Vec::new())
                } else {
                    lsecurity!(
                        au,
                        "Handler::Password -> Result::Denied - incorrect password"
                    );
                    CredState::Denied(BAD_PASSWORD_MSG)
                }
            }
            // All other cases fail.
            _ => {
                lsecurity!(
                    au,
                    "Handler::Anonymous -> Result::Denied - invalid cred type for handler"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    fn validate_totp_password(
        au: &mut AuditScope,
        cred: &AuthCredential,
        ts: &Duration,
        pw_totp: &mut CredTotpPw,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
    ) -> CredState {
        match (cred, &pw_totp.totp_state, &pw_totp.pw_state) {
            // Must be done first.
            (AuthCredential::TOTP(totp_chal), CredVerifyState::Init, CredVerifyState::Init) => {
                if pw_totp.totp.verify(*totp_chal, ts) {
                    pw_totp.totp_state = CredVerifyState::Success;
                    lsecurity!(
                        au,
                        "Handler::PasswordMFA -> Result::Continue - TOTP OK, password -"
                    );
                    CredState::Continue(vec![AuthAllowed::Password])
                } else {
                    pw_totp.totp_state = CredVerifyState::Fail;
                    lsecurity!(
                        au,
                        "Handler::PasswordMFA -> Result::Denied - TOTP Fail, password -"
                    );
                    CredState::Denied(BAD_TOTP_MSG)
                }
            }
            // Must only proceed if totp was success.
            (
                AuthCredential::Password(cleartext),
                CredVerifyState::Success,
                CredVerifyState::Init,
            ) => {
                if pw_totp.pw.verify(cleartext.as_str()).unwrap_or(false) {
                    pw_totp.pw_state = CredVerifyState::Success;
                    lsecurity!(
                        au,
                        "Handler::PasswordMFA -> Result::Success - TOTP OK, password OK"
                    );
                    Self::maybe_pw_upgrade(au, &pw_totp.pw, who, cleartext.as_str(), async_tx);
                    CredState::Success(Vec::new())
                } else {
                    pw_totp.pw_state = CredVerifyState::Fail;
                    lsecurity!(
                        au,
                        "Handler::PasswordMFA -> Result::Denied - TOTP OK, password Fail"
                    );
                    CredState::Denied(BAD_PASSWORD_MSG)
                }
            }
            _ => {
                lsecurity!(
                    au,
                    "Handler::PasswordMFA -> Result::Denied - invalid cred type for handler"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    } // end CredHandler::PasswordMFA

    pub fn validate_webauthn(
        au: &mut AuditScope,
        cred: &AuthCredential,
        wan_cred: &mut CredWebauthn,
        webauthn: &Webauthn<WebauthnDomainConfig>,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
    ) -> CredState {
        if wan_cred.state != CredVerifyState::Init {
            lsecurity!(
                au,
                "Handler::Webauthn -> Result::Denied - Internal State Already Fail"
            );
            return CredState::Denied(BAD_WEBAUTHN_MSG);
        }

        match cred {
            AuthCredential::Webauthn(resp) => {
                // lets see how we go.
                webauthn.authenticate_credential(&resp, wan_cred.wan_state.clone())
                    .map(|r| {
                        wan_cred.state = CredVerifyState::Success;
                        // Success. Determine if we need to update the counter
                        // async from r.
                        if let Some((cid, counter)) = r {
                            // Do async
                            if let Err(_e) = async_tx.send(DelayedAction::WebauthnCounterIncrement(WebauthnCounterIncrement {
                                target_uuid: who,
                                cid,
                                counter,
                            })) {
                                ladmin_warning!(au, "unable to queue delayed webauthn counter increment, continuing ... ");
                            };
                        };
                        CredState::Success(Vec::new())
                    })
                    .unwrap_or_else(|e| {
                        wan_cred.state = CredVerifyState::Fail;
                        // Denied.
                        lsecurity!(au, "Handler::Webauthn -> Result::Denied - webauthn error {:?}", e);
                        CredState::Denied(BAD_WEBAUTHN_MSG)
                    })
            }
            _ => {
                lsecurity!(
                    au,
                    "Handler::Webauthn -> Result::Denied - invalid cred type for handler"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    pub fn validate(
        &mut self,
        au: &mut AuditScope,
        cred: &AuthCredential,
        ts: &Duration,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
        webauthn: &Webauthn<WebauthnDomainConfig>,
    ) -> CredState {
        match self {
            CredHandler::Anonymous => Self::validate_anonymous(au, cred),
            CredHandler::Password(ref mut pw) => {
                Self::validate_password(au, cred, pw, who, async_tx)
            }
            CredHandler::PasswordMFA(ref mut pw_totp) => {
                Self::validate_totp_password(au, cred, ts, pw_totp, who, async_tx)
            }
            CredHandler::Webauthn(ref mut wan_cred) => {
                Self::validate_webauthn(au, cred, wan_cred, webauthn, who, async_tx)
            }
        }
    }

    pub fn next_auth_allowed(&self) -> Vec<AuthAllowed> {
        match &self {
            CredHandler::Anonymous => vec![AuthAllowed::Anonymous],
            CredHandler::Password(_) => vec![AuthAllowed::Password],
            // webauth
            // mfa
            CredHandler::PasswordMFA(_) => vec![AuthAllowed::Password, AuthAllowed::TOTP],
            CredHandler::Webauthn(webauthn) => vec![AuthAllowed::Webauthn(webauthn.chal.clone())],
        }
    }

    fn can_proceed(&self, mech: &AuthMech) -> bool {
        match (self, mech) {
            (CredHandler::Anonymous, AuthMech::Anonymous)
            | (CredHandler::Password(_), AuthMech::Password)
            | (CredHandler::PasswordMFA(_), AuthMech::PasswordMFA)
            | (CredHandler::Webauthn(_), AuthMech::Webauthn) => true,
            (_, _) => false,
        }
    }

    fn allows_mech(&self) -> AuthMech {
        match self {
            CredHandler::Anonymous => AuthMech::Anonymous,
            CredHandler::Password(_) => AuthMech::Password,
            CredHandler::PasswordMFA(_) => AuthMech::PasswordMFA,
            CredHandler::Webauthn(_) => AuthMech::Webauthn,
        }
    }
}

#[derive(Clone)]
/// This interleaves with the client auth step. The client sends an "init"
/// and we go to the init state, sending back the list of what can proceed.
/// The client then sends a "begin" with the chosen mech that moves to
/// "InProgress", "Success" or "Denied". From there the CredHandler
/// is interacted with until we move to either "Success" or "Denied".
enum AuthSessionState {
    Init(Vec<CredHandler>),
    // Stop! Don't make this a vec - make the credhandler able to hold multiple
    // internal copies of it's type and check against them all.
    InProgress(CredHandler),
    Success,
    Denied(&'static str),
}

impl AuthSessionState {
    fn is_denied(&self) -> Option<&'static str> {
        match &self {
            AuthSessionState::Denied(x) => Some(x),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct AuthSession {
    // Do we store a copy of the entry?
    // How do we know what claims to add?
    account: Account,
    // Store how we plan to handle this sessions authentication: this is generally
    // made apparent by the presentation of an application id or not. If none is presented
    // we want the primary-interaction credentials.
    //
    // This handler will then handle the mfa and stepping up through to generate the auth states
    state: AuthSessionState,
}

impl AuthSession {
    pub fn new(
        au: &mut AuditScope,
        account: Account,
        _appid: &Option<String>,
        webauthn: &Webauthn<WebauthnDomainConfig>,
        ct: Duration,
    ) -> (Option<Self>, AuthState) {
        // During this setup, determine the credential handler that we'll be using
        // for this session. This is currently based on presentation of an application
        // id.
        let state = if account.is_within_valid_time(ct) {
            // We want the primary handler - this is where we make a decision
            // based on the anonymous ... in theory this could be cleaner
            // and interact with the account more?
            if account.is_anonymous() {
                AuthSessionState::Init(vec![CredHandler::Anonymous])
            } else {
                // Now we see if they have one ...
                match &account.primary {
                    Some(cred) => {
                        // TODO: Make it possible to have multiple creds.
                        // Probably means new authsession has to be failable
                        CredHandler::try_from(au, cred, webauthn)
                            .map(|ch| AuthSessionState::Init(vec![ch]))
                            .unwrap_or_else(|_| {
                                lsecurity_critical!(
                                    au,
                                    "corrupt credentials, unable to start credhandler"
                                );
                                AuthSessionState::Denied("invalid credential state")
                            })
                    }
                    None => {
                        lsecurity!(au, "account has no primary credentials");
                        AuthSessionState::Denied("invalid credential state")
                    }
                }
            }
        } else {
            lsecurity!(au, "account expired");
            AuthSessionState::Denied(ACCOUNT_EXPIRED)
        };

        // if credhandler == deny, finish = true.
        if let Some(reason) = state.is_denied() {
            // Already denied, lets send that result
            (None, AuthState::Denied(reason.to_string()))
        } else {
            // We can proceed
            let auth_session = AuthSession { account, state };
            // Get the set of mechanisms that can proceed. This is tied
            // to the session so that it can mutate state and have progression
            // of what's next, or ordering.
            let valid_mechs = auth_session.valid_auth_mechs();

            let as_state = AuthState::Choose(valid_mechs);
            (Some(auth_session), as_state)
        }
    }

    pub fn get_account(&self) -> &Account {
        &self.account
    }

    pub fn start_session(
        &mut self,
        _au: &mut AuditScope,
        mech: &AuthMech,
        // time: &Duration,
        // webauthn: &Webauthn<WebauthnDomainConfig>,
    ) -> Result<AuthState, OperationError> {
        // Given some auth mech, select which credential(s) are apropriate
        // and attempt to use them.

        // Today we only select one, but later we could have *multiple* that
        // match the selector.
        let (next_state, response) = match &mut self.state {
            AuthSessionState::Success
            | AuthSessionState::Denied(_)
            | AuthSessionState::InProgress(_) => (
                None,
                Err(OperationError::InvalidAuthState(
                    "session already finalised!".to_string(),
                )),
            ),
            AuthSessionState::Init(handlers) => {
                // Which handlers are relevant?
                let mut allowed_handlers: Vec<_> = handlers
                    .iter()
                    .filter(|ch| ch.can_proceed(mech))
                    .cloned()
                    .collect();

                if let Some(allowed_handler) = allowed_handlers.pop() {
                    let allowed: Vec<_> = allowed_handler.next_auth_allowed();

                    if allowed.is_empty() {
                        (
                            None,
                            Err(OperationError::InvalidAuthState(
                                "unable to negotitate credentials".to_string(),
                            )),
                        )
                    } else {
                        (
                            Some(AuthSessionState::InProgress(allowed_handler)),
                            Ok(AuthState::Continue(allowed)),
                        )
                    }
                } else {
                    (
                        Some(AuthSessionState::Denied(BAD_CREDENTIALS)),
                        Ok(AuthState::Denied(BAD_CREDENTIALS.to_string())),
                    )
                }
            }
        };

        if let Some(mut next_state) = next_state {
            std::mem::swap(&mut self.state, &mut next_state);
        };

        response
    }

    // This should return a AuthResult or similar state of checking?
    pub fn validate_creds(
        &mut self,
        au: &mut AuditScope,
        cred: &AuthCredential,
        time: &Duration,
        async_tx: &Sender<DelayedAction>,
        webauthn: &Webauthn<WebauthnDomainConfig>,
    ) -> Result<AuthState, OperationError> {
        let (next_state, response) = match &mut self.state {
            AuthSessionState::Init(_) | AuthSessionState::Success | AuthSessionState::Denied(_) => {
                return Err(OperationError::InvalidAuthState(
                    "session already finalised!".to_string(),
                ));
            }
            AuthSessionState::InProgress(ref mut handler) => {
                match handler.validate(au, cred, time, self.account.uuid, async_tx, webauthn) {
                    CredState::Success(claims) => {
                        lsecurity!(au, "Successful cred handling");
                        let uat = self
                            .account
                            .to_userauthtoken(&claims)
                            .ok_or(OperationError::InvalidState)?;

                        // Now encrypt and prepare the token for return to the client.
                        (Some(AuthSessionState::Success), Ok(AuthState::Success(uat)))
                    }
                    CredState::Continue(allowed) => {
                        lsecurity!(au, "Request credential continuation: {:?}", allowed);
                        (None, Ok(AuthState::Continue(allowed)))
                    }
                    CredState::Denied(reason) => {
                        lsecurity!(au, "Credentials denied: {}", reason);
                        (
                            Some(AuthSessionState::Denied(reason)),
                            Ok(AuthState::Denied(reason.to_string())),
                        )
                    }
                }
            }
        };

        if let Some(mut next_state) = next_state {
            std::mem::swap(&mut self.state, &mut next_state);
        };

        // Also send an async message to self to log the auth as provided.
        // Alternately, open a write, and commit the needed security metadata here
        // now rather than async (probably better for lock-outs etc)
        //
        // TODO #59: Async message the account owner about the login?
        // If this fails, how can we in memory lock the account?
        //
        // The lockouts could also be an in-memory concept too?

        // If this suceeds audit?
        //  If success, to authtoken?

        response
    }

    pub fn end_session(&mut self, reason: &'static str) -> Result<AuthState, OperationError> {
        let mut next_state = AuthSessionState::Denied(reason);
        std::mem::swap(&mut self.state, &mut next_state);
        Ok(AuthState::Denied(reason.to_string()))
    }

    fn valid_auth_mechs(&self) -> Vec<AuthMech> {
        match &self.state {
            AuthSessionState::Success
            | AuthSessionState::Denied(_)
            | AuthSessionState::InProgress(_) => Vec::new(),
            AuthSessionState::Init(handlers) => {
                // Iterate over the handlers into what mechs they are
                // and filter to unique?
                handlers.iter().map(|h| h.allows_mech()).collect()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::AuditScope;
    use crate::constants::{JSON_ADMIN_V1, JSON_ANONYMOUS_V1};
    use crate::credential::policy::CryptoPolicy;
    use crate::credential::totp::{TOTP, TOTP_DEFAULT_STEP};
    use crate::credential::webauthn::WebauthnDomainConfig;
    use crate::credential::Credential;
    use crate::idm::authsession::{
        AuthSession, BAD_AUTH_TYPE_MSG, BAD_PASSWORD_MSG, BAD_TOTP_MSG, BAD_WEBAUTHN_MSG,
    };
    use crate::idm::delayed::DelayedAction;
    use crate::idm::AuthState;
    use crate::utils::duration_from_epoch_now;
    use kanidm_proto::v1::{AuthAllowed, AuthCredential, AuthMech};
    use std::time::Duration;
    use webauthn_rs::proto::UserVerificationPolicy;
    use webauthn_rs::Webauthn;

    use tokio::sync::mpsc::unbounded_channel as unbounded;
    use webauthn_authenticator_rs::{softtok::U2FSoft, WebauthnAuthenticator};

    fn create_webauthn() -> Webauthn<WebauthnDomainConfig> {
        Webauthn::new(WebauthnDomainConfig {
            rp_name: "example.com".to_string(),
            origin: "https://idm.example.com".to_string(),
            rp_id: "example.com".to_string(),
        })
    }

    #[test]
    fn test_idm_authsession_anonymous_auth_mech() {
        let mut audit = AuditScope::new(
            "test_idm_authsession_anonymous_auth_mech",
            uuid::Uuid::new_v4(),
            None,
        );
        let webauthn = create_webauthn();

        let anon_account = entry_str_to_account!(JSON_ANONYMOUS_V1);

        let (session, state) = AuthSession::new(
            &mut audit,
            anon_account,
            None,
            &webauthn,
            duration_from_epoch_now(),
        );

        if let AuthState::Choose(auth_mechs) = state {
            assert!(
                true == auth_mechs.iter().fold(false, |acc, x| match x {
                    AuthMech::Anonymous => true,
                    _ => acc,
                })
            );
        } else {
            panic!("Invalid auth state")
        }

        let state = session
            .expect("Missing auth session?")
            .start_session(&mut audit, &AuthMech::Anonymous)
            .expect("Failed to select anonymous mech.");

        if let AuthState::Continue(auth_mechs) = state {
            assert!(
                true == auth_mechs.iter().fold(false, |acc, x| match x {
                    AuthAllowed::Anonymous => true,
                    _ => acc,
                })
            );
        } else {
            panic!("Invalid auth state")
        }
    }

    // Deprecated, will remove later.
    #[test]
    fn test_idm_authsession_missing_appid() {
        let webauthn = create_webauthn();
        let anon_account = entry_str_to_account!(JSON_ANONYMOUS_V1);
        let mut audit = AuditScope::new(
            "test_idm_authsession_missing_appid",
            uuid::Uuid::new_v4(),
            None,
        );

        let (session, state) = AuthSession::new(
            &mut audit,
            anon_account,
            Some("NonExistantAppID".to_string()),
            &webauthn,
            duration_from_epoch_now(),
        );

        // We now ignore appids.
        assert!(session.is_some());

        if let AuthState::Choose(_) = state {
            // Pass
        } else {
            panic!();
        }
    }

    macro_rules! start_password_session {
        (
            $audit:expr,
            $account:expr,
            $webauthn:expr
        ) => {{
            let (session, state) = AuthSession::new(
                $audit,
                $account.clone(),
                None,
                $webauthn,
                duration_from_epoch_now(),
            );
            let mut session = session.unwrap();

            if let AuthState::Choose(auth_mechs) = state {
                assert!(
                    true == auth_mechs.iter().fold(false, |acc, x| match x {
                        AuthMech::Password => true,
                        _ => acc,
                    })
                );
            } else {
                panic!();
            }

            let state = session
                .start_session($audit, &AuthMech::Password)
                .expect("Failed to select anonymous mech.");

            if let AuthState::Continue(auth_mechs) = state {
                assert!(
                    true == auth_mechs.iter().fold(false, |acc, x| match x {
                        AuthAllowed::Password => true,
                        _ => acc,
                    })
                );
            } else {
                panic!("Invalid auth state")
            }

            session
        }};
    }

    #[test]
    fn test_idm_authsession_simple_password_mech() {
        let mut audit = AuditScope::new(
            "test_idm_authsession_simple_password_mech",
            uuid::Uuid::new_v4(),
            None,
        );
        let webauthn = create_webauthn();
        // create the ent
        let mut account = entry_str_to_account!(JSON_ADMIN_V1);
        // manually load in a cred
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "test_password").unwrap();
        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();

        // now check
        let mut session = start_password_session!(&mut audit, account, &webauthn);

        let attempt = AuthCredential::Password("bad_password".to_string());
        match session.validate_creds(
            &mut audit,
            &attempt,
            &Duration::from_secs(0),
            &async_tx,
            &webauthn,
        ) {
            Ok(AuthState::Denied(_)) => {}
            _ => panic!(),
        };

        // === Now begin a new session, and use a good pw.

        let mut session = start_password_session!(&mut audit, account, &webauthn);

        let attempt = AuthCredential::Password("test_password".to_string());
        match session.validate_creds(
            &mut audit,
            &attempt,
            &Duration::from_secs(0),
            &async_tx,
            &webauthn,
        ) {
            Ok(AuthState::Success(_)) => {}
            _ => panic!(),
        };
        assert!(async_rx.try_recv().is_err());

        audit.write_log();
    }

    macro_rules! start_password_mfa_session {
        (
            $audit:expr,
            $account:expr,
            $webauthn:expr
        ) => {{
            let (session, state) = AuthSession::new(
                $audit,
                $account.clone(),
                None,
                $webauthn,
                duration_from_epoch_now(),
            );
            let mut session = session.unwrap();

            if let AuthState::Choose(auth_mechs) = state {
                assert!(
                    true == auth_mechs.iter().fold(false, |acc, x| match x {
                        AuthMech::PasswordMFA => true,
                        _ => acc,
                    })
                );
            } else {
                panic!();
            }

            let state = session
                .start_session($audit, &AuthMech::PasswordMFA)
                .expect("Failed to select anonymous mech.");

            if let AuthState::Continue(auth_mechs) = state {
                assert!(
                    true == auth_mechs.iter().fold(false, |acc, x| match x {
                        // TODO: How to return webauthn chal?
                        AuthAllowed::TOTP => true,
                        _ => acc,
                    })
                );
            } else {
                panic!("Invalid auth state")
            }

            session
        }};
    }

    #[test]
    fn test_idm_authsession_totp_password_mech() {
        let mut audit = AuditScope::new(
            "test_idm_authsession_totp_password_mech",
            uuid::Uuid::new_v4(),
            None,
        );
        let webauthn = create_webauthn();
        // create the ent
        let mut account = entry_str_to_account!(JSON_ADMIN_V1);

        // Setup a fake time stamp for consistency.
        let ts = Duration::from_secs(12345);

        // manually load in a cred
        let totp = TOTP::generate_secure("test_totp".to_string(), TOTP_DEFAULT_STEP);

        let totp_good = totp
            .do_totp_duration_from_epoch(&ts)
            .expect("failed to perform totp.");
        let totp_bad = totp
            .do_totp_duration_from_epoch(&Duration::from_secs(1234567))
            .expect("failed to perform totp.");
        assert!(totp_bad != totp_good);

        let pw_good = "test_password";
        let pw_bad = "bad_password";

        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw_good)
            .unwrap()
            .update_totp(totp);
        // add totp also
        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();

        // now check

        // check send anon (fail)
        {
            let mut session = start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Anonymous,
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };
        }

        // == two step checks

        // Sending a PW first is an immediate fail.
        {
            let mut session = start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Password(pw_bad.to_string()),
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };
        }
        // check send bad totp, should fail immediate
        {
            let mut session = start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::TOTP(totp_bad),
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_TOTP_MSG),
                _ => panic!(),
            };
        }

        // check send good totp, should continue
        //      then bad pw, fail pw
        {
            let mut session = start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::TOTP(totp_good),
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &AuthCredential::Password(pw_bad.to_string()),
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };
        }

        // check send good totp, should continue
        //      then good pw, success
        {
            let mut session = start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::TOTP(totp_good),
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &AuthCredential::Password(pw_good.to_string()),
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };
        }

        assert!(async_rx.try_recv().is_err());
        audit.write_log();
    }

    macro_rules! start_webauthn_only_session {
        (
            $audit:expr,
            $account:expr,
            $webauthn:expr
        ) => {{
            let (session, state) = AuthSession::new(
                $audit,
                $account.clone(),
                None,
                $webauthn,
                duration_from_epoch_now(),
            );
            let mut session = session.unwrap();

            if let AuthState::Choose(auth_mechs) = state {
                assert!(
                    true == auth_mechs.iter().fold(false, |acc, x| match x {
                        AuthMech::Webauthn => true,
                        _ => acc,
                    })
                );
            } else {
                panic!();
            }

            let state = session
                .start_session($audit, &AuthMech::Webauthn)
                .expect("Failed to select Webauthn mech.");

            let wan_chal = if let AuthState::Continue(auth_mechs) = state {
                assert!(auth_mechs.len() == 1);
                auth_mechs
                    .into_iter()
                    .fold(None, |_acc, x| match x {
                        AuthAllowed::Webauthn(chal) => Some(chal),
                        _ => None,
                    })
                    .expect("No webauthn challenge found.")
            } else {
                panic!();
            };

            (session, wan_chal)
        }};
    }

    #[test]
    fn test_idm_authsession_webauthn_only_mech() {
        let mut audit = AuditScope::new(
            "test_idm_authsession_webauthn_mech",
            uuid::Uuid::new_v4(),
            None,
        );
        let webauthn = create_webauthn();
        let (async_tx, mut async_rx) = unbounded();
        let ts = duration_from_epoch_now();
        // create the ent
        let mut account = entry_str_to_account!(JSON_ADMIN_V1);

        // Setup a soft token
        let mut wa = WebauthnAuthenticator::new(U2FSoft::new());

        let (chal, reg_state) = webauthn
            .generate_challenge_register(&account.name, Some(UserVerificationPolicy::Discouraged))
            .expect("Failed to setup webauthn rego challenge");

        let r = wa
            .do_registration("https://idm.example.com", chal)
            .expect("Failed to create soft token");

        let wan_cred = webauthn
            .register_credential(&r, reg_state, |_| Ok(false))
            .expect("Failed to register soft token");

        // Now create the credential for the account.
        let cred = Credential::new_webauthn_only("soft".to_string(), wan_cred);
        account.primary = Some(cred);

        // now check correct mech was offered. we stash this challenge for later
        // to help generate a failure.
        let (_session, inv_chal) = start_webauthn_only_session!(&mut audit, account, &webauthn);

        // check send anon (fail)
        {
            let (mut session, _inv_chal) =
                start_webauthn_only_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Anonymous,
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };
        }

        // Check good challenge
        {
            let (mut session, chal) = start_webauthn_only_session!(&mut audit, account, &webauthn);

            let resp = wa
                .do_authentication("https://idm.example.com", chal)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Webauthn(resp),
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };
        }

        // Check the async counter update was sent.
        match async_rx.try_recv() {
            Ok(DelayedAction::WebauthnCounterIncrement(_)) => {}
            _ => assert!(false),
        }

        // Check bad challenge.
        {
            let (mut session, _chal) = start_webauthn_only_session!(&mut audit, account, &webauthn);

            let resp = wa
                // HERE -> we use inv_chal instead.
                .do_authentication("https://idm.example.com", inv_chal)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Webauthn(resp),
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_WEBAUTHN_MSG),
                _ => panic!(),
            };
        }

        // Use an incorrect softtoken.
        {
            let mut inv_wa = WebauthnAuthenticator::new(U2FSoft::new());
            let (chal, reg_state) = webauthn
                .generate_challenge_register(
                    &account.name,
                    Some(UserVerificationPolicy::Discouraged),
                )
                .expect("Failed to setup webauthn rego challenge");

            let r = inv_wa
                .do_registration("https://idm.example.com", chal)
                .expect("Failed to create soft token");

            let inv_cred = webauthn
                .register_credential(&r, reg_state, |_| Ok(false))
                .expect("Failed to register soft token");

            // Discard the auth_state, we only need the invalid challenge.
            let (chal, _auth_state) = webauthn
                .generate_challenge_authenticate(vec![inv_cred])
                .expect("Failed to generate challenge for in inv softtoken");

            // Create the response.
            let resp = inv_wa
                .do_authentication("https://idm.example.com", chal)
                .expect("Failed to use softtoken for response.");

            let (mut session, _chal) = start_webauthn_only_session!(&mut audit, account, &webauthn);
            // Ignore the real cred, use the diff cred. Normally this shouldn't even
            // get this far, because the client should identify that the cred id's are
            // not inline.
            match session.validate_creds(
                &mut audit,
                &AuthCredential::Webauthn(resp),
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_WEBAUTHN_MSG),
                _ => panic!(),
            };
        }

        assert!(async_rx.try_recv().is_err());
        audit.write_log();
    }
}
