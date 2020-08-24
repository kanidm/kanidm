use crate::audit::AuditScope;
use crate::idm::account::Account;
use crate::idm::claim::Claim;
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::{AuthAllowed, AuthCredential, AuthState};

use crate::credential::{totp::TOTP, Credential, Password};

use crate::idm::delayed::{DelayedAction, PasswordUpgrade};
// use crossbeam::channel::Sender;
use tokio::sync::mpsc::UnboundedSender as Sender;

use std::convert::TryFrom;
use std::time::Duration;
use uuid::Uuid;

// Each CredHandler takes one or more credentials and determines if the
// handlers requirements can be 100% fufilled. This is where MFA or other
// auth policies would exist, but each credHandler has to be a whole
// encapsulated unit of function.

const BAD_PASSWORD_MSG: &str = "incorrect password";
const BAD_TOTP_MSG: &str = "incorrect totp";
const BAD_AUTH_TYPE_MSG: &str = "invalid authentication method in this context";
const BAD_CREDENTIALS: &str = "invalid credential message";

enum CredState {
    Success(Vec<Claim>),
    Continue(Vec<AuthAllowed>),
    Denied(&'static str),
}

#[derive(Clone, Debug)]
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
enum CredHandler {
    Denied,
    // The bool is a flag if the cred has been authed against.
    Anonymous,
    // AppPassword
    // {
    // Password
    Password(Password),
    // Webauthn
    // Webauthn + Password
    TOTPPassword(CredTotpPw),
}

impl TryFrom<&Credential> for CredHandler {
    type Error = ();
    // Is there a nicer implementation of this?
    fn try_from(c: &Credential) -> Result<Self, Self::Error> {
        match (c.password.as_ref(), c.totp.as_ref()) {
            (Some(pw), None) => Ok(CredHandler::Password(pw.clone())),
            (Some(pw), Some(totp)) => Ok(CredHandler::TOTPPassword(CredTotpPw {
                pw: pw.clone(),
                pw_state: CredVerifyState::Init,
                totp: totp.clone(),
                totp_state: CredVerifyState::Init,
            })),
            // Must be an invalid set of credentials. WTF?
            _ => Err(()),
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

    fn validate_anonymous(au: &mut AuditScope, creds: &[AuthCredential]) -> CredState {
        creds.iter().fold(
            CredState::Continue(vec![AuthAllowed::Anonymous]),
            |acc, cred| {
                // There is no "continuation" from this type - we only set it at
                // the start assuming there is no values in the iter so we can tell
                // the session to continue up to some timelimit.
                match acc {
                    // If denied, continue returning denied.
                    CredState::Denied(_) => {
                        lsecurity!(au, "Handler::Anonymous -> Result::Denied - already denied");
                        acc
                    }
                    // We have a continue or success, it's important we keep checking here
                    // after the success, because if they sent "multiple" anonymous or
                    // they sent anon + password, we need to handle both cases. Double anon
                    // is okay, but anything else is instant failure, even if we already
                    // had a success.
                    _ => {
                        match cred {
                            AuthCredential::Anonymous => {
                                // For anonymous, no claims will ever be issued.
                                lsecurity!(au, "Handler::Anonymous -> Result::Success");
                                CredState::Success(Vec::new())
                            }
                            _ => {
                                lsecurity!(au, "Handler::Anonymous -> Result::Denied - invalid cred type for handler");
                                CredState::Denied(BAD_AUTH_TYPE_MSG)
                            }
                        }
                    }
                } // end match acc
            },
        )
    }

    fn validate_password(
        au: &mut AuditScope,
        creds: &[AuthCredential],
        pw: &mut Password,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
    ) -> CredState {
        creds.iter().fold(
            // If no creds, remind that we want pw ...
            CredState::Continue(vec![AuthAllowed::Password]),
            |acc, cred| {
                match acc {
                    // If failed, continue to fail.
                    CredState::Denied(_) => {
                        lsecurity!(au, "Handler::Password -> Result::Denied - already denied");
                        acc
                    }
                    _ => {
                        match cred {
                            AuthCredential::Password(cleartext) => {
                                if pw.verify(cleartext.as_str()).unwrap_or(false) {
                                    lsecurity!(au, "Handler::Password -> Result::Success");
                                    Self::maybe_pw_upgrade(au, pw, who, cleartext.as_str(), async_tx);
                                    CredState::Success(Vec::new())
                                } else {
                                    lsecurity!(au, "Handler::Password -> Result::Denied - incorrect password");
                                    CredState::Denied(BAD_PASSWORD_MSG)
                                }
                            }
                            // All other cases fail.
                            _ => {
                                lsecurity!(au, "Handler::Anonymous -> Result::Denied - invalid cred type for handler");
                                CredState::Denied(BAD_AUTH_TYPE_MSG)
                            }
                        }
                    }
                } // end match acc
            },
        )
    }

    fn validate_totp_password(
        au: &mut AuditScope,
        creds: &[AuthCredential],
        ts: &Duration,
        pw_totp: &mut CredTotpPw,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
    ) -> CredState {
        // Set the default reminder to both pw + totp
        creds.iter().fold(
            // If no creds, remind that we want pw ...
            CredState::Continue(vec![AuthAllowed::TOTP, AuthAllowed::Password]),
            |acc, cred| {
                match acc {
                    CredState::Denied(_) => {
                        lsecurity!(au, "Handler::TOTPPassword -> Result::Denied - already denied");
                        acc
                    }
                    _ => {
                        match cred {
                            AuthCredential::Password(cleartext) => {
                                // if pw -> check
                                if pw_totp.pw.verify(cleartext.as_str()).unwrap_or(false) {
                                    pw_totp.pw_state = CredVerifyState::Success;
                                    Self::maybe_pw_upgrade(au, &pw_totp.pw, who, cleartext.as_str(), async_tx);
                                    match pw_totp.totp_state {
                                        CredVerifyState::Init => {
                                            // TOTP hasn't been run yet, we need it before
                                            // we indicate the pw status.
                                            lsecurity!(au, "Handler::TOTPPassword -> Result::Continue - TOTP -, password OK");
                                            CredState::Continue(vec![AuthAllowed::TOTP])
                                        }
                                        CredVerifyState::Success => {
                                            // The totp is success, and password good, let's go!
                                            lsecurity!(au, "Handler::TOTPPassword -> Result::Success - TOTP OK, password OK");
                                            CredState::Success(Vec::new())
                                        }
                                        CredVerifyState::Fail => {
                                            // The totp already failed, send that message now.
                                            // Should be impossible state.
                                            lsecurity!(au, "Handler::TOTPPassword -> Result::Denied - TOTP Fail, password OK");
                                            CredState::Denied(BAD_TOTP_MSG)
                                        }
                                    }
                                } else {
                                    pw_totp.pw_state = CredVerifyState::Fail;
                                    match pw_totp.totp_state {
                                        CredVerifyState::Init => {
                                            // TOTP hasn't been run yet, we need it before
                                            // we indicate the pw status.
                                            lsecurity!(au, "Handler::TOTPPassword -> Result::Continue - TOTP -, password Fail");
                                            CredState::Continue(vec![AuthAllowed::TOTP])
                                        }
                                        CredVerifyState::Success => {
                                            // The totp is success, but password bad.
                                            lsecurity!(au, "Handler::TOTPPassword -> Result::Denied - TOTP OK, password Fail");
                                            CredState::Denied(BAD_PASSWORD_MSG)
                                        }
                                        CredVerifyState::Fail => {
                                            // The totp already failed, remind.
                                            // this should be an impossible state.
                                            lsecurity!(au, "Handler::TOTPPassword -> Result::Denied - TOTP Fail, password Fail");
                                            CredState::Denied(BAD_TOTP_MSG)
                                        }
                                    }
                                }
                            }
                            AuthCredential::TOTP(totp_chal) => {
                                // if totp -> check
                                if pw_totp.totp.verify(*totp_chal, ts) {
                                    pw_totp.totp_state = CredVerifyState::Success;
                                    match pw_totp.pw_state {
                                        CredVerifyState::Init => {
                                            lsecurity!(au, "Handler::TOTPPassword -> Result::Continue - TOTP OK, password -");
                                            CredState::Continue(vec![AuthAllowed::Password])
                                        }
                                        CredVerifyState::Success => {
                                            lsecurity!(au, "Handler::TOTPPassword -> Result::Success - TOTP OK, password OK");
                                            CredState::Success(Vec::new())
                                        }
                                        CredVerifyState::Fail => {
                                            lsecurity!(au, "Handler::TOTPPassword -> Result::Denied - TOTP OK, password Fail");
                                            CredState::Denied(BAD_PASSWORD_MSG)
                                        }
                                    }
                                } else {
                                    pw_totp.totp_state = CredVerifyState::Fail;
                                    lsecurity!(au, "Handler::TOTPPassword -> Result::Denied - TOTP Fail, password -");
                                    CredState::Denied(BAD_TOTP_MSG)
                                }
                            }
                            // All other cases fail.
                            _ => {
                                lsecurity!(au, "Handler::TOTPPassword -> Result::Denied - invalid cred type for handler");
                                CredState::Denied(BAD_AUTH_TYPE_MSG)
                            }
                        } // end match cred
                    }
                } // end match acc
            },
        ) // end fold
    } // end CredHandler::TOTPPassword

    pub fn validate(
        &mut self,
        au: &mut AuditScope,
        creds: &[AuthCredential],
        ts: &Duration,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
    ) -> CredState {
        match self {
            CredHandler::Denied => {
                // Sad trombone.
                lsecurity!(au, "Handler::Denied -> Result::Denied");
                CredState::Denied("authentication denied")
            }
            CredHandler::Anonymous => Self::validate_anonymous(au, creds),
            CredHandler::Password(ref mut pw) => {
                Self::validate_password(au, creds, pw, who, async_tx)
            }
            CredHandler::TOTPPassword(ref mut pw_totp) => {
                Self::validate_totp_password(au, creds, ts, pw_totp, who, async_tx)
            }
        }
    }

    pub fn valid_auth_mechs(&self) -> Vec<AuthAllowed> {
        match &self {
            CredHandler::Denied => Vec::new(),
            CredHandler::Anonymous => vec![AuthAllowed::Anonymous],
            CredHandler::Password(_) => vec![AuthAllowed::Password],
            // webauth
            // mfa
            CredHandler::TOTPPassword(_) => vec![AuthAllowed::Password, AuthAllowed::TOTP],
        }
    }

    pub(crate) fn is_denied(&self) -> bool {
        match &self {
            CredHandler::Denied => true,
            _ => false,
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
    handler: CredHandler,
    // Store any related appid we are processing for.
    appid: Option<String>,
    // Store claims related to the handler
    // need to store state somehow?
    finished: bool,
}

impl AuthSession {
    pub fn new(au: &mut AuditScope, account: Account, appid: Option<String>) -> Self {
        // During this setup, determine the credential handler that we'll be using
        // for this session. This is currently based on presentation of an application
        // id.
        let handler = match appid {
            Some(_) => CredHandler::Denied,
            None => {
                // We want the primary handler - this is where we make a decision
                // based on the anonymous ... in theory this could be cleaner
                // and interact with the account more?
                if account.is_anonymous() {
                    CredHandler::Anonymous
                } else {
                    // Now we see if they have one ...
                    match &account.primary {
                        Some(cred) => {
                            // Probably means new authsession has to be failable
                            CredHandler::try_from(cred).unwrap_or_else(|_| {
                                lsecurity_critical!(
                                    au,
                                    "corrupt credentials, unable to start credhandler"
                                );
                                CredHandler::Denied
                            })
                        }
                        None => CredHandler::Denied,
                    }
                }
            }
        };

        // Is this handler locked?
        // Is the whole account locked?
        // What about in memory account locking? Is that something
        // we store in the account somehow?
        // TODO #59: Implement handler locking!

        // if credhandler == deny, finish = true.
        let finished: bool = handler.is_denied();

        AuthSession {
            account,
            handler,
            appid,
            finished,
        }
    }

    // This should return a AuthResult or similar state of checking?
    pub fn validate_creds(
        &mut self,
        au: &mut AuditScope,
        creds: &[AuthCredential],
        time: &Duration,
        async_tx: &Sender<DelayedAction>,
    ) -> Result<AuthState, OperationError> {
        if self.finished {
            return Err(OperationError::InvalidAuthState(
                "session already finalised!".to_string(),
            ));
        }

        if creds.len() > 4 {
            lsecurity!(
                au,
                "Credentials denied: potential flood/dos/bruteforce attempt. {} creds were sent.",
                creds.len()
            );
            return Ok(AuthState::Denied(BAD_CREDENTIALS.to_string()));
        }

        match self
            .handler
            .validate(au, creds, time, self.account.uuid, async_tx)
        {
            CredState::Success(claims) => {
                lsecurity!(au, "Successful cred handling");
                self.finished = true;
                let uat = self
                    .account
                    .to_userauthtoken(&claims)
                    .ok_or(OperationError::InvalidState)?;
                Ok(AuthState::Success(uat))
            }
            CredState::Continue(allowed) => {
                lsecurity!(au, "Request credential continuation: {:?}", allowed);
                Ok(AuthState::Continue(allowed))
            }
            CredState::Denied(reason) => {
                self.finished = true;
                lsecurity!(au, "Credentials denied: {}", reason);
                Ok(AuthState::Denied(reason.to_string()))
            }
        }
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
    }

    pub fn valid_auth_mechs(&self) -> Vec<AuthAllowed> {
        if self.finished {
            Vec::new()
        } else {
            self.handler.valid_auth_mechs()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::AuditScope;
    use crate::constants::{JSON_ADMIN_V1, JSON_ANONYMOUS_V1};
    use crate::credential::policy::CryptoPolicy;
    use crate::credential::totp::{TOTP, TOTP_DEFAULT_STEP};
    use crate::credential::Credential;
    use crate::idm::authsession::{
        AuthSession, BAD_AUTH_TYPE_MSG, BAD_CREDENTIALS, BAD_PASSWORD_MSG, BAD_TOTP_MSG,
    };
    use kanidm_proto::v1::{AuthAllowed, AuthCredential, AuthState};
    use std::time::Duration;
    // use async_std::task;

    use tokio::sync::mpsc::unbounded_channel as unbounded;
    // , UnboundedSender as Sender, UnboundedReceiver as Receiver};

    #[test]
    fn test_idm_authsession_anonymous_auth_mech() {
        let mut audit = AuditScope::new(
            "test_idm_authsession_anonymous_auth_mech",
            uuid::Uuid::new_v4(),
            None,
        );

        let anon_account = entry_str_to_account!(JSON_ANONYMOUS_V1);

        let session = AuthSession::new(&mut audit, anon_account, None);

        let auth_mechs = session.valid_auth_mechs();

        assert!(
            true == auth_mechs.iter().fold(false, |acc, x| match x {
                AuthAllowed::Anonymous => true,
                _ => acc,
            })
        );
    }

    #[test]
    fn test_idm_authsession_floodcheck_mech() {
        let mut audit = AuditScope::new(
            "test_idm_authsession_floodcheck_mech",
            uuid::Uuid::new_v4(),
            None,
        );
        let anon_account = entry_str_to_account!(JSON_ANONYMOUS_V1);
        let mut session = AuthSession::new(&mut audit, anon_account, None);
        let (async_tx, mut async_rx) = unbounded();

        let attempt = vec![
            AuthCredential::Anonymous,
            AuthCredential::Anonymous,
            AuthCredential::Anonymous,
            AuthCredential::Anonymous,
            AuthCredential::Anonymous,
        ];
        match session.validate_creds(&mut audit, &attempt, &Duration::from_secs(0), &async_tx) {
            Ok(AuthState::Denied(msg)) => {
                assert!(msg == BAD_CREDENTIALS);
            }
            _ => panic!(),
        };
        assert!(async_rx.try_recv().is_err());
        audit.write_log();
    }

    #[test]
    fn test_idm_authsession_missing_appid() {
        let anon_account = entry_str_to_account!(JSON_ANONYMOUS_V1);
        let mut audit = AuditScope::new(
            "test_idm_authsession_missing_appid",
            uuid::Uuid::new_v4(),
            None,
        );

        let session = AuthSession::new(
            &mut audit,
            anon_account,
            Some("NonExistantAppID".to_string()),
        );

        let auth_mechs = session.valid_auth_mechs();

        // Will always move to denied.
        assert!(auth_mechs == Vec::new());
    }

    #[test]
    fn test_idm_authsession_simple_password_mech() {
        let mut audit = AuditScope::new(
            "test_idm_authsession_simple_password_mech",
            uuid::Uuid::new_v4(),
            None,
        );
        // create the ent
        let mut account = entry_str_to_account!(JSON_ADMIN_V1);
        // manually load in a cred
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "test_password").unwrap();
        account.primary = Some(cred);

        // now check
        let mut session = AuthSession::new(&mut audit, account.clone(), None);
        let (async_tx, mut async_rx) = unbounded();
        let auth_mechs = session.valid_auth_mechs();

        assert!(
            true == auth_mechs.iter().fold(false, |acc, x| match x {
                AuthAllowed::Password => true,
                _ => acc,
            })
        );

        let attempt = vec![AuthCredential::Password("bad_password".to_string())];
        match session.validate_creds(&mut audit, &attempt, &Duration::from_secs(0), &async_tx) {
            Ok(AuthState::Denied(_)) => {}
            _ => panic!(),
        };

        let mut session = AuthSession::new(&mut audit, account, None);
        let attempt = vec![AuthCredential::Password("test_password".to_string())];
        match session.validate_creds(&mut audit, &attempt, &Duration::from_secs(0), &async_tx) {
            Ok(AuthState::Success(_)) => {}
            _ => panic!(),
        };
        assert!(async_rx.try_recv().is_err());

        audit.write_log();
    }

    #[test]
    fn test_idm_authsession_totp_password_mech() {
        let mut audit = AuditScope::new(
            "test_idm_authsession_totp_password_mech",
            uuid::Uuid::new_v4(),
            None,
        );
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

        // now check
        let session = AuthSession::new(&mut audit, account.clone(), None);
        let (async_tx, mut async_rx) = unbounded();
        let auth_mechs = session.valid_auth_mechs();
        assert!(auth_mechs.iter().fold(true, |acc, x| match x {
            AuthAllowed::Password => acc,
            AuthAllowed::TOTP => acc,
            _ => false,
        }));

        // Rest of test go here

        // check send anon (fail)
        {
            let mut session = AuthSession::new(&mut audit, account.clone(), None);
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Anonymous],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };
        }

        // == two step checks

        // check send bad pw, should get continue (even though denied set)
        //      then send good totp, should fail.
        {
            let mut session = AuthSession::new(&mut audit, account.clone(), None);
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Password(pw_bad.to_string())],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::TOTP]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::TOTP(totp_good)],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };
        }
        // check send bad pw, should get continue (even though denied set)
        //      then send bad totp, should fail TOTP
        {
            let mut session = AuthSession::new(&mut audit, account.clone(), None);
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Password(pw_bad.to_string())],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::TOTP]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::TOTP(totp_bad)],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_TOTP_MSG),
                _ => panic!(),
            };
        }

        // check send good pw, should get continue
        //      then send good totp, success
        {
            let mut session = AuthSession::new(&mut audit, account.clone(), None);
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Password(pw_good.to_string())],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::TOTP]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::TOTP(totp_good)],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };
        }

        // check send good pw, should get continue
        //      then send bad totp, fail otp
        {
            let mut session = AuthSession::new(&mut audit, account.clone(), None);
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Password(pw_good.to_string())],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::TOTP]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::TOTP(totp_bad)],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_TOTP_MSG),
                _ => panic!(),
            };
        }

        // check send bad totp, should fail immediate
        {
            let mut session = AuthSession::new(&mut audit, account.clone(), None);
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::TOTP(totp_bad)],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_TOTP_MSG),
                _ => panic!(),
            };
        }

        // check send good totp, should continue
        //      then bad pw, fail pw
        {
            let mut session = AuthSession::new(&mut audit, account.clone(), None);
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::TOTP(totp_good)],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Password(pw_bad.to_string())],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };
        }

        // check send good totp, should continue
        //      then good pw, success
        {
            let mut session = AuthSession::new(&mut audit, account.clone(), None);
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::TOTP(totp_good)],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Password(pw_good.to_string())],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };
        }

        // == one step checks

        // check bad totp, bad pw, fail totp.
        {
            let mut session = AuthSession::new(&mut audit, account.clone(), None);
            match session.validate_creds(
                &mut audit,
                &vec![
                    AuthCredential::Password(pw_bad.to_string()),
                    AuthCredential::TOTP(totp_bad),
                ],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_TOTP_MSG),
                _ => panic!(),
            };
        }
        // check send bad pw, good totp fail password
        {
            let mut session = AuthSession::new(&mut audit, account.clone(), None);
            match session.validate_creds(
                &mut audit,
                &vec![
                    AuthCredential::TOTP(totp_good),
                    AuthCredential::Password(pw_bad.to_string()),
                ],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };
        }
        // check send good pw, bad totp fail totp.
        {
            let mut session = AuthSession::new(&mut audit, account.clone(), None);
            match session.validate_creds(
                &mut audit,
                &vec![
                    AuthCredential::TOTP(totp_bad),
                    AuthCredential::Password(pw_good.to_string()),
                ],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_TOTP_MSG),
                _ => panic!(),
            };
        }
        // check good pw, good totp, success
        {
            let mut session = AuthSession::new(&mut audit, account.clone(), None);
            match session.validate_creds(
                &mut audit,
                &vec![
                    AuthCredential::TOTP(totp_good),
                    AuthCredential::Password(pw_good.to_string()),
                ],
                &ts,
                &async_tx,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };
        }

        assert!(async_rx.try_recv().is_err());
        audit.write_log();
    }
}
