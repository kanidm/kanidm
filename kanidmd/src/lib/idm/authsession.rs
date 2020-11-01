use crate::audit::AuditScope;
use crate::idm::account::Account;
use crate::idm::claim::Claim;
use crate::idm::AuthState;
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::{AuthAllowed, AuthCredential};

use crate::credential::{totp::TOTP, Credential, Password};

use crate::idm::delayed::{DelayedAction, PasswordUpgrade};
// use crossbeam::channel::Sender;
use tokio::sync::mpsc::UnboundedSender as Sender;

use std::convert::TryFrom;
use std::time::Duration;
use uuid::Uuid;
use webauthn_rs::proto::Credential as WebauthnCredential;
use webauthn_rs::proto::{RequestChallengeResponse, UserVerificationPolicy};
use webauthn_rs::{Webauthn, AuthenticationState};
use crate::credential::webauthn::WebauthnDomainConfig;

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
    Denied(&'static str),
    Anonymous,
    // AppPassword (?)
    Password(Password),
    TOTPPassword(CredTotpPw),
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
        match (c.password.as_ref(), c.totp.as_ref(), c.webauthn.as_ref()) {
            (Some(pw), None, None) => Ok(CredHandler::Password(pw.clone())),
            (Some(pw), Some(totp), None) => Ok(CredHandler::TOTPPassword(CredTotpPw {
                pw: pw.clone(),
                pw_state: CredVerifyState::Init,
                totp: totp.clone(),
                totp_state: CredVerifyState::Init,
            })),
            (None, None, Some(wan)) => webauthn
                .generate_challenge_authenticate(wan.values().map(|c| c.clone()).collect(), Some(UserVerificationPolicy::Discouraged))
                .map(|(chal, wan_state)| {
                    CredHandler::Webauthn(CredWebauthn {
                        chal,
                        wan_state,
                        state: CredVerifyState::Init,
                    })
                })
                .map_err(|e| {
                    lsecurity!(au, "Unable to create webauthn authentication challenge -> {:?}", e);
                    ()
                }),
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

    pub fn validate_webauthn(
        au: &mut AuditScope,
        creds: &[AuthCredential],
        wan_cred: &mut CredWebauthn,
        webauthn: &Webauthn<WebauthnDomainConfig>,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
    ) -> CredState {
        if wan_cred.state != CredVerifyState::Init {
            lsecurity!(au, "Handler::Webauthn -> Result::Denied - Internal State Already Fail");
            return CredState::Denied(BAD_WEBAUTHN_MSG);
        }

        creds.iter().fold(
            CredState::Continue(vec![]),
            |acc, cred| {
                match acc {
                    // If denied, continue returning denied.
                    CredState::Denied(_) => {
                        lsecurity!(au, "Handler::Webauthn -> Result::Denied - already denied");
                        acc
                    }
                    _ => {
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
                                lsecurity!(au, "Handler::Webauthn -> Result::Denied - invalid cred type for handler");
                                CredState::Denied(BAD_AUTH_TYPE_MSG)
                            }
                        }
                    }
                } // end match acc
            }
        ) // end fold
    }

    pub fn validate(
        &mut self,
        au: &mut AuditScope,
        creds: &[AuthCredential],
        ts: &Duration,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
        webauthn: &Webauthn<WebauthnDomainConfig>,
    ) -> CredState {
        match self {
            CredHandler::Denied(reason) => {
                // Sad trombone.
                lsecurity!(au, "Handler::Denied -> Result::Denied");
                CredState::Denied(reason)
            }
            CredHandler::Anonymous => Self::validate_anonymous(au, creds),
            CredHandler::Password(ref mut pw) => {
                Self::validate_password(au, creds, pw, who, async_tx)
            }
            CredHandler::TOTPPassword(ref mut pw_totp) => {
                Self::validate_totp_password(au, creds, ts, pw_totp, who, async_tx)
            }
            CredHandler::Webauthn(ref mut wan_cred) => {
                Self::validate_webauthn(au, creds, wan_cred, webauthn, who, async_tx)
            }
        }
    }

    pub fn valid_auth_mechs(&self) -> Vec<AuthAllowed> {
        match &self {
            CredHandler::Denied(_) => Vec::new(),
            CredHandler::Anonymous => vec![AuthAllowed::Anonymous],
            CredHandler::Password(_) => vec![AuthAllowed::Password],
            // webauth
            // mfa
            CredHandler::TOTPPassword(_) => vec![AuthAllowed::Password, AuthAllowed::TOTP],
            CredHandler::Webauthn(webauthn) => vec![AuthAllowed::Webauthn(
                webauthn.chal.clone()
            )],
        }
    }

    pub(crate) fn is_denied(&self) -> Option<&'static str> {
        match &self {
            CredHandler::Denied(x) => Some(x),
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
    handler: CredHandler,
    // The identity of the credential that uniquely identifies it.
    // cred_uuid: Uuid,
    // Store any related appid we are processing for.
    appid: Option<String>,
    // Store claims related to the handler
    // need to store state somehow?
    finished: bool,
}

impl AuthSession {
    pub fn new(
        au: &mut AuditScope,
        account: Account,
        appid: Option<String>,
        webauthn: &Webauthn<WebauthnDomainConfig>,
        ct: Duration,
    ) -> (Option<Self>, AuthState) {
        // During this setup, determine the credential handler that we'll be using
        // for this session. This is currently based on presentation of an application
        // id.
        let handler = if account.is_within_valid_time(ct) {
            match appid {
                Some(_) => CredHandler::Denied("authentication denied"),
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
                                CredHandler::try_from(au, cred, webauthn).unwrap_or_else(|_| {
                                    lsecurity_critical!(
                                        au,
                                        "corrupt credentials, unable to start credhandler"
                                    );
                                    CredHandler::Denied("invalid credential state")
                                })
                            }
                            None => {
                                lsecurity!(au, "account has no primary credentials");
                                CredHandler::Denied("invalid credential state")
                            }
                        }
                    }
                }
            }
        } else {
            lsecurity!(au, "account expired");
            CredHandler::Denied(ACCOUNT_EXPIRED)
        };

        // if credhandler == deny, finish = true.
        if let Some(reason) = handler.is_denied() {
            // Already denied, lets send that result
            (None, AuthState::Denied(reason.to_string()))
        } else {
            // We can proceed
            let auth_session = AuthSession {
                account,
                handler,
                appid,
                finished: false,
            };
            // Get the set of mechanisms that can proceed. This is tied
            // to the session so that it can mutate state and have progression
            // of what's next, or ordering.
            let next_mech = auth_session.valid_auth_mechs();

            let state = AuthState::Continue(next_mech);
            (Some(auth_session), state)
        }
    }

    pub fn get_account(&self) -> &Account {
        &self.account
    }

    pub fn end_session(&mut self, reason: String) -> Result<AuthState, OperationError> {
        self.finished = true;
        Ok(AuthState::Denied(reason))
    }

    // This should return a AuthResult or similar state of checking?
    pub fn validate_creds(
        &mut self,
        au: &mut AuditScope,
        creds: &[AuthCredential],
        time: &Duration,
        async_tx: &Sender<DelayedAction>,
        webauthn: &Webauthn<WebauthnDomainConfig>,
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
            self.finished = true;
            return Ok(AuthState::Denied(BAD_CREDENTIALS.to_string()));
        }

        match self
            .handler
            .validate(au, creds, time, self.account.uuid, async_tx, webauthn)
        {
            CredState::Success(claims) => {
                lsecurity!(au, "Successful cred handling");
                self.finished = true;
                let uat = self
                    .account
                    .to_userauthtoken(&claims)
                    .ok_or(OperationError::InvalidState)?;

                // Now encrypt and prepare the token for return to the client.
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

    fn valid_auth_mechs(&self) -> Vec<AuthAllowed> {
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
        BAD_WEBAUTHN_MSG,
    };
    use crate::idm::AuthState;
    use crate::utils::duration_from_epoch_now;
    use kanidm_proto::v1::{AuthAllowed, AuthCredential};
    use std::time::Duration;
    // use async_std::task;
    use webauthn_rs::Webauthn;
    use webauthn_rs::proto::UserVerificationPolicy;
    use crate::credential::webauthn::WebauthnDomainConfig;

    use tokio::sync::mpsc::unbounded_channel as unbounded;
    // , UnboundedSender as Sender, UnboundedReceiver as Receiver};
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

        let (_session, state) =
            AuthSession::new(&mut audit, anon_account, None, &webauthn, duration_from_epoch_now());

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

    #[test]
    fn test_idm_authsession_floodcheck_mech() {
        let mut audit = AuditScope::new(
            "test_idm_authsession_floodcheck_mech",
            uuid::Uuid::new_v4(),
            None,
        );
        let webauthn = create_webauthn();
        let anon_account = entry_str_to_account!(JSON_ANONYMOUS_V1);
        let (session, _) =
            AuthSession::new(&mut audit, anon_account, None, &webauthn, duration_from_epoch_now());
        let (async_tx, mut async_rx) = unbounded();

        // Will be some.
        let mut session = session.unwrap();

        let attempt = vec![
            AuthCredential::Anonymous,
            AuthCredential::Anonymous,
            AuthCredential::Anonymous,
            AuthCredential::Anonymous,
            AuthCredential::Anonymous,
        ];
        match session.validate_creds(&mut audit, &attempt, &Duration::from_secs(0), &async_tx, &webauthn) {
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

        assert!(session.is_none());

        if let AuthState::Denied(_) = state {
            // Pass
        } else {
            panic!();
        }
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

        // now check
        let (session, state) =
            AuthSession::new(&mut audit, account.clone(), None, &webauthn, duration_from_epoch_now());
        let mut session = session.unwrap();
        let (async_tx, mut async_rx) = unbounded();
        if let AuthState::Continue(auth_mechs) = state {
            assert!(
                true == auth_mechs.iter().fold(false, |acc, x| match x {
                    AuthAllowed::Password => true,
                    _ => acc,
                })
            );
        } else {
            panic!();
        }

        let attempt = vec![AuthCredential::Password("bad_password".to_string())];
        match session.validate_creds(&mut audit, &attempt, &Duration::from_secs(0), &async_tx, &webauthn) {
            Ok(AuthState::Denied(_)) => {}
            _ => panic!(),
        };

        let (session, _state) =
            AuthSession::new(&mut audit, account, None, &webauthn, duration_from_epoch_now());
        let mut session = session.unwrap();
        let attempt = vec![AuthCredential::Password("test_password".to_string())];
        match session.validate_creds(&mut audit, &attempt, &Duration::from_secs(0), &async_tx, &webauthn) {
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

        // now check
        let (_session, state) =
            AuthSession::new(&mut audit, account.clone(), None, &webauthn, duration_from_epoch_now());
        let (async_tx, mut async_rx) = unbounded();
        if let AuthState::Continue(auth_mechs) = state {
            assert!(auth_mechs.iter().fold(true, |acc, x| match x {
                AuthAllowed::Password => acc,
                AuthAllowed::TOTP => acc,
                _ => false,
            }));
        } else {
            panic!();
        }

        // Rest of test go here

        // check send anon (fail)
        {
            let (session, _state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, duration_from_epoch_now());
            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Anonymous],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };
        }

        // == two step checks

        // check send bad pw, should get continue (even though denied set)
        //      then send good totp, should fail.
        {
            let (session, _state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, duration_from_epoch_now());
            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Password(pw_bad.to_string())],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::TOTP]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::TOTP(totp_good)],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };
        }
        // check send bad pw, should get continue (even though denied set)
        //      then send bad totp, should fail TOTP
        {
            let (session, _state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, duration_from_epoch_now());
            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Password(pw_bad.to_string())],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::TOTP]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::TOTP(totp_bad)],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_TOTP_MSG),
                _ => panic!(),
            };
        }

        // check send good pw, should get continue
        //      then send good totp, success
        {
            let (session, _state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, duration_from_epoch_now());
            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Password(pw_good.to_string())],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::TOTP]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::TOTP(totp_good)],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };
        }

        // check send good pw, should get continue
        //      then send bad totp, fail otp
        {
            let (session, _state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, duration_from_epoch_now());
            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Password(pw_good.to_string())],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::TOTP]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::TOTP(totp_bad)],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_TOTP_MSG),
                _ => panic!(),
            };
        }

        // check send bad totp, should fail immediate
        {
            let (session, _state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, duration_from_epoch_now());
            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::TOTP(totp_bad)],
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
            let (session, _state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, duration_from_epoch_now());
            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::TOTP(totp_good)],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Password(pw_bad.to_string())],
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
            let (session, _state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, duration_from_epoch_now());
            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::TOTP(totp_good)],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Password(pw_good.to_string())],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };
        }

        // == one step checks

        // check bad totp, bad pw, fail totp.
        {
            let (session, _state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, duration_from_epoch_now());
            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![
                    AuthCredential::Password(pw_bad.to_string()),
                    AuthCredential::TOTP(totp_bad),
                ],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_TOTP_MSG),
                _ => panic!(),
            };
        }
        // check send bad pw, good totp fail password
        {
            let (session, _state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, duration_from_epoch_now());
            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![
                    AuthCredential::TOTP(totp_good),
                    AuthCredential::Password(pw_bad.to_string()),
                ],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };
        }
        // check send good pw, bad totp fail totp.
        {
            let (session, _state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, duration_from_epoch_now());
            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![
                    AuthCredential::TOTP(totp_bad),
                    AuthCredential::Password(pw_good.to_string()),
                ],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_TOTP_MSG),
                _ => panic!(),
            };
        }
        // check good pw, good totp, success
        {
            let (session, _state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, duration_from_epoch_now());
            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![
                    AuthCredential::TOTP(totp_good),
                    AuthCredential::Password(pw_good.to_string()),
                ],
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
        let (_session, state) =
            AuthSession::new(&mut audit, account.clone(), None, &webauthn, ts);
        let inv_chal = if let AuthState::Continue(auth_mechs) = state {
            assert!(auth_mechs.len() == 1);
            auth_mechs.into_iter().fold(None, |acc, x| match x {
                AuthAllowed::Webauthn(chal) => Some(chal),
                _ => None,
            })
            .expect("No webauthn challenge found.")
        } else {
            panic!();
        };

        // check send anon (fail)
        {
            let (session, _state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, ts);
            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Anonymous],
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
            let (session, state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, ts);

            let resp = if let AuthState::Continue(mut auth_mechs) = state {
                match auth_mechs.pop() {
                    Some(AuthAllowed::Webauthn(chal)) => {
                        wa.do_authentication("https://idm.example.com", chal)
                            .expect("failed to use softtoken to authenticate")
                    }
                    _ => {
                        panic!();
                    }
                }
            } else {
                panic!();
            };

            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Webauthn(resp)],
                &ts,
                &async_tx,
                &webauthn,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };
        }
        // Check bad challenge.
        {
            let (session, state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, ts);

            let resp = if let AuthState::Continue(mut auth_mechs) = state {
                match auth_mechs.pop() {
                    Some(AuthAllowed::Webauthn(_chal)) => {
                        // HERE -> we use inv_chal instead.
                        wa.do_authentication("https://idm.example.com", inv_chal)
                            .expect("failed to use softtoken to authenticate")
                    }
                    _ => {
                        panic!();
                    }
                }
            } else {
                panic!();
            };

            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Webauthn(resp)],
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
                .generate_challenge_register(&account.name, Some(UserVerificationPolicy::Discouraged))
                .expect("Failed to setup webauthn rego challenge");

            let r = inv_wa
                .do_registration("https://idm.example.com", chal)
                .expect("Failed to create soft token");

            let inv_cred = webauthn
                .register_credential(&r, reg_state, |_| Ok(false))
                .expect("Failed to register soft token");

            let (chal, auth_state) = webauthn
                .generate_challenge_authenticate(vec![inv_cred], 
                Some(UserVerificationPolicy::Discouraged)).expect("Failed to generate challenge for in inv softtoken");

            let resp = inv_wa
                .do_authentication("https://idm.example.com", chal)
                .expect("Failed to use softtoken for response.");

            let (session, _state) =
                AuthSession::new(&mut audit, account.clone(), None, &webauthn, ts);

            // Ignore the real cred, use the diff cred. Normally this shouldn't even
            // get this far, because the client should identify that the cred id's are
            // not inline.
            let mut session = session.unwrap();
            match session.validate_creds(
                &mut audit,
                &vec![AuthCredential::Webauthn(resp)],
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
