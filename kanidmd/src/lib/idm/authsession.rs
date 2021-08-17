//! This module contains the logic to conduct an authentication of an account.
//! Generally this has to process an authentication attempt, and validate each
//! factor to assert that the user is legitimate. This also contains some
//! support code for asynchronous task execution.
use crate::credential::BackupCodes;
use crate::idm::account::Account;
use crate::idm::delayed::BackupCodeRemoval;
use crate::idm::AuthState;
use crate::tracing_tree;
use crate::{admin_error, admin_warn, prelude::*, security_critical, security_info};
use hashbrown::HashSet;
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::{AuthAllowed, AuthCredential, AuthMech, AuthType};

use crate::credential::{totp::Totp, Credential, CredentialType, Password};

use crate::idm::delayed::{DelayedAction, PasswordUpgrade, WebauthnCounterIncrement};
// use crossbeam::channel::Sender;
use tokio::sync::mpsc::UnboundedSender as Sender;

use crate::credential::webauthn::WebauthnDomainConfig;
use std::time::Duration;
use uuid::Uuid;
// use webauthn_rs::proto::Credential as WebauthnCredential;
use bundy::hs512::HS512;
pub use std::collections::BTreeSet as Set;
use webauthn_rs::proto::RequestChallengeResponse;
use webauthn_rs::{AuthenticationState, Webauthn};

// Each CredHandler takes one or more credentials and determines if the
// handlers requirements can be 100% fufilled. This is where MFA or other
// auth policies would exist, but each credHandler has to be a whole
// encapsulated unit of function.

const BAD_PASSWORD_MSG: &str = "incorrect password";
const BAD_TOTP_MSG: &str = "incorrect totp";
const BAD_WEBAUTHN_MSG: &str = "invalid webauthn authentication";
const BAD_BACKUPCODE_MSG: &str = "invalid backup code";
const BAD_AUTH_TYPE_MSG: &str = "invalid authentication method in this context";
const BAD_CREDENTIALS: &str = "invalid credential message";
const ACCOUNT_EXPIRED: &str = "account expired";
const PW_BADLIST_MSG: &str = "password is in badlist";

/// A response type to indicate the progress and potential result of an authentication attempt.
enum CredState {
    Success(AuthType),
    Continue(Vec<AuthAllowed>),
    Denied(&'static str),
}

#[derive(Clone, Debug, PartialEq)]
/// The state of verification of an individual credential during an authentication.
enum CredVerifyState {
    Init,
    Success,
    Fail,
}

#[derive(Clone, Debug)]
/// The state of a multifactor authenticator during authentication.
struct CredMfa {
    pw: Password,
    pw_state: CredVerifyState,
    totp: Option<Totp>,
    wan: Option<(RequestChallengeResponse, AuthenticationState)>,
    backup_code: Option<BackupCodes>,
    mfa_state: CredVerifyState,
}

#[derive(Clone, Debug)]
/// The state of a webauthn credential during authentication
struct CredWebauthn {
    chal: RequestChallengeResponse,
    wan_state: AuthenticationState,
    state: CredVerifyState,
}

/// The current active handler for this authentication session. This is determined from what credentials
/// are possible from the account, and what the user selected as the preferred authentication
/// mechanism.
#[derive(Clone, Debug)]
enum CredHandler {
    Anonymous,
    // AppPassword (?)
    Password(Password, bool),
    PasswordMfa(Box<CredMfa>),
    Webauthn(CredWebauthn),
    // Webauthn + Password
}

impl CredHandler {
    // ! TRACING INTEGRATED
    /// Given a credential and some external configuration, Generate the credential handler
    /// that will be used for this session. This credential handler is a "self contained"
    /// unit that defines what is possible to use during this authentication session to prevent
    /// inconsistency.
    fn try_from(
        au: &mut AuditScope,
        c: &Credential,
        webauthn: &Webauthn<WebauthnDomainConfig>,
    ) -> Result<Self, ()> {
        match &c.type_ {
            CredentialType::Password(pw) => Ok(CredHandler::Password(pw.clone(), false)),
            CredentialType::GeneratedPassword(pw) => Ok(CredHandler::Password(pw.clone(), true)),
            CredentialType::PasswordMfa(pw, maybe_totp, maybe_wan, maybe_backup_code) => {
                let wan = if !maybe_wan.is_empty() {
                    webauthn
                        .generate_challenge_authenticate(maybe_wan.values().cloned().collect())
                        .map(Some)
                        .map_err(|e| {
                            lsecurity!(
                                au,
                                "Unable to create webauthn authentication challenge -> {:?}",
                                e
                            );
                        })?
                } else {
                    None
                };

                let cmfa = Box::new(CredMfa {
                    pw: pw.clone(),
                    pw_state: CredVerifyState::Init,
                    totp: maybe_totp.clone(),
                    wan,
                    backup_code: maybe_backup_code.clone(),
                    mfa_state: CredVerifyState::Init,
                });

                // Paranoia. Should NEVER occur.
                if cmfa.totp.is_none() && cmfa.wan.is_none() {
                    security_critical!("Unable to create CredHandler::PasswordMfa - totp and webauthn are both not present. Credentials MAY be corrupt!");
                    lsecurity_critical!(
                        au,
                        "Unable to create CredHandler::PasswordMfa - totp and webauthn are both not present. Credentials MAY be corrupt!"
                    );
                    return Err(());
                }

                Ok(CredHandler::PasswordMfa(cmfa))
            }
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
                    security_info!(?e, "Unable to create webauthn authentication challenge");
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
    // ! TRACING INTEGRATED
    /// Determine if this password factor requires an upgrade of it's cryptographic type. If
    /// so, send an asynchronous event into the queue that will allow the password to have it's
    /// content upgraded later.
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
            })) {
                admin_warn!("unable to queue delayed pwupgrade, continuing ... ");
                ladmin_warning!(au, "unable to queue delayed pwupgrade, continuing ... ");
            };
        }
    }

    // ! TRACING INTEGRATED
    /// validate that the client wants to authenticate as the anonymous user.
    fn validate_anonymous(au: &mut AuditScope, cred: &AuthCredential) -> CredState {
        match cred {
            AuthCredential::Anonymous => {
                // For anonymous, no claims will ever be issued.
                security_info!("Handler::Anonymous -> Result::Success");
                lsecurity!(au, "Handler::Anonymous -> Result::Success");
                CredState::Success(AuthType::Anonymous)
            }
            _ => {
                security_info!(
                    "Handler::Anonymous -> Result::Denied - invalid cred type for handler"
                );
                lsecurity!(
                    au,
                    "Handler::Anonymous -> Result::Denied - invalid cred type for handler"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    // ! TRACING INTEGRATED
    /// Validate a singule password credential of the account.
    fn validate_password(
        au: &mut AuditScope,
        cred: &AuthCredential,
        pw: &mut Password,
        generated: bool,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
        pw_badlist_set: Option<&HashSet<String>>,
    ) -> CredState {
        match cred {
            AuthCredential::Password(cleartext) => {
                if pw.verify(cleartext.as_str()).unwrap_or(false) {
                    match pw_badlist_set {
                        Some(p) if p.contains(&cleartext.to_lowercase()) => {
                            security_info!("Handler::Password -> Result::Denied - Password found in badlist during login");
                            lsecurity!(
                                au,
                                "Handler::Password -> Result::Denied - Password found in badlist during login"
                            );
                            CredState::Denied(PW_BADLIST_MSG)
                        }
                        _ => {
                            security_info!("Handler::Password -> Result::Success");
                            lsecurity!(au, "Handler::Password -> Result::Success");
                            Self::maybe_pw_upgrade(au, pw, who, cleartext.as_str(), async_tx);
                            if generated {
                                CredState::Success(AuthType::GeneratedPassword)
                            } else {
                                CredState::Success(AuthType::Password)
                            }
                        }
                    }
                } else {
                    security_info!("Handler::Password -> Result::Denied - incorrect password");
                    lsecurity!(
                        au,
                        "Handler::Password -> Result::Denied - incorrect password"
                    );
                    CredState::Denied(BAD_PASSWORD_MSG)
                }
            }
            // All other cases fail.
            _ => {
                security_info!(
                    "Handler::Password -> Result::Denied - invalid cred type for handler"
                );
                lsecurity!(
                    au,
                    "Handler::Password -> Result::Denied - invalid cred type for handler"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    // ! TRACING INTEGRATED
    /// Proceed with the next step in a multifactor authentication, based on the current
    /// verification results and state. If this logic of this statemachine is violated, the
    /// authentication will fail.
    fn validate_password_mfa(
        au: &mut AuditScope,
        cred: &AuthCredential,
        ts: &Duration,
        pw_mfa: &mut CredMfa,
        webauthn: &Webauthn<WebauthnDomainConfig>,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
        pw_badlist_set: Option<&HashSet<String>>,
    ) -> CredState {
        match (&pw_mfa.mfa_state, &pw_mfa.pw_state) {
            (CredVerifyState::Init, CredVerifyState::Init) => {
                // MFA first
                match (
                    cred,
                    pw_mfa.totp.as_ref(),
                    pw_mfa.wan.as_ref(),
                    pw_mfa.backup_code.as_ref(),
                ) {
                    (AuthCredential::Webauthn(resp), _, Some((_, wan_state)), _) => {
                        match webauthn.authenticate_credential(&resp, &wan_state) {
                            Ok((cid, auth_data)) => {
                                pw_mfa.mfa_state = CredVerifyState::Success;
                                // Success. Determine if we need to update the counter
                                // async from r.
                                if auth_data.counter != 0 {
                                    // Do async
                                    if let Err(_e) =
                                        async_tx.send(DelayedAction::WebauthnCounterIncrement(
                                            WebauthnCounterIncrement {
                                                target_uuid: who,
                                                cid: cid.clone(),
                                                counter: auth_data.counter,
                                            },
                                        ))
                                    {
                                        admin_warn!("unable to queue delayed webauthn counter increment, continuing ... ");
                                        ladmin_warning!(au, "unable to queue delayed webauthn counter increment, continuing ... ");
                                    };
                                };
                                CredState::Continue(vec![AuthAllowed::Password])
                            }
                            Err(e) => {
                                pw_mfa.mfa_state = CredVerifyState::Fail;
                                // Denied.
                                security_info!(
                                    ?e,
                                    "Handler::Webauthn -> Result::Denied - webauthn error"
                                );
                                lsecurity!(
                                    au,
                                    "Handler::Webauthn -> Result::Denied - webauthn error {:?}",
                                    e
                                );
                                CredState::Denied(BAD_WEBAUTHN_MSG)
                            }
                        }
                    }
                    (AuthCredential::Totp(totp_chal), Some(totp), _, _) => {
                        if totp.verify(*totp_chal, ts) {
                            pw_mfa.mfa_state = CredVerifyState::Success;
                            security_info!(
                                "Handler::PasswordMfa -> Result::Continue - TOTP OK, password -"
                            );
                            lsecurity!(
                                au,
                                "Handler::PasswordMfa -> Result::Continue - TOTP OK, password -"
                            );
                            CredState::Continue(vec![AuthAllowed::Password])
                        } else {
                            pw_mfa.mfa_state = CredVerifyState::Fail;
                            security_info!(
                                "Handler::PasswordMfa -> Result::Denied - TOTP Fail, password -"
                            );
                            lsecurity!(
                                au,
                                "Handler::PasswordMfa -> Result::Denied - TOTP Fail, password -"
                            );
                            CredState::Denied(BAD_TOTP_MSG)
                        }
                    }
                    (AuthCredential::BackupCode(code_chal), _, _, Some(backup_codes)) => {
                        if backup_codes.verify(&code_chal) {
                            if let Err(_e) =
                                async_tx.send(DelayedAction::BackupCodeRemoval(BackupCodeRemoval {
                                    target_uuid: who,
                                    code_to_remove: code_chal.to_string(),
                                }))
                            {
                                admin_warn!(
                                    "unable to queue delayed backup code removal, continuing ... "
                                );
                                ladmin_warning!(
                                    au,
                                    "unable to queue delayed backup code removal, continuing ... "
                                );
                            };
                            pw_mfa.mfa_state = CredVerifyState::Success;
                            security_info!("Handler::PasswordMfa -> Result::Continue - BackupCode OK, password -");
                            lsecurity!(
                                au,
                                "Handler::PasswordMfa -> Result::Continue - BackupCode OK, password -"
                            );
                            CredState::Continue(vec![AuthAllowed::Password])
                        } else {
                            pw_mfa.mfa_state = CredVerifyState::Fail;
                            security_info!("Handler::PasswordMfa -> Result::Denied - BackupCode Fail, password -");
                            lsecurity!(
                                au,
                                "Handler::PasswordMfa -> Result::Denied - BackupCode Fail, password -"
                            );
                            CredState::Denied(BAD_BACKUPCODE_MSG)
                        }
                    }
                    _ => {
                        security_info!("Handler::PasswordMfa -> Result::Denied - invalid cred type for handler");
                        lsecurity!(
                            au,
                            "Handler::PasswordMfa -> Result::Denied - invalid cred type for handler"
                        );
                        CredState::Denied(BAD_AUTH_TYPE_MSG)
                    }
                }
            }
            (CredVerifyState::Success, CredVerifyState::Init) => {
                // PW second.
                match cred {
                    AuthCredential::Password(cleartext) => {
                        if pw_mfa.pw.verify(cleartext.as_str()).unwrap_or(false) {
                            match pw_badlist_set {
                                Some(p) if p.contains(&cleartext.to_lowercase()) => {
                                    pw_mfa.pw_state = CredVerifyState::Fail;
                                    security_info!("Handler::PasswordMfa -> Result::Denied - Password found in badlist during login");
                                    lsecurity!(
                                        au,
                                        "Handler::PasswordMfa -> Result::Denied - Password found in badlist during login"
                                    );
                                    CredState::Denied(PW_BADLIST_MSG)
                                }
                                _ => {
                                    pw_mfa.pw_state = CredVerifyState::Success;
                                    security_info!("Handler::PasswordMfa -> Result::Success - TOTP/WebAuthn/BackupCode OK, password OK");
                                    lsecurity!(
                                        au,
                                        "Handler::PasswordMfa -> Result::Success - TOTP/WebAuthn/BackupCode OK, password OK"
                                    );
                                    Self::maybe_pw_upgrade(
                                        au,
                                        &pw_mfa.pw,
                                        who,
                                        cleartext.as_str(),
                                        async_tx,
                                    );
                                    CredState::Success(AuthType::PasswordMfa)
                                }
                            }
                        } else {
                            pw_mfa.pw_state = CredVerifyState::Fail;
                            security_info!("Handler::PasswordMfa -> Result::Denied - TOTP/WebAuthn/BackupCode OK, password Fail");
                            lsecurity!(
                                au,
                                "Handler::PasswordMfa -> Result::Denied - TOTP/WebAuthn/BackupCode OK, password Fail"
                            );
                            CredState::Denied(BAD_PASSWORD_MSG)
                        }
                    }
                    _ => {
                        security_info!("Handler::PasswordMfa -> Result::Denied - invalid cred type for handler");
                        lsecurity!(
                            au,
                            "Handler::PasswordMfa -> Result::Denied - invalid cred type for handler"
                        );
                        CredState::Denied(BAD_AUTH_TYPE_MSG)
                    }
                }
            }
            _ => {
                security_info!(
                    "Handler::PasswordMfa -> Result::Denied - invalid credential mfa and pw state"
                );
                lsecurity!(
                    au,
                    "Handler::PasswordMfa -> Result::Denied - invalid credential mfa and pw state"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    } // end CredHandler::PasswordMfa

    // ! TRACING INTEGRATED
    /// Validate a webauthn authentication attempt
    pub fn validate_webauthn(
        au: &mut AuditScope,
        cred: &AuthCredential,
        wan_cred: &mut CredWebauthn,
        webauthn: &Webauthn<WebauthnDomainConfig>,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
    ) -> CredState {
        if wan_cred.state != CredVerifyState::Init {
            security_info!("Handler::Webauthn -> Result::Denied - Internal State Already Fail");
            lsecurity!(
                au,
                "Handler::Webauthn -> Result::Denied - Internal State Already Fail"
            );
            return CredState::Denied(BAD_WEBAUTHN_MSG);
        }

        match cred {
            AuthCredential::Webauthn(resp) => {
                // lets see how we go.
                match webauthn.authenticate_credential(&resp, &wan_cred.wan_state) {
                    Ok((cid, auth_data)) => {
                        wan_cred.state = CredVerifyState::Success;
                        // Success. Determine if we need to update the counter
                        // async from r.
                        if auth_data.counter != 0 {
                            // Do async
                            if let Err(_e) = async_tx.send(DelayedAction::WebauthnCounterIncrement(
                                WebauthnCounterIncrement {
                                    target_uuid: who,
                                    cid: cid.clone(),
                                    counter: auth_data.counter,
                                },
                            )) {
                                admin_warn!("unable to queue delayed webauthn counter increment, continuing ... ");
                                ladmin_warning!(au, "unable to queue delayed webauthn counter increment, continuing ... ");
                            };
                        };
                        CredState::Success(AuthType::Webauthn)
                    }
                    Err(e) => {
                        wan_cred.state = CredVerifyState::Fail;
                        // Denied.
                        security_info!(?e, "Handler::Webauthn -> Result::Denied - webauthn error");
                        lsecurity!(
                            au,
                            "Handler::Webauthn -> Result::Denied - webauthn error {:?}",
                            e
                        );
                        CredState::Denied(BAD_WEBAUTHN_MSG)
                    }
                }
            }
            _ => {
                security_info!(
                    "Handler::Webauthn -> Result::Denied - invalid cred type for handler"
                );
                lsecurity!(
                    au,
                    "Handler::Webauthn -> Result::Denied - invalid cred type for handler"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    // ! TRACING INTEGRATED
    #[allow(clippy::too_many_arguments)]
    /// Given the current handler, proceed to authenticate the attempted credential step.
    pub fn validate(
        &mut self,
        au: &mut AuditScope,
        cred: &AuthCredential,
        ts: &Duration,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
        webauthn: &Webauthn<WebauthnDomainConfig>,
        pw_badlist_set: Option<&HashSet<String>>,
    ) -> CredState {
        match self {
            CredHandler::Anonymous => Self::validate_anonymous(au, cred),
            CredHandler::Password(ref mut pw, generated) => {
                Self::validate_password(au, cred, pw, *generated, who, async_tx, pw_badlist_set)
            }
            CredHandler::PasswordMfa(ref mut pw_mfa) => Self::validate_password_mfa(
                au,
                cred,
                ts,
                pw_mfa,
                webauthn,
                who,
                async_tx,
                pw_badlist_set,
            ),
            CredHandler::Webauthn(ref mut wan_cred) => {
                Self::validate_webauthn(au, cred, wan_cred, webauthn, who, async_tx)
            }
        }
    }

    /// Determine based on the current status, what is the next allowed step that
    /// can proceed.
    pub fn next_auth_allowed(&self) -> Vec<AuthAllowed> {
        match &self {
            CredHandler::Anonymous => vec![AuthAllowed::Anonymous],
            CredHandler::Password(_, _) => vec![AuthAllowed::Password],
            CredHandler::PasswordMfa(ref pw_mfa) => pw_mfa
                .backup_code
                .iter()
                .map(|_| AuthAllowed::BackupCode)
                .chain(pw_mfa.totp.iter().map(|_| AuthAllowed::Totp))
                .chain(
                    pw_mfa
                        .wan
                        .iter()
                        .map(|(chal, _)| AuthAllowed::Webauthn(chal.clone())),
                )
                .collect(),
            CredHandler::Webauthn(webauthn) => vec![AuthAllowed::Webauthn(webauthn.chal.clone())],
        }
    }

    /// Determine which mechanismes can proceed given the requested mechanism.
    fn can_proceed(&self, mech: &AuthMech) -> bool {
        match (self, mech) {
            (CredHandler::Anonymous, AuthMech::Anonymous)
            | (CredHandler::Password(_, _), AuthMech::Password)
            | (CredHandler::PasswordMfa(_), AuthMech::PasswordMfa)
            | (CredHandler::Webauthn(_), AuthMech::Webauthn) => true,
            (_, _) => false,
        }
    }

    fn allows_mech(&self) -> AuthMech {
        match self {
            CredHandler::Anonymous => AuthMech::Anonymous,
            CredHandler::Password(_, _) => AuthMech::Password,
            CredHandler::PasswordMfa(_) => AuthMech::PasswordMfa,
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
/// The current state of an authentication session that is in progress.
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
    // ! TRACING INTEGRATED
    /// Create a new auth session, based on the available credential handlers of the account.
    /// the session is a whole encapsulated unit of what we need to proceed, so that subsequent
    /// or interleved write operations do not cause inconsistency in this process.
    pub fn new(
        au: &mut AuditScope,
        account: Account,
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
                                security_critical!(
                                    "corrupt credentials, unable to start credhandler"
                                );
                                lsecurity_critical!(
                                    au,
                                    "corrupt credentials, unable to start credhandler"
                                );
                                AuthSessionState::Denied("invalid credential state")
                            })
                    }
                    None => {
                        security_info!("account has no primary credentials");
                        lsecurity!(au, "account has no primary credentials");
                        AuthSessionState::Denied("invalid credential state")
                    }
                }
            }
        } else {
            security_info!("account expired");
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

    /// Given the users indicated and preferred authentication mechanism that they want to proceed
    /// with, select the credential handler and begin the process of stepping through the
    /// authentication process.
    // ! TRACING INTEGRATED
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

    // ! TRACING INTEGRATED
    /// Conduct a step of the authentication process. This validates the next credential factor
    /// presented and returns a result of Success, Continue, or Denied. Only in the success
    /// case is a UAT granted -- all others do not, including raised operation errors.
    pub fn validate_creds(
        &mut self,
        au: &mut AuditScope,
        cred: &AuthCredential,
        time: &Duration,
        async_tx: &Sender<DelayedAction>,
        webauthn: &Webauthn<WebauthnDomainConfig>,
        pw_badlist_set: Option<&HashSet<String>>,
        uat_bundy_hmac: &HS512,
    ) -> Result<AuthState, OperationError> {
        let (next_state, response) = match &mut self.state {
            AuthSessionState::Init(_) | AuthSessionState::Success | AuthSessionState::Denied(_) => {
                return Err(OperationError::InvalidAuthState(
                    "session already finalised!".to_string(),
                ));
            }
            AuthSessionState::InProgress(ref mut handler) => {
                match handler.validate(
                    au,
                    cred,
                    time,
                    self.account.uuid,
                    async_tx,
                    webauthn,
                    pw_badlist_set,
                ) {
                    CredState::Success(auth_type) => {
                        security_info!("Successful cred handling");
                        lsecurity!(au, "Successful cred handling");
                        // TODO: put the operation id into the call to `to_userauthtoken`
                        // Can't `unwrap` the uuid until full integration, because some unit tests
                        // call functions that call this indirectly without opening a span first,
                        // and this returns `None` when not in a span (and panics if the tree isn't initialized).
                        let _tracing_id = tracing_tree::operation_id();
                        let uat = self
                            .account
                            .to_userauthtoken(au.uuid, *time, auth_type)
                            .ok_or(OperationError::InvalidState)?;

                        // Now encrypt and prepare the token for return to the client.
                        let token = uat_bundy_hmac.sign(&uat).map_err(|e| {
                            admin_error!(?e, "Failed to sign UserAuthToken");
                            ladmin_error!(au, "Failed to sign UserAuthToken - {:?}", e);
                            OperationError::InvalidState
                        })?;

                        (
                            Some(AuthSessionState::Success),
                            Ok(AuthState::Success(token)),
                        )
                    }
                    CredState::Continue(allowed) => {
                        security_info!(?allowed, "Request credential continuation");
                        lsecurity!(au, "Request credential continuation: {:?}", allowed);
                        (None, Ok(AuthState::Continue(allowed)))
                    }
                    CredState::Denied(reason) => {
                        security_info!(%reason, "Credentials denied");
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

    /// End the session, defaulting to a denied.
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
    use crate::credential::policy::CryptoPolicy;
    use crate::credential::totp::{Totp, TOTP_DEFAULT_STEP};
    use crate::credential::webauthn::WebauthnDomainConfig;
    use crate::credential::{BackupCodes, Credential};
    use crate::idm::authsession::{
        AuthSession, BAD_AUTH_TYPE_MSG, BAD_BACKUPCODE_MSG, BAD_PASSWORD_MSG, BAD_TOTP_MSG,
        BAD_WEBAUTHN_MSG, PW_BADLIST_MSG,
    };
    use crate::idm::delayed::DelayedAction;
    use crate::idm::AuthState;
    use crate::prelude::*;
    use crate::tracing_tree;
    use hashbrown::HashSet;
    pub use std::collections::BTreeSet as Set;

    use crate::utils::{duration_from_epoch_now, readable_password_from_random};
    use kanidm_proto::v1::{AuthAllowed, AuthCredential, AuthMech};
    use std::time::Duration;
    use webauthn_rs::Webauthn;

    use tokio::sync::mpsc::unbounded_channel as unbounded;
    use webauthn_authenticator_rs::{softtok::U2FSoft, WebauthnAuthenticator};

    use bundy::hs512::HS512;
    use std::str::FromStr;

    fn create_pw_badlist_cache() -> HashSet<String> {
        let mut s = HashSet::new();
        s.insert((&"list@no3IBTyqHu$bad").to_lowercase());
        s
    }

    fn create_webauthn() -> Webauthn<WebauthnDomainConfig> {
        Webauthn::new(WebauthnDomainConfig {
            rp_name: "example.com".to_string(),
            origin: "https://idm.example.com".to_string(),
            rp_id: "example.com".to_string(),
        })
    }

    fn create_hs512() -> HS512 {
        let pkey_str = HS512::generate_key().unwrap();
        HS512::from_str(&pkey_str).unwrap()
    }

    #[test]
    fn test_idm_authsession_anonymous_auth_mech() {
        let _ = tracing_tree::test_init();
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

    macro_rules! start_password_session {
        (
            $audit:expr,
            $account:expr,
            $webauthn:expr
        ) => {{
            let (session, state) = AuthSession::new(
                $audit,
                $account.clone(),
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

            (session, create_pw_badlist_cache())
        }};
    }

    #[test]
    fn test_idm_authsession_simple_password_mech() {
        let _ = tracing_tree::test_init();
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
        let (mut session, pw_badlist_cache) =
            start_password_session!(&mut audit, account, &webauthn);

        let attempt = AuthCredential::Password("bad_password".to_string());
        let hs512 = create_hs512();
        match session.validate_creds(
            &mut audit,
            &attempt,
            &Duration::from_secs(0),
            &async_tx,
            &webauthn,
            Some(&pw_badlist_cache),
            &hs512,
        ) {
            Ok(AuthState::Denied(_)) => {}
            _ => panic!(),
        };

        // === Now begin a new session, and use a good pw.

        let (mut session, pw_badlist_cache) =
            start_password_session!(&mut audit, account, &webauthn);

        let attempt = AuthCredential::Password("test_password".to_string());
        match session.validate_creds(
            &mut audit,
            &attempt,
            &Duration::from_secs(0),
            &async_tx,
            &webauthn,
            Some(&pw_badlist_cache),
            &hs512,
        ) {
            Ok(AuthState::Success(_)) => {}
            _ => panic!(),
        };

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());

        audit.write_log();
    }

    #[test]
    fn test_idm_authsession_simple_password_badlist() {
        let _ = tracing_tree::test_init();
        let mut audit = AuditScope::new(
            "test_idm_authsession_simple_password_badlist",
            uuid::Uuid::new_v4(),
            None,
        );
        let hs512 = create_hs512();
        let webauthn = create_webauthn();
        // create the ent
        let mut account = entry_str_to_account!(JSON_ADMIN_V1);
        // manually load in a cred
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "list@no3IBTyqHu$bad").unwrap();
        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();

        // now check, even though the password is correct, Auth should be denied since it is in badlist
        let (mut session, pw_badlist_cache) =
            start_password_session!(&mut audit, account, &webauthn);

        let attempt = AuthCredential::Password("list@no3IBTyqHu$bad".to_string());
        match session.validate_creds(
            &mut audit,
            &attempt,
            &Duration::from_secs(0),
            &async_tx,
            &webauthn,
            Some(&pw_badlist_cache),
            &hs512,
        ) {
            Ok(AuthState::Denied(msg)) => assert!(msg == PW_BADLIST_MSG),
            _ => panic!(),
        };

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
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
                $webauthn,
                duration_from_epoch_now(),
            );
            let mut session = session.expect("Session was unable to be created.");

            if let AuthState::Choose(auth_mechs) = state {
                assert!(
                    true == auth_mechs.iter().fold(false, |acc, x| match x {
                        AuthMech::PasswordMfa => true,
                        _ => acc,
                    })
                );
            } else {
                panic!();
            }

            let state = session
                .start_session($audit, &AuthMech::PasswordMfa)
                .expect("Failed to select anonymous mech.");

            let mut rchal = None;

            if let AuthState::Continue(auth_mechs) = state {
                assert!(
                    true == auth_mechs.iter().fold(false, |acc, x| match x {
                        // TODO: How to return webauthn chal?
                        AuthAllowed::Webauthn(chal) => {
                            rchal = Some(chal.clone());
                            true
                        }
                        AuthAllowed::Totp => true,
                        _ => acc,
                    })
                );
            } else {
                panic!("Invalid auth state")
            }

            (session, rchal, create_pw_badlist_cache())
        }};
    }

    #[test]
    fn test_idm_authsession_totp_password_mech() {
        let _ = tracing_tree::test_init();
        let mut audit = AuditScope::new(
            "test_idm_authsession_totp_password_mech",
            uuid::Uuid::new_v4(),
            None,
        );
        let hs512 = create_hs512();
        let webauthn = create_webauthn();
        // create the ent
        let mut account = entry_str_to_account!(JSON_ADMIN_V1);

        // Setup a fake time stamp for consistency.
        let ts = Duration::from_secs(12345);

        // manually load in a cred
        let totp = Totp::generate_secure(TOTP_DEFAULT_STEP);

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
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Anonymous,
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };
        }

        // == two step checks

        // Sending a PW first is an immediate fail.
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Password(pw_bad.to_string()),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };
        }
        // check send bad totp, should fail immediate
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Totp(totp_bad),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_TOTP_MSG),
                _ => panic!(),
            };
        }

        // check send good totp, should continue
        //      then bad pw, fail pw
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Totp(totp_good),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
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
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };
        }

        // check send good totp, should continue
        //      then good pw, success
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Totp(totp_good),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
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
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        audit.write_log();
    }

    #[test]
    fn test_idm_authsession_password_mfa_badlist() {
        let _ = tracing_tree::test_init();
        let mut audit = AuditScope::new(
            "test_idm_authsession_password_mfa_badlist",
            uuid::Uuid::new_v4(),
            None,
        );
        let webauthn = create_webauthn();
        let hs512 = create_hs512();
        // create the ent
        let mut account = entry_str_to_account!(JSON_ADMIN_V1);

        // Setup a fake time stamp for consistency.
        let ts = Duration::from_secs(12345);

        // manually load in a cred
        let totp = Totp::generate_secure(TOTP_DEFAULT_STEP);

        let totp_good = totp
            .do_totp_duration_from_epoch(&ts)
            .expect("failed to perform totp.");

        let pw_badlist = "list@no3IBTyqHu$bad";

        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw_badlist)
            .unwrap()
            .update_totp(totp);
        // add totp also
        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();

        // now check

        // == two step checks

        // check send good totp, should continue
        //      then badlist pw, failed
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Totp(totp_good),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &mut audit,
                &AuthCredential::Password(pw_badlist.to_string()),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == PW_BADLIST_MSG),
                _ => panic!(),
            };
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
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

    fn setup_webauthn(
        name: &str,
    ) -> (
        webauthn_rs::Webauthn<crate::credential::webauthn::WebauthnDomainConfig>,
        webauthn_authenticator_rs::WebauthnAuthenticator<U2FSoft>,
        webauthn_rs::proto::Credential,
    ) {
        let webauthn = create_webauthn();
        // Setup a soft token
        let mut wa = WebauthnAuthenticator::new(U2FSoft::new());

        let (chal, reg_state) = webauthn
            .generate_challenge_register(name, false)
            .expect("Failed to setup webauthn rego challenge");

        let r = wa
            .do_registration("https://idm.example.com", chal)
            .expect("Failed to create soft token");

        let (wan_cred, _) = webauthn
            .register_credential(&r, &reg_state, |_| Ok(false))
            .expect("Failed to register soft token");

        (webauthn, wa, wan_cred)
    }

    #[test]
    fn test_idm_authsession_webauthn_only_mech() {
        let _ = tracing_tree::test_init();
        let mut audit = AuditScope::new(
            "test_idm_authsession_webauthn_only_mech",
            uuid::Uuid::new_v4(),
            None,
        );
        let (async_tx, mut async_rx) = unbounded();
        let ts = duration_from_epoch_now();
        // create the ent
        let mut account = entry_str_to_account!(JSON_ADMIN_V1);

        let (webauthn, mut wa, wan_cred) = setup_webauthn(account.name.as_str());
        let hs512 = create_hs512();

        // Now create the credential for the account.
        let cred = Credential::new_webauthn_only("soft".to_string(), wan_cred);
        account.primary = Some(cred);

        // now check correct mech was offered.

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
                None,
                &hs512,
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
                None,
                &hs512,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };
        }

        // Check the async counter update was sent.
        match async_rx.blocking_recv() {
            Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
            _ => assert!(false),
        }

        // Check bad challenge.
        {
            let (_session, inv_chal) = start_webauthn_only_session!(&mut audit, account, &webauthn);
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
                None,
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_WEBAUTHN_MSG),
                _ => panic!(),
            };
        }

        // Use an incorrect softtoken.
        {
            let mut inv_wa = WebauthnAuthenticator::new(U2FSoft::new());
            let (chal, reg_state) = webauthn
                .generate_challenge_register(&account.name, false)
                .expect("Failed to setup webauthn rego challenge");

            let r = inv_wa
                .do_registration("https://idm.example.com", chal)
                .expect("Failed to create soft token");

            let (inv_cred, _) = webauthn
                .register_credential(&r, &reg_state, |_| Ok(false))
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
                None,
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_WEBAUTHN_MSG),
                _ => panic!(),
            };
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        audit.write_log();
    }

    #[test]
    fn test_idm_authsession_webauthn_password_mech() {
        let _ = tracing_tree::test_init();
        let mut audit = AuditScope::new(
            "test_idm_authsession_webauthn_password_mech",
            uuid::Uuid::new_v4(),
            None,
        );
        let (async_tx, mut async_rx) = unbounded();
        let ts = duration_from_epoch_now();
        // create the ent
        let mut account = entry_str_to_account!(JSON_ADMIN_V1);

        let (webauthn, mut wa, wan_cred) = setup_webauthn(account.name.as_str());
        let hs512 = create_hs512();
        let pw_good = "test_password";
        let pw_bad = "bad_password";

        // Now create the credential for the account.
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw_good)
            .unwrap()
            .append_webauthn("soft".to_string(), wan_cred)
            .unwrap();

        account.primary = Some(cred);

        // check pw first (fail)
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Password(pw_bad.to_string()),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };
        }

        // Check totp first attempt fails.
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Totp(0),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };
        }

        // check bad webauthn (fail)
        // NOTE: We only check bad challenge here as bad softtoken is already
        // extensively tested.
        {
            let (_session, inv_chal, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);
            let (mut session, _chal, _) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            let inv_chal = inv_chal.unwrap();

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
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_WEBAUTHN_MSG),
                _ => panic!(),
            };
        }

        // check good webauthn/bad pw (fail)
        {
            let (mut session, chal, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);
            let chal = chal.unwrap();

            let resp = wa
                .do_authentication("https://idm.example.com", chal)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Webauthn(resp),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
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
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };

            // Check the async counter update was sent.
            match async_rx.blocking_recv() {
                Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
                _ => assert!(false),
            }
        }

        // Check good webauthn/good pw (pass)
        {
            let (mut session, chal, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);
            let chal = chal.unwrap();

            let resp = wa
                .do_authentication("https://idm.example.com", chal)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Webauthn(resp),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
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
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };

            // Check the async counter update was sent.
            match async_rx.blocking_recv() {
                Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
                _ => assert!(false),
            }
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        audit.write_log();
    }

    #[test]
    fn test_idm_authsession_webauthn_password_totp_mech() {
        let _ = tracing_tree::test_init();
        let mut audit = AuditScope::new(
            "test_idm_authsession_webauthn_password_totp_mech",
            uuid::Uuid::new_v4(),
            None,
        );
        let (async_tx, mut async_rx) = unbounded();
        let ts = duration_from_epoch_now();
        // create the ent
        let mut account = entry_str_to_account!(JSON_ADMIN_V1);

        let (webauthn, mut wa, wan_cred) = setup_webauthn(account.name.as_str());
        let hs512 = create_hs512();

        let totp = Totp::generate_secure(TOTP_DEFAULT_STEP);
        let totp_good = totp
            .do_totp_duration_from_epoch(&ts)
            .expect("failed to perform totp.");
        let totp_bad = totp
            .do_totp_duration_from_epoch(&Duration::from_secs(1234567))
            .expect("failed to perform totp.");
        assert!(totp_bad != totp_good);

        let pw_good = "test_password";
        let pw_bad = "bad_password";

        // Now create the credential for the account.
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw_good)
            .unwrap()
            .append_webauthn("soft".to_string(), wan_cred)
            .unwrap()
            .update_totp(totp);

        account.primary = Some(cred);

        // check pw first (fail)
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Password(pw_bad.to_string()),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };
        }

        // Check bad totp (fail)
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Totp(totp_bad),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_TOTP_MSG),
                _ => panic!(),
            };
        }

        // check bad webauthn (fail)
        {
            let (_session, inv_chal, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);
            let (mut session, _chal, _) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            let inv_chal = inv_chal.unwrap();

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
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_WEBAUTHN_MSG),
                _ => panic!(),
            };
        }

        // check good webauthn/bad pw (fail)
        {
            let (mut session, chal, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);
            let chal = chal.unwrap();

            let resp = wa
                .do_authentication("https://idm.example.com", chal)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Webauthn(resp),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
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
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };

            // Check the async counter update was sent.
            match async_rx.blocking_recv() {
                Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
                _ => assert!(false),
            }
        }

        // check good totp/bad pw (fail)
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Totp(totp_good),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
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
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };
        }

        // check good totp/good pw (pass)
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Totp(totp_good),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
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
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };
        }

        // Check good webauthn/good pw (pass)
        {
            let (mut session, chal, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);
            let chal = chal.unwrap();

            let resp = wa
                .do_authentication("https://idm.example.com", chal)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Webauthn(resp),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
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
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };

            // Check the async counter update was sent.
            match async_rx.blocking_recv() {
                Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
                _ => assert!(false),
            }
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        audit.write_log();
    }

    #[test]
    fn test_idm_authsession_backup_code_mech() {
        let _ = tracing_tree::test_init();
        let mut audit = AuditScope::new(
            "test_idm_authsession_backup_code_mech",
            uuid::Uuid::new_v4(),
            None,
        );
        let hs512 = create_hs512();
        let webauthn = create_webauthn();
        // create the ent
        let mut account = entry_str_to_account!(JSON_ADMIN_V1);

        // Setup a fake time stamp for consistency.
        let ts = Duration::from_secs(12345);

        // manually load in a cred
        let totp = Totp::generate_secure(TOTP_DEFAULT_STEP);

        let totp_good = totp
            .do_totp_duration_from_epoch(&ts)
            .expect("failed to perform totp.");

        let pw_good = "test_password";
        let pw_bad = "bad_password";

        let backup_code_good = readable_password_from_random();
        let backup_code_bad = readable_password_from_random();
        assert!(backup_code_bad != backup_code_good);
        let mut code_set = std::collections::HashSet::new();
        code_set.insert(backup_code_good.clone());

        let backup_codes = BackupCodes::new(code_set);

        // add totp and backup codes also
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw_good)
            .unwrap()
            .update_totp(totp)
            .update_backup_code(backup_codes)
            .unwrap();

        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();

        // now check
        // == two step checks

        // Sending a PW first is an immediate fail.
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Password(pw_bad.to_string()),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };
        }
        // check send wrong backup code, should fail immediate
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::BackupCode(backup_code_bad),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_BACKUPCODE_MSG),
                _ => panic!(),
            };
        }
        // check send good backup code, should continue
        //      then bad pw, fail pw
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::BackupCode(backup_code_good.clone()),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
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
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };
        }
        // Can't process BackupCodeRemoval without the server instance
        match async_rx.blocking_recv() {
            Some(DelayedAction::BackupCodeRemoval(_)) => {}
            _ => assert!(false),
        }

        // check send good backup code, should continue
        //      then good pw, success
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::BackupCode(backup_code_good.clone()),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
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
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };
        }
        // Can't process BackupCodeRemoval without the server instance
        match async_rx.blocking_recv() {
            Some(DelayedAction::BackupCodeRemoval(_)) => {}
            _ => assert!(false),
        }

        // TOTP should also work:
        // check send good TOTP, should continue
        //      then good pw, success
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &mut audit,
                &AuthCredential::Totp(totp_good),
                &ts,
                &async_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &hs512,
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
                Some(&pw_badlist_cache),
                &hs512,
            ) {
                Ok(AuthState::Success(_)) => {}
                _ => panic!(),
            };
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        audit.write_log();
    }
}
