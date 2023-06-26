//! This module contains the logic to conduct an authentication of an account.
//! Generally this has to process an authentication attempt, and validate each
//! factor to assert that the user is legitimate. This also contains some
//! support code for asynchronous task execution.
use std::collections::BTreeMap;
pub use std::collections::BTreeSet as Set;
use std::convert::TryFrom;
use std::fmt;
use std::time::Duration;

// use webauthn_rs::proto::Credential as WebauthnCredential;
use compact_jwt::{Jws, JwsSigner};
use hashbrown::HashSet;
use kanidm_proto::v1::{
    AuthAllowed, AuthCredential, AuthIssueSession, AuthMech, OperationError, UserAuthToken,
};
// use crossbeam::channel::Sender;
use tokio::sync::mpsc::UnboundedSender as Sender;
use uuid::Uuid;
// use webauthn_rs::prelude::DeviceKey as DeviceKeyV4;
use nonempty::{nonempty, NonEmpty};
use webauthn_rs::prelude::Passkey as PasskeyV4;
use webauthn_rs::prelude::{
    CredentialID, PasskeyAuthentication, RequestChallengeResponse, SecurityKeyAuthentication,
    Webauthn,
};

use crate::credential::totp::Totp;
use crate::credential::{BackupCodes, Credential, CredentialType, Password};
use crate::idm::account::Account;
use crate::idm::audit::AuditEvent;
use crate::idm::delayed::{
    AuthSessionRecord, BackupCodeRemoval, DelayedAction, PasswordUpgrade, WebauthnCounterIncrement,
};
use crate::idm::AuthState;
use crate::prelude::*;
use crate::value::Session;
use time::OffsetDateTime;

// Each CredHandler takes one or more credentials and determines if the
// handlers requirements can be 100% fulfilled. This is where MFA or other
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

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum AuthType {
    Anonymous,
    UnixPassword,
    Password,
    GeneratedPassword,
    PasswordMfa,
    Passkey,
}

impl fmt::Display for AuthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthType::Anonymous => write!(f, "anonymous"),
            AuthType::UnixPassword => write!(f, "unixpassword"),
            AuthType::Password => write!(f, "password"),
            AuthType::GeneratedPassword => write!(f, "generatedpassword"),
            AuthType::PasswordMfa => write!(f, "passwordmfa"),
            AuthType::Passkey => write!(f, "passkey"),
        }
    }
}

#[derive(Debug, Clone)]
enum AuthIntent {
    InitialAuth,
    Reauth {
        session_id: Uuid,
        session_expiry: Option<OffsetDateTime>,
    },
}

/// A response type to indicate the progress and potential result of an authentication attempt.
enum CredState {
    Success { auth_type: AuthType, cred_id: Uuid },
    Continue(NonEmpty<AuthAllowed>),
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
    totp: BTreeMap<String, Totp>,
    wan: Option<(RequestChallengeResponse, SecurityKeyAuthentication)>,
    backup_code: Option<BackupCodes>,
    mfa_state: CredVerifyState,
}

#[derive(Clone, Debug)]
/// The state of a webauthn credential during authentication
struct CredWebauthn {
    chal: RequestChallengeResponse,
    wan_state: PasskeyAuthentication,
    state: CredVerifyState,
}

/// The current active handler for this authentication session. This is determined from what credentials
/// are possible from the account, and what the user selected as the preferred authentication
/// mechanism.
#[derive(Clone, Debug)]
enum CredHandler {
    Anonymous {
        cred_id: Uuid,
    },
    Password {
        pw: Password,
        generated: bool,
        cred_id: Uuid,
    },
    PasswordMfa {
        cmfa: Box<CredMfa>,
        cred_id: Uuid,
    },
    Passkey {
        c_wan: CredWebauthn,
        cred_ids: BTreeMap<CredentialID, Uuid>,
    },
}

impl TryFrom<(&Credential, &Webauthn)> for CredHandler {
    type Error = ();

    /// Given a credential and some external configuration, Generate the credential handler
    /// that will be used for this session. This credential handler is a "self contained"
    /// unit that defines what is possible to use during this authentication session to prevent
    /// inconsistency.
    fn try_from((c, webauthn): (&Credential, &Webauthn)) -> Result<Self, Self::Error> {
        match &c.type_ {
            CredentialType::Password(pw) => Ok(CredHandler::Password {
                pw: pw.clone(),
                generated: false,
                cred_id: c.uuid,
            }),
            CredentialType::GeneratedPassword(pw) => Ok(CredHandler::Password {
                pw: pw.clone(),
                generated: true,
                cred_id: c.uuid,
            }),
            CredentialType::PasswordMfa(pw, maybe_totp, maybe_wan, maybe_backup_code) => {
                let wan = if !maybe_wan.is_empty() {
                    let sks: Vec<_> = maybe_wan.values().cloned().collect();
                    webauthn
                        .start_securitykey_authentication(&sks)
                        .map(Some)
                        .map_err(|e| {
                            security_info!(
                                err = ?e,
                                "Unable to create webauthn authentication challenge"
                            )
                        })?
                } else {
                    None
                };

                let cmfa = Box::new(CredMfa {
                    pw: pw.clone(),
                    pw_state: CredVerifyState::Init,
                    totp: maybe_totp
                        .iter()
                        .map(|(l, t)| (l.clone(), t.clone()))
                        .collect(),
                    wan,
                    backup_code: maybe_backup_code.clone(),
                    mfa_state: CredVerifyState::Init,
                });

                // Paranoia. Should NEVER occur.
                if cmfa.totp.is_empty() && cmfa.wan.is_none() {
                    security_critical!("Unable to create CredHandler::PasswordMfa - totp and webauthn are both not present. Credentials MAY be corrupt!");
                    return Err(());
                }

                Ok(CredHandler::PasswordMfa {
                    cmfa,
                    cred_id: c.uuid,
                })
            }
            CredentialType::Webauthn(wan) => {
                let pks: Vec<_> = wan.values().cloned().collect();
                let cred_ids: BTreeMap<_, _> = pks
                    .iter()
                    .map(|pk| (pk.cred_id().clone(), c.uuid))
                    .collect();
                webauthn
                    .start_passkey_authentication(&pks)
                    .map(|(chal, wan_state)| CredHandler::Passkey {
                        c_wan: CredWebauthn {
                            chal,
                            wan_state,
                            state: CredVerifyState::Init,
                        },
                        cred_ids,
                    })
                    .map_err(|e| {
                        security_info!(?e, "Unable to create webauthn authentication challenge");
                        // maps to unit.
                    })
            }
        }
    }
}

impl TryFrom<(&BTreeMap<Uuid, (String, PasskeyV4)>, &Webauthn)> for CredHandler {
    type Error = ();

    /// Given a credential and some external configuration, Generate the credential handler
    /// that will be used for this session. This credential handler is a "self contained"
    /// unit that defines what is possible to use during this authentication session to prevent
    /// inconsistency.
    fn try_from(
        (wan, webauthn): (&BTreeMap<Uuid, (String, PasskeyV4)>, &Webauthn),
    ) -> Result<Self, Self::Error> {
        if wan.is_empty() {
            security_info!("Account does not have any passkeys");
            return Err(());
        }

        let pks: Vec<_> = wan.values().map(|(_, k)| k).cloned().collect();
        let cred_ids: BTreeMap<_, _> = wan
            .iter()
            .map(|(u, (_, k))| (k.cred_id().clone(), *u))
            .collect();

        webauthn
            .start_passkey_authentication(&pks)
            .map(|(chal, wan_state)| CredHandler::Passkey {
                c_wan: CredWebauthn {
                    chal,
                    wan_state,
                    state: CredVerifyState::Init,
                },
                cred_ids,
            })
            .map_err(|e| {
                security_info!(
                    ?e,
                    "Unable to create passkey webauthn authentication challenge"
                );
                // maps to unit.
            })
    }
}

impl TryFrom<(Uuid, &PasskeyV4, &Webauthn)> for CredHandler {
    type Error = ();
    fn try_from(
        (cred_id, pk, webauthn): (Uuid, &PasskeyV4, &Webauthn),
    ) -> Result<Self, Self::Error> {
        let cred_ids = btreemap!((pk.cred_id().clone(), cred_id));
        let pks = vec![pk.clone()];

        webauthn
            .start_passkey_authentication(pks.as_slice())
            .map(|(chal, wan_state)| CredHandler::Passkey {
                c_wan: CredWebauthn {
                    chal,
                    wan_state,
                    state: CredVerifyState::Init,
                },
                cred_ids,
            })
            .map_err(|e| {
                security_info!(
                    ?e,
                    "Unable to create passkey webauthn authentication challenge"
                );
                // maps to unit.
            })
    }
}

impl CredHandler {
    /// Determine if this password factor requires an upgrade of it's cryptographic type. If
    /// so, send an asynchronous event into the queue that will allow the password to have it's
    /// content upgraded later.
    fn maybe_pw_upgrade(
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
            };
        }
    }

    /// validate that the client wants to authenticate as the anonymous user.
    fn validate_anonymous(cred: &AuthCredential, cred_id: Uuid) -> CredState {
        match cred {
            AuthCredential::Anonymous => {
                // For anonymous, no claims will ever be issued.
                security_debug!("Handler::Anonymous -> Result::Success");
                CredState::Success {
                    auth_type: AuthType::Anonymous,
                    cred_id,
                }
            }
            _ => {
                security_error!(
                    "Handler::Anonymous -> Result::Denied - invalid cred type for handler"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    /// Validate a singule password credential of the account.
    fn validate_password(
        cred: &AuthCredential,
        cred_id: Uuid,
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
                            security_error!("Handler::Password -> Result::Denied - Password found in badlist during login");
                            CredState::Denied(PW_BADLIST_MSG)
                        }
                        _ => {
                            security_info!("Handler::Password -> Result::Success");
                            Self::maybe_pw_upgrade(pw, who, cleartext.as_str(), async_tx);
                            if generated {
                                CredState::Success {
                                    auth_type: AuthType::GeneratedPassword,
                                    cred_id,
                                }
                            } else {
                                CredState::Success {
                                    auth_type: AuthType::Password,
                                    cred_id,
                                }
                            }
                        }
                    }
                } else {
                    security_error!("Handler::Password -> Result::Denied - incorrect password");
                    CredState::Denied(BAD_PASSWORD_MSG)
                }
            }
            // All other cases fail.
            _ => {
                security_error!(
                    "Handler::Password -> Result::Denied - invalid cred type for handler"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    /// Proceed with the next step in a multifactor authentication, based on the current
    /// verification results and state. If this logic of this statemachine is violated, the
    /// authentication will fail.
    fn validate_password_mfa(
        cred: &AuthCredential,
        cred_id: Uuid,
        ts: Duration,
        pw_mfa: &mut CredMfa,
        webauthn: &Webauthn,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
        pw_badlist_set: Option<&HashSet<String>>,
    ) -> CredState {
        match (&pw_mfa.mfa_state, &pw_mfa.pw_state) {
            (CredVerifyState::Init, CredVerifyState::Init) => {
                // MFA first
                match (
                    cred,
                    !pw_mfa.totp.is_empty(),
                    pw_mfa.wan.as_ref(),
                    pw_mfa.backup_code.as_ref(),
                ) {
                    (AuthCredential::SecurityKey(resp), _, Some((_, wan_state)), _) => {
                        match webauthn.finish_securitykey_authentication(resp, wan_state) {
                            Ok(auth_result) => {
                                pw_mfa.mfa_state = CredVerifyState::Success;
                                // Success. Determine if we need to update the counter
                                // async from r.
                                if auth_result.needs_update() {
                                    // Do async
                                    if let Err(_e) =
                                        async_tx.send(DelayedAction::WebauthnCounterIncrement(
                                            WebauthnCounterIncrement {
                                                target_uuid: who,
                                                auth_result,
                                            },
                                        ))
                                    {
                                        admin_warn!("unable to queue delayed webauthn property update, continuing ... ");
                                    };
                                };
                                CredState::Continue(nonempty![AuthAllowed::Password])
                            }
                            Err(e) => {
                                pw_mfa.mfa_state = CredVerifyState::Fail;
                                // Denied.
                                security_error!(
                                    ?e,
                                    "Handler::Webauthn -> Result::Denied - webauthn error"
                                );
                                CredState::Denied(BAD_WEBAUTHN_MSG)
                            }
                        }
                    }
                    (AuthCredential::Totp(totp_chal), true, _, _) => {
                        // So long as one totp matches, success. Log which token was used.
                        // We don't need to worry about the empty case since none will match and we
                        // will get the failure.
                        if let Some(label) = pw_mfa
                            .totp
                            .iter()
                            .find(|(_, t)| t.verify(*totp_chal, ts))
                            .map(|(l, _)| l)
                        {
                            pw_mfa.mfa_state = CredVerifyState::Success;
                            security_info!(
                                "Handler::PasswordMfa -> Result::Continue - TOTP ({}) OK, password -", label
                            );
                            CredState::Continue(nonempty![AuthAllowed::Password])
                        } else {
                            pw_mfa.mfa_state = CredVerifyState::Fail;
                            security_error!(
                                "Handler::PasswordMfa -> Result::Denied - TOTP Fail, password -"
                            );
                            CredState::Denied(BAD_TOTP_MSG)
                        }
                    }
                    (AuthCredential::BackupCode(code_chal), _, _, Some(backup_codes)) => {
                        if backup_codes.verify(code_chal) {
                            if let Err(_e) =
                                async_tx.send(DelayedAction::BackupCodeRemoval(BackupCodeRemoval {
                                    target_uuid: who,
                                    code_to_remove: code_chal.to_string(),
                                }))
                            {
                                admin_warn!(
                                    "unable to queue delayed backup code removal, continuing ... "
                                );
                            };
                            pw_mfa.mfa_state = CredVerifyState::Success;
                            security_info!("Handler::PasswordMfa -> Result::Continue - BackupCode OK, password -");
                            CredState::Continue(nonempty![AuthAllowed::Password])
                        } else {
                            pw_mfa.mfa_state = CredVerifyState::Fail;
                            security_error!("Handler::PasswordMfa -> Result::Denied - BackupCode Fail, password -");
                            CredState::Denied(BAD_BACKUPCODE_MSG)
                        }
                    }
                    _ => {
                        security_error!("Handler::PasswordMfa -> Result::Denied - invalid cred type for handler");
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
                                    security_error!("Handler::PasswordMfa -> Result::Denied - Password found in badlist during login");
                                    CredState::Denied(PW_BADLIST_MSG)
                                }
                                _ => {
                                    pw_mfa.pw_state = CredVerifyState::Success;
                                    security_info!("Handler::PasswordMfa -> Result::Success - TOTP/WebAuthn/BackupCode OK, password OK");
                                    Self::maybe_pw_upgrade(
                                        &pw_mfa.pw,
                                        who,
                                        cleartext.as_str(),
                                        async_tx,
                                    );
                                    CredState::Success {
                                        auth_type: AuthType::PasswordMfa,
                                        cred_id,
                                    }
                                }
                            }
                        } else {
                            pw_mfa.pw_state = CredVerifyState::Fail;
                            security_error!("Handler::PasswordMfa -> Result::Denied - TOTP/WebAuthn/BackupCode OK, password Fail");
                            CredState::Denied(BAD_PASSWORD_MSG)
                        }
                    }
                    _ => {
                        security_error!("Handler::PasswordMfa -> Result::Denied - invalid cred type for handler");
                        CredState::Denied(BAD_AUTH_TYPE_MSG)
                    }
                }
            }
            _ => {
                security_error!(
                    "Handler::PasswordMfa -> Result::lenied - invalid credential mfa and pw state"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    // end CredHandler::PasswordMfa

    /// Validate a webauthn authentication attempt
    pub fn validate_webauthn(
        cred: &AuthCredential,
        cred_ids: &BTreeMap<CredentialID, Uuid>,
        wan_cred: &mut CredWebauthn,
        webauthn: &Webauthn,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
    ) -> CredState {
        if wan_cred.state != CredVerifyState::Init {
            security_error!("Handler::Webauthn -> Result::Denied - Internal State Already Fail");
            return CredState::Denied(BAD_WEBAUTHN_MSG);
        }

        match cred {
            AuthCredential::Passkey(resp) => {
                // lets see how we go.
                match webauthn.finish_passkey_authentication(resp, &wan_cred.wan_state) {
                    Ok(auth_result) => {
                        if let Some(cred_id) = cred_ids.get(auth_result.cred_id()).copied() {
                            wan_cred.state = CredVerifyState::Success;
                            // Success. Determine if we need to update the counter
                            // async from r.
                            if auth_result.needs_update() {
                                // Do async
                                if let Err(_e) =
                                    async_tx.send(DelayedAction::WebauthnCounterIncrement(
                                        WebauthnCounterIncrement {
                                            target_uuid: who,
                                            auth_result,
                                        },
                                    ))
                                {
                                    admin_warn!("unable to queue delayed webauthn property update, continuing ... ");
                                };
                            };

                            CredState::Success {
                                auth_type: AuthType::Passkey,
                                cred_id,
                            }
                        } else {
                            wan_cred.state = CredVerifyState::Fail;
                            // Denied.
                            security_error!("Handler::Webauthn -> Result::Denied - webauthn credential id not found");
                            CredState::Denied(BAD_WEBAUTHN_MSG)
                        }
                    }
                    Err(e) => {
                        wan_cred.state = CredVerifyState::Fail;
                        // Denied.
                        security_error!(?e, "Handler::Webauthn -> Result::Denied - webauthn error");
                        CredState::Denied(BAD_WEBAUTHN_MSG)
                    }
                }
            }
            _ => {
                security_error!(
                    "Handler::Webauthn -> Result::Denied - invalid cred type for handler"
                );
                CredState::Denied(BAD_AUTH_TYPE_MSG)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    /// Given the current handler, proceed to authenticate the attempted credential step.
    pub fn validate(
        &mut self,
        cred: &AuthCredential,
        ts: Duration,
        who: Uuid,
        async_tx: &Sender<DelayedAction>,
        webauthn: &Webauthn,
        pw_badlist_set: Option<&HashSet<String>>,
    ) -> CredState {
        match self {
            CredHandler::Anonymous { cred_id } => Self::validate_anonymous(cred, *cred_id),
            CredHandler::Password {
                ref mut pw,
                generated,
                cred_id,
            } => Self::validate_password(
                cred,
                *cred_id,
                pw,
                *generated,
                who,
                async_tx,
                pw_badlist_set,
            ),
            CredHandler::PasswordMfa {
                ref mut cmfa,
                cred_id,
            } => Self::validate_password_mfa(
                cred,
                *cred_id,
                ts,
                cmfa,
                webauthn,
                who,
                async_tx,
                pw_badlist_set,
            ),
            CredHandler::Passkey {
                ref mut c_wan,
                cred_ids,
            } => Self::validate_webauthn(cred, cred_ids, c_wan, webauthn, who, async_tx),
        }
    }

    /// Determine based on the current status, what is the next allowed step that
    /// can proceed.
    pub fn next_auth_allowed(&self) -> Vec<AuthAllowed> {
        match &self {
            CredHandler::Anonymous { .. } => vec![AuthAllowed::Anonymous],
            CredHandler::Password { .. } => vec![AuthAllowed::Password],
            CredHandler::PasswordMfa { ref cmfa, .. } => cmfa
                .backup_code
                .iter()
                .map(|_| AuthAllowed::BackupCode)
                // This looks weird but the idea is that if at least *one*
                // totp exists, then we only offer TOTP once. If none are
                // there we offer it none.
                .chain(cmfa.totp.iter().next().map(|_| AuthAllowed::Totp))
                // This iter is over an option so it's there or not.
                .chain(
                    cmfa.wan
                        .iter()
                        .map(|(chal, _)| AuthAllowed::SecurityKey(chal.clone())),
                )
                .collect(),
            CredHandler::Passkey { c_wan, .. } => vec![AuthAllowed::Passkey(c_wan.chal.clone())],
        }
    }

    /// Determine which mechanismes can proceed given the requested mechanism.
    fn can_proceed(&self, mech: &AuthMech) -> bool {
        match (self, mech) {
            (CredHandler::Anonymous { .. }, AuthMech::Anonymous)
            | (CredHandler::Password { .. }, AuthMech::Password)
            | (CredHandler::PasswordMfa { .. }, AuthMech::PasswordMfa)
            | (CredHandler::Passkey { .. }, AuthMech::Passkey) => true,
            (_, _) => false,
        }
    }

    fn allows_mech(&self) -> AuthMech {
        match self {
            CredHandler::Anonymous { .. } => AuthMech::Anonymous,
            CredHandler::Password { .. } => AuthMech::Password,
            CredHandler::PasswordMfa { .. } => AuthMech::PasswordMfa,
            CredHandler::Passkey { .. } => AuthMech::Passkey,
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
/// This interleaves with the client auth step. The client sends an "init"
/// and we go to the init state, sending back the list of what can proceed.
/// The client then sends a "begin" with the chosen mech that moves to
/// "InProgress", "Success" or "Denied". From there the CredHandler
/// is interacted with until we move to either "Success" or "Denied".
enum AuthSessionState {
    Init(NonEmpty<CredHandler>),
    // Stop! Don't make this a vec - make the credhandler able to hold multiple
    // internal copies of it's type and check against them all.
    //
    // Clippy wants this to be boxxed, however match on box types is a pain / problematic,
    // so I'm not sure it can be done.
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

    // The type of session we will issue if successful
    issue: AuthIssueSession,

    // What is the "intent" behind this auth session? Are we doing an initial auth? Or a re-auth
    // for a privilege grant?
    intent: AuthIntent,

    // Where did the event come from?
    source: Source,
}

impl AuthSession {
    /// Create a new auth session, based on the available credential handlers of the account.
    /// the session is a whole encapsulated unit of what we need to proceed, so that subsequent
    /// or interleved write operations do not cause inconsistency in this process.
    pub fn new(
        account: Account,
        issue: AuthIssueSession,
        webauthn: &Webauthn,
        ct: Duration,
        source: Source,
    ) -> (Option<Self>, AuthState) {
        // During this setup, determine the credential handler that we'll be using
        // for this session. This is currently based on presentation of an application
        // id.
        let state = if account.is_within_valid_time(ct) {
            // We want the primary handler - this is where we make a decision
            // based on the anonymous ... in theory this could be cleaner
            // and interact with the account more?
            if account.is_anonymous() {
                AuthSessionState::Init(nonempty![CredHandler::Anonymous {
                    cred_id: account.uuid,
                }])
            } else {
                // What's valid to use in this context?
                let mut handlers = Vec::new();

                if let Some(cred) = &account.primary {
                    // TODO: Make it possible to have multiple creds.
                    // Probably means new authsession has to be failable
                    if let Ok(ch) = CredHandler::try_from((cred, webauthn)) {
                        handlers.push(ch);
                    } else {
                        security_critical!(
                            "corrupt credentials, unable to start primary credhandler"
                        );
                    }
                }

                if let Ok(ch) = CredHandler::try_from((&account.passkeys, webauthn)) {
                    handlers.push(ch);
                };

                if let Some(non_empty_handlers) = NonEmpty::collect(handlers.into_iter()) {
                    AuthSessionState::Init(non_empty_handlers)
                } else {
                    security_info!("account has no available credentials");
                    AuthSessionState::Denied("invalid credential state")
                }
            }
        } else {
            security_info!("account expired");
            AuthSessionState::Denied(ACCOUNT_EXPIRED)
        };

        // if credhandler == deny, finish = true.
        if let Some(reason) = state.is_denied() {
            // Already denied, lets send that result
            (None, AuthState::Denied(reason.to_string()))
        } else {
            // We can proceed
            let auth_session = AuthSession {
                account,
                state,
                issue,
                intent: AuthIntent::InitialAuth,
                source,
            };
            // Get the set of mechanisms that can proceed. This is tied
            // to the session so that it can mutate state and have progression
            // of what's next, or ordering.
            let valid_mechs = auth_session.valid_auth_mechs();

            security_debug!(?valid_mechs, "Offering auth mechanisms");
            let as_state = AuthState::Choose(valid_mechs);
            (Some(auth_session), as_state)
        }
    }

    /// Build a new auth session which has been preconfigured for re-authentication.
    /// This differs from [`AuthSession::new`] as we preselect the credential that
    /// will be used in this operation based on the credential id that was used in the
    /// initial authentication.
    pub(crate) fn new_reauth(
        account: Account,
        session_id: Uuid,
        session: &Session,
        cred_id: Uuid,
        issue: AuthIssueSession,
        webauthn: &Webauthn,
        ct: Duration,
        source: Source,
    ) -> (Option<Self>, AuthState) {
        /// An inner enum to allow us to more easily define state within this fn
        enum State {
            Expired,
            NoMatchingCred,
            Proceed(CredHandler),
        }

        let state = if account.is_within_valid_time(ct) {
            // Get the credential that matches this cred_id.
            //
            // To make this work "cleanly" we can't really nest a bunch of if
            // statements like if primary and if primary.cred_id because the logic will
            // just be chaos. So for now we build this as a mut option.
            //
            // Do we need to double check for anon here? I don't think so since the
            // anon cred_id won't ever exist on an account.

            let mut cred_handler = None;

            if let Some(primary) = account.primary.as_ref() {
                if primary.uuid == cred_id {
                    if let Ok(ch) = CredHandler::try_from((primary, webauthn)) {
                        // Update it.
                        debug_assert!(cred_handler.is_none());
                        cred_handler = Some(ch);
                    } else {
                        security_critical!(
                            "corrupt credentials, unable to start primary credhandler"
                        );
                    }
                }
            }

            if let Some(pk) = account.passkeys.get(&cred_id).map(|(_, pk)| pk) {
                if let Ok(ch) = CredHandler::try_from((cred_id, pk, webauthn)) {
                    // Update it.
                    debug_assert!(cred_handler.is_none());
                    cred_handler = Some(ch);
                } else {
                    security_critical!("corrupt credentials, unable to start primary credhandler");
                }
            }

            // Did anything get set-up?

            if let Some(cred_handler) = cred_handler {
                State::Proceed(cred_handler)
            } else {
                State::NoMatchingCred
            }
        } else {
            State::Expired
        };

        match state {
            State::Proceed(handler) => {
                let allow = handler.next_auth_allowed();
                let auth_session = AuthSession {
                    account,
                    state: AuthSessionState::InProgress(handler),
                    issue,
                    intent: AuthIntent::Reauth {
                        session_id,
                        session_expiry: session.expiry,
                    },
                    source,
                };

                let as_state = AuthState::Continue(allow);
                (Some(auth_session), as_state)
            }
            State::Expired => {
                security_info!("account expired");
                (None, AuthState::Denied(ACCOUNT_EXPIRED.to_string()))
            }
            State::NoMatchingCred => {
                security_error!("Unable to select a credential for authentication");
                (None, AuthState::Denied(BAD_CREDENTIALS.to_string()))
            }
        }
    }

    // This is used for softlock identification only.
    pub fn get_credential_uuid(&self) -> Result<Option<Uuid>, OperationError> {
        match &self.state {
            AuthSessionState::InProgress(CredHandler::Password { cred_id, .. })
            | AuthSessionState::InProgress(CredHandler::PasswordMfa { cred_id, .. }) => {
                Ok(Some(*cred_id))
            }
            AuthSessionState::InProgress(CredHandler::Anonymous { .. })
            | AuthSessionState::InProgress(CredHandler::Passkey { .. }) => Ok(None),
            _ => Err(OperationError::InvalidState),
        }
    }

    /// Given the users indicated and preferred authentication mechanism that they want to proceed
    /// with, select the credential handler and begin the process of stepping through the
    /// authentication process.
    pub fn start_session(
        &mut self,
        mech: &AuthMech,
        // time: &Duration,
        // webauthn: &WebauthnCore,
    ) -> Result<AuthState, OperationError> {
        // Given some auth mech, select which credential(s) are appropriate
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
                        security_info!("Unable to negotiate credentials");
                        (
                            None,
                            Err(OperationError::InvalidAuthState(
                                "unable to negotiate credentials".to_string(),
                            )),
                        )
                    } else {
                        (
                            Some(AuthSessionState::InProgress(allowed_handler)),
                            Ok(AuthState::Continue(allowed)),
                        )
                    }
                } else {
                    security_error!("Unable to select a credential for authentication");
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

    /// Conduct a step of the authentication process. This validates the next credential factor
    /// presented and returns a result of Success, Continue, or Denied. Only in the success
    /// case is a UAT granted -- all others do not, including raised operation errors.
    pub fn validate_creds(
        &mut self,
        cred: &AuthCredential,
        time: Duration,
        async_tx: &Sender<DelayedAction>,
        audit_tx: &Sender<AuditEvent>,
        webauthn: &Webauthn,
        pw_badlist_set: Option<&HashSet<String>>,
        uat_jwt_signer: &JwsSigner,
    ) -> Result<AuthState, OperationError> {
        let (next_state, response) = match &mut self.state {
            AuthSessionState::Init(_) | AuthSessionState::Success | AuthSessionState::Denied(_) => {
                return Err(OperationError::InvalidAuthState(
                    "session already finalised!".to_string(),
                ));
            }
            AuthSessionState::InProgress(ref mut handler) => {
                match handler.validate(
                    cred,
                    time,
                    self.account.uuid,
                    async_tx,
                    webauthn,
                    pw_badlist_set,
                ) {
                    CredState::Success { auth_type, cred_id } => {
                        // Issue the uat based on a set of factors.
                        let uat = self.issue_uat(&auth_type, time, async_tx, cred_id)?;
                        let jwt = Jws::new(uat);

                        // Now encrypt and prepare the token for return to the client.
                        let token = jwt
                            // Do we want to embed this? Or just give the URL? I think we embed
                            // as we only need the client to be able to check it's not tampered, but
                            // this isn't a root of trust.
                            .sign_embed_public_jwk(uat_jwt_signer)
                            .map(|jwts| jwts.to_string())
                            .map_err(|e| {
                                admin_error!(?e, "Failed to sign UserAuthToken to Jwt");
                                OperationError::InvalidState
                            })?;

                        (
                            Some(AuthSessionState::Success),
                            Ok(AuthState::Success(token, self.issue)),
                        )
                    }
                    CredState::Continue(allowed) => {
                        security_info!(?allowed, "Request credential continuation");
                        (None, Ok(AuthState::Continue(allowed.into_iter().collect())))
                    }
                    CredState::Denied(reason) => {
                        if audit_tx
                            .send(AuditEvent::AuthenticationDenied {
                                source: self.source.clone().into(),
                                spn: self.account.spn.clone(),
                                uuid: self.account.uuid,
                                time: OffsetDateTime::UNIX_EPOCH + time,
                            })
                            .is_err()
                        {
                            error!("Unable to submit audit event to queue");
                        }
                        security_info!(%reason, "Credentials denied");
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

        // If this succeeds audit?
        //  If success, to authtoken?

        response
    }

    fn issue_uat(
        &mut self,
        auth_type: &AuthType,
        time: Duration,
        async_tx: &Sender<DelayedAction>,
        cred_id: Uuid,
    ) -> Result<UserAuthToken, OperationError> {
        security_debug!("Successful cred handling");
        match self.intent {
            AuthIntent::InitialAuth => {
                let session_id = Uuid::new_v4();
                // We need to actually work this out better, and then
                // pass it to to_userauthtoken
                let scope = match auth_type {
                    AuthType::UnixPassword | AuthType::Anonymous => SessionScope::ReadOnly,
                    AuthType::GeneratedPassword => SessionScope::ReadWrite,
                    AuthType::Password | AuthType::PasswordMfa | AuthType::Passkey => {
                        SessionScope::PrivilegeCapable
                    }
                };

                security_info!(
                    "Issuing {:?} session {} for {} {}",
                    self.issue,
                    session_id,
                    self.account.spn,
                    self.account.uuid
                );

                let uat = self
                    .account
                    .to_userauthtoken(session_id, scope, time)
                    .ok_or(OperationError::InvalidState)?;

                // Queue the session info write.
                // This is dependent on the type of authentication factors
                // used. Generally we won't submit for Anonymous. Add an extra
                // safety barrier for auth types that shouldn't be here. Generally we
                // submit session info for everything else.
                match auth_type {
                    AuthType::Anonymous => {
                        // Skip - these sessions are not validated by session id.
                    }
                    AuthType::UnixPassword => {
                        // Impossibru!
                        admin_error!("Impossible auth type (UnixPassword) found");
                        return Err(OperationError::InvalidState);
                    }
                    AuthType::Password
                    | AuthType::GeneratedPassword
                    | AuthType::PasswordMfa
                    | AuthType::Passkey => {
                        trace!("⚠️   Queued AuthSessionRecord for {}", self.account.uuid);
                        async_tx.send(DelayedAction::AuthSessionRecord(AuthSessionRecord {
                            target_uuid: self.account.uuid,
                            session_id,
                            cred_id,
                            label: "Auth Session".to_string(),
                            expiry: uat.expiry,
                            issued_at: uat.issued_at,
                            issued_by: IdentityId::User(self.account.uuid),
                            scope,
                        }))
                        .map_err(|e| {
                            debug!(?e, "queue failure");
                            admin_error!("unable to queue failing authentication as the session will not validate ... ");
                            OperationError::InvalidState
                        })?;
                    }
                };

                Ok(uat)
            }
            AuthIntent::Reauth {
                session_id,
                session_expiry,
            } => {
                // Sanity check - We have already been really strict about what session types
                // can actually trigger a re-auth, but we recheck here for paranoia!
                let scope = match auth_type {
                    AuthType::UnixPassword | AuthType::Anonymous | AuthType::GeneratedPassword => {
                        error!("AuthType used in Reauth is not valid for session re-issuance. Rejecting");
                        return Err(OperationError::InvalidState);
                    }
                    AuthType::Password | AuthType::PasswordMfa | AuthType::Passkey => {
                        SessionScope::PrivilegeCapable
                    }
                };

                let uat = self
                    .account
                    .to_reissue_userauthtoken(session_id, session_expiry, scope, time)
                    .ok_or(OperationError::InvalidState)?;

                Ok(uat)
            }
        }
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
    pub use std::collections::BTreeSet as Set;
    use std::time::Duration;

    use compact_jwt::JwsSigner;
    use hashbrown::HashSet;
    use kanidm_proto::v1::{AuthAllowed, AuthCredential, AuthIssueSession, AuthMech};
    use tokio::sync::mpsc::unbounded_channel as unbounded;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_authenticator_rs::WebauthnAuthenticator;

    use crate::credential::totp::{Totp, TOTP_DEFAULT_STEP};
    use crate::credential::{BackupCodes, Credential};
    use crate::idm::audit::AuditEvent;
    use crate::idm::authsession::{
        AuthSession, BAD_AUTH_TYPE_MSG, BAD_BACKUPCODE_MSG, BAD_PASSWORD_MSG, BAD_TOTP_MSG,
        BAD_WEBAUTHN_MSG, PW_BADLIST_MSG,
    };
    use crate::idm::delayed::DelayedAction;
    use crate::idm::AuthState;
    use crate::prelude::*;
    use crate::utils::{duration_from_epoch_now, readable_password_from_random};
    use kanidm_lib_crypto::CryptoPolicy;

    fn create_pw_badlist_cache() -> HashSet<String> {
        let mut s = HashSet::new();
        s.insert("list@no3IBTyqHu$bad".to_lowercase());
        s
    }

    fn create_webauthn() -> webauthn_rs::Webauthn {
        webauthn_rs::WebauthnBuilder::new(
            "example.com",
            &url::Url::parse("https://idm.example.com").unwrap(),
        )
        .and_then(|builder| builder.build())
        .unwrap()
    }

    fn create_jwt_signer() -> JwsSigner {
        JwsSigner::generate_es256().expect("failed to construct signer.")
    }

    #[test]
    fn test_idm_authsession_anonymous_auth_mech() {
        sketching::test_init();

        let webauthn = create_webauthn();

        let anon_account = entry_to_account!(E_ANONYMOUS_V1.clone());

        let (session, state) = AuthSession::new(
            anon_account,
            AuthIssueSession::Token,
            &webauthn,
            duration_from_epoch_now(),
            Source::Internal,
        );

        if let AuthState::Choose(auth_mechs) = state {
            assert!(auth_mechs.iter().any(|x| matches!(x, AuthMech::Anonymous)));
        } else {
            panic!("Invalid auth state")
        }

        let state = session
            .expect("Missing auth session?")
            .start_session(&AuthMech::Anonymous)
            .expect("Failed to select anonymous mech.");

        if let AuthState::Continue(auth_mechs) = state {
            assert!(auth_mechs
                .iter()
                .any(|x| matches!(x, AuthAllowed::Anonymous)));
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
                $account.clone(),
                AuthIssueSession::Token,
                $webauthn,
                duration_from_epoch_now(),
                Source::Internal,
            );
            let mut session = session.unwrap();

            if let AuthState::Choose(auth_mechs) = state {
                assert!(auth_mechs.iter().any(|x| matches!(x, AuthMech::Password)));
            } else {
                panic!();
            }

            let state = session
                .start_session(&AuthMech::Password)
                .expect("Failed to select anonymous mech.");

            if let AuthState::Continue(auth_mechs) = state {
                assert!(auth_mechs
                    .iter()
                    .any(|x| matches!(x, AuthAllowed::Password)));
            } else {
                panic!("Invalid auth state")
            }

            (session, create_pw_badlist_cache())
        }};
    }

    #[test]
    fn test_idm_authsession_simple_password_mech() {
        sketching::test_init();
        let webauthn = create_webauthn();
        // create the ent
        let mut account = entry_to_account!(E_ADMIN_V1.clone());
        // manually load in a cred
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "test_password").unwrap();
        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();

        // now check
        let (mut session, pw_badlist_cache) =
            start_password_session!(&mut audit, account, &webauthn);

        let attempt = AuthCredential::Password("bad_password".to_string());
        let jws_signer = create_jwt_signer();
        match session.validate_creds(
            &attempt,
            Duration::from_secs(0),
            &async_tx,
            &audit_tx,
            &webauthn,
            Some(&pw_badlist_cache),
            &jws_signer,
        ) {
            Ok(AuthState::Denied(_)) => {}
            _ => panic!(),
        };

        match audit_rx.try_recv() {
            Ok(AuditEvent::AuthenticationDenied { .. }) => {}
            _ => assert!(false),
        }

        // === Now begin a new session, and use a good pw.

        let (mut session, pw_badlist_cache) =
            start_password_session!(&mut audit, account, &webauthn);

        let attempt = AuthCredential::Password("test_password".to_string());
        match session.validate_creds(
            &attempt,
            Duration::from_secs(0),
            &async_tx,
            &audit_tx,
            &webauthn,
            Some(&pw_badlist_cache),
            &jws_signer,
        ) {
            Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
            _ => panic!(),
        };

        match async_rx.blocking_recv() {
            Some(DelayedAction::AuthSessionRecord(_)) => {}
            _ => assert!(false),
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    #[test]
    fn test_idm_authsession_simple_password_badlist() {
        sketching::test_init();
        let jws_signer = create_jwt_signer();
        let webauthn = create_webauthn();
        // create the ent
        let mut account = entry_to_account!(E_ADMIN_V1.clone());
        // manually load in a cred
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, "list@no3IBTyqHu$bad").unwrap();
        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();

        // now check, even though the password is correct, Auth should be denied since it is in badlist
        let (mut session, pw_badlist_cache) =
            start_password_session!(&mut audit, account, &webauthn);

        let attempt = AuthCredential::Password("list@no3IBTyqHu$bad".to_string());
        match session.validate_creds(
            &attempt,
            Duration::from_secs(0),
            &async_tx,
            &audit_tx,
            &webauthn,
            Some(&pw_badlist_cache),
            &jws_signer,
        ) {
            Ok(AuthState::Denied(msg)) => assert!(msg == PW_BADLIST_MSG),
            _ => panic!(),
        };

        match audit_rx.try_recv() {
            Ok(AuditEvent::AuthenticationDenied { .. }) => {}
            _ => assert!(false),
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    macro_rules! start_password_mfa_session {
        (
            $account:expr,
            $webauthn:expr
        ) => {{
            let (session, state) = AuthSession::new(
                $account.clone(),
                AuthIssueSession::Token,
                $webauthn,
                duration_from_epoch_now(),
                Source::Internal,
            );
            let mut session = session.expect("Session was unable to be created.");

            if let AuthState::Choose(auth_mechs) = state {
                assert!(auth_mechs
                    .iter()
                    .any(|x| matches!(x, AuthMech::PasswordMfa)))
            } else {
                panic!();
            }

            let state = session
                .start_session(&AuthMech::PasswordMfa)
                .expect("Failed to select anonymous mech.");

            let mut rchal = None;

            if let AuthState::Continue(auth_mechs) = state {
                assert!(
                    true == auth_mechs.iter().fold(false, |acc, x| match x {
                        // TODO: How to return webauthn chal?
                        AuthAllowed::SecurityKey(chal) => {
                            rchal = Some(chal.clone());
                            true
                        }
                        // Why does this also return `true`? If we hit this but not
                        // Webauthn, then we will panic when unwrapping `rchal` later...
                        AuthAllowed::Totp => true,
                        _ => acc,
                    })
                );

                // I feel like this is what we should be doing
                // assuming there will only be one `AuthAllowed::Webauthn`.
                // rchal = auth_mechs.iter().find_map(|x| match x {
                //     AuthAllowed::Webauthn(chal) => Some(chal),
                //     _ => None,
                // });
                // assert!(rchal.is_some());
            } else {
                panic!("Invalid auth state")
            }

            (session, rchal, create_pw_badlist_cache())
        }};
    }

    #[test]
    fn test_idm_authsession_totp_password_mech() {
        sketching::test_init();
        let webauthn = create_webauthn();
        let jws_signer = create_jwt_signer();
        // create the ent
        let mut account = entry_to_account!(E_ADMIN_V1);

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
            .append_totp("totp".to_string(), totp);
        // add totp also
        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();

        // now check

        // check send anon (fail)
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Anonymous,
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }

        // == two step checks

        // Sending a PW first is an immediate fail.
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }
        // check send bad totp, should fail immediate
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_bad),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_TOTP_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }

        // check send good totp, should continue
        //      then bad pw, fail pw
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }

        // check send good totp, should continue
        //      then good pw, success
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };

            match async_rx.blocking_recv() {
                Some(DelayedAction::AuthSessionRecord(_)) => {}
                _ => assert!(false),
            }
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    #[test]
    fn test_idm_authsession_password_mfa_badlist() {
        sketching::test_init();
        let webauthn = create_webauthn();
        let jws_signer = create_jwt_signer();
        // create the ent
        let mut account = entry_to_account!(E_ADMIN_V1);

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
            .append_totp("totp".to_string(), totp);
        // add totp also
        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();

        // now check

        // == two step checks

        // check send good totp, should continue
        //      then badlist pw, failed
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_badlist.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == PW_BADLIST_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    macro_rules! start_webauthn_only_session {
        (
            $audit:expr,
            $account:expr,
            $webauthn:expr
        ) => {{
            let (session, state) = AuthSession::new(
                $account.clone(),
                AuthIssueSession::Token,
                $webauthn,
                duration_from_epoch_now(),
                Source::Internal,
            );
            let mut session = session.unwrap();

            if let AuthState::Choose(auth_mechs) = state {
                assert!(auth_mechs.iter().any(|x| matches!(x, AuthMech::Passkey)));
            } else {
                panic!();
            }

            let state = session
                .start_session(&AuthMech::Passkey)
                .expect("Failed to select Passkey mech.");

            let wan_chal = if let AuthState::Continue(auth_mechs) = state {
                assert!(auth_mechs.len() == 1);
                auth_mechs
                    .into_iter()
                    .fold(None, |_acc, x| match x {
                        AuthAllowed::Passkey(chal) => Some(chal),
                        _ => None,
                    })
                    .expect("No securitykey challenge found.")
            } else {
                panic!();
            };

            (session, wan_chal)
        }};
    }

    fn setup_webauthn_passkey(
        name: &str,
    ) -> (
        webauthn_rs::prelude::Webauthn,
        webauthn_authenticator_rs::WebauthnAuthenticator<SoftPasskey>,
        webauthn_rs::prelude::Passkey,
    ) {
        let webauthn = create_webauthn();
        // Setup a soft token
        let mut wa = WebauthnAuthenticator::new(SoftPasskey::new());

        let uuid = Uuid::new_v4();

        let (chal, reg_state) = webauthn
            .start_passkey_registration(uuid, name, name, None)
            .expect("Failed to setup passkey rego challenge");

        let r = wa
            .do_registration(webauthn.get_allowed_origins()[0].clone(), chal)
            .expect("Failed to create soft passkey");

        let wan_cred = webauthn
            .finish_passkey_registration(&r, &reg_state)
            .expect("Failed to register soft token");

        (webauthn, wa, wan_cred)
    }

    fn setup_webauthn_securitykey(
        name: &str,
    ) -> (
        webauthn_rs::prelude::Webauthn,
        webauthn_authenticator_rs::WebauthnAuthenticator<SoftPasskey>,
        webauthn_rs::prelude::SecurityKey,
    ) {
        let webauthn = create_webauthn();
        // Setup a soft token
        let mut wa = WebauthnAuthenticator::new(SoftPasskey::new());

        let uuid = Uuid::new_v4();

        let (chal, reg_state) = webauthn
            .start_securitykey_registration(uuid, name, name, None, None, None)
            .expect("Failed to setup passkey rego challenge");

        let r = wa
            .do_registration(webauthn.get_allowed_origins()[0].clone(), chal)
            .expect("Failed to create soft securitykey");

        let wan_cred = webauthn
            .finish_securitykey_registration(&r, &reg_state)
            .expect("Failed to register soft token");

        (webauthn, wa, wan_cred)
    }

    #[test]
    fn test_idm_authsession_webauthn_only_mech() {
        sketching::test_init();
        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();
        let ts = duration_from_epoch_now();
        // create the ent
        let mut account = entry_to_account!(E_ADMIN_V1.clone());

        let (webauthn, mut wa, wan_cred) = setup_webauthn_passkey(account.name.as_str());
        let jws_signer = create_jwt_signer();

        // Now create the credential for the account.
        account.passkeys = btreemap![(Uuid::new_v4(), ("soft".to_string(), wan_cred))];

        // now check correct mech was offered.

        // check send anon (fail)
        {
            let (mut session, _inv_chal) =
                start_webauthn_only_session!(&mut audit, account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Anonymous,
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                None,
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }

        // Check good challenge
        {
            let (mut session, chal) = start_webauthn_only_session!(&mut audit, account, &webauthn);

            let resp = wa
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::Passkey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                None,
                &jws_signer,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };

            // Check the async counter update was sent.
            match async_rx.blocking_recv() {
                Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
                _ => assert!(false),
            }
            match async_rx.blocking_recv() {
                Some(DelayedAction::AuthSessionRecord(_)) => {}
                _ => assert!(false),
            }
        }

        // Check bad challenge.
        {
            let (_session, inv_chal) = start_webauthn_only_session!(&mut audit, account, &webauthn);
            let (mut session, _chal) = start_webauthn_only_session!(&mut audit, account, &webauthn);

            let resp = wa
                // HERE -> we use inv_chal instead.
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), inv_chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::Passkey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                None,
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_WEBAUTHN_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }

        // Use an incorrect softtoken.
        {
            let mut inv_wa = WebauthnAuthenticator::new(SoftPasskey::new());
            let (chal, reg_state) = webauthn
                .start_passkey_registration(account.uuid, &account.name, &account.displayname, None)
                .expect("Failed to setup webauthn rego challenge");

            let r = inv_wa
                .do_registration(webauthn.get_allowed_origins()[0].clone(), chal)
                .expect("Failed to create soft token");

            let inv_cred = webauthn
                .finish_passkey_registration(&r, &reg_state)
                .expect("Failed to register soft token");

            // Discard the auth_state, we only need the invalid challenge.
            let (chal, _auth_state) = webauthn
                .start_passkey_authentication(&vec![inv_cred])
                .expect("Failed to generate challenge for in inv softtoken");

            // Create the response.
            let resp = inv_wa
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), chal)
                .map(Box::new)
                .expect("Failed to use softtoken for response.");

            let (mut session, _chal) = start_webauthn_only_session!(&mut audit, account, &webauthn);
            // Ignore the real cred, use the diff cred. Normally this shouldn't even
            // get this far, because the client should identify that the cred id's are
            // not inline.
            match session.validate_creds(
                &AuthCredential::Passkey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                None,
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_WEBAUTHN_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    #[test]
    fn test_idm_authsession_webauthn_password_mech() {
        sketching::test_init();
        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();
        let ts = duration_from_epoch_now();
        // create the ent
        let mut account = entry_to_account!(E_ADMIN_V1);

        let (webauthn, mut wa, wan_cred) = setup_webauthn_securitykey(account.name.as_str());
        let jws_signer = create_jwt_signer();
        let pw_good = "test_password";
        let pw_bad = "bad_password";

        // Now create the credential for the account.
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw_good)
            .unwrap()
            .append_securitykey("soft".to_string(), wan_cred)
            .unwrap();

        account.primary = Some(cred);

        // check pw first (fail)
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }

        // Check totp first attempt fails.
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(0),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }

        // check bad webauthn (fail)
        // NOTE: We only check bad challenge here as bad softtoken is already
        // extensively tested.
        {
            let (_session, inv_chal, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);
            let (mut session, _chal, _) = start_password_mfa_session!(account, &webauthn);

            let inv_chal = inv_chal.unwrap();

            let resp = wa
                // HERE -> we use inv_chal instead.
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), inv_chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::SecurityKey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_WEBAUTHN_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }

        // check good webauthn/bad pw (fail)
        {
            let (mut session, chal, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);
            let chal = chal.unwrap();

            let resp = wa
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::SecurityKey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }

            // Check the async counter update was sent.
            match async_rx.blocking_recv() {
                Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
                _ => assert!(false),
            }
        }

        // Check good webauthn/good pw (pass)
        {
            let (mut session, chal, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);
            let chal = chal.unwrap();

            let resp = wa
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::SecurityKey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };

            // Check the async counter update was sent.
            match async_rx.blocking_recv() {
                Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
                _ => assert!(false),
            }
            match async_rx.blocking_recv() {
                Some(DelayedAction::AuthSessionRecord(_)) => {}
                _ => assert!(false),
            }
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    #[test]
    fn test_idm_authsession_webauthn_password_totp_mech() {
        sketching::test_init();
        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();
        let ts = duration_from_epoch_now();
        // create the ent
        let mut account = entry_to_account!(E_ADMIN_V1);

        let (webauthn, mut wa, wan_cred) = setup_webauthn_securitykey(account.name.as_str());
        let jws_signer = create_jwt_signer();

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
            .append_securitykey("soft".to_string(), wan_cred)
            .unwrap()
            .append_totp("totp".to_string(), totp);

        account.primary = Some(cred);

        // check pw first (fail)
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }

        // Check bad totp (fail)
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_bad),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_TOTP_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }

        // check bad webauthn (fail)
        {
            let (_session, inv_chal, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);
            let (mut session, _chal, _) = start_password_mfa_session!(account, &webauthn);

            let inv_chal = inv_chal.unwrap();

            let resp = wa
                // HERE -> we use inv_chal instead.
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), inv_chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::SecurityKey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_WEBAUTHN_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }

        // check good webauthn/bad pw (fail)
        {
            let (mut session, chal, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);
            let chal = chal.unwrap();

            let resp = wa
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::SecurityKey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }

            // Check the async counter update was sent.
            match async_rx.blocking_recv() {
                Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
                _ => assert!(false),
            }
        }

        // check good totp/bad pw (fail)
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }

        // check good totp/good pw (pass)
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };

            match async_rx.blocking_recv() {
                Some(DelayedAction::AuthSessionRecord(_)) => {}
                _ => assert!(false),
            }
        }

        // Check good webauthn/good pw (pass)
        {
            let (mut session, chal, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);
            let chal = chal.unwrap();

            let resp = wa
                .do_authentication(webauthn.get_allowed_origins()[0].clone(), chal)
                .map(Box::new)
                .expect("failed to use softtoken to authenticate");

            match session.validate_creds(
                &AuthCredential::SecurityKey(resp),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };

            // Check the async counter update was sent.
            match async_rx.blocking_recv() {
                Some(DelayedAction::WebauthnCounterIncrement(_)) => {}
                _ => assert!(false),
            }
            match async_rx.blocking_recv() {
                Some(DelayedAction::AuthSessionRecord(_)) => {}
                _ => assert!(false),
            }
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    #[test]
    fn test_idm_authsession_backup_code_mech() {
        sketching::test_init();
        let jws_signer = create_jwt_signer();
        let webauthn = create_webauthn();
        // create the ent
        let mut account = entry_to_account!(E_ADMIN_V1);

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
        let mut code_set = HashSet::new();
        code_set.insert(backup_code_good.clone());

        let backup_codes = BackupCodes::new(code_set);

        // add totp and backup codes also
        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw_good)
            .unwrap()
            .append_totp("totp".to_string(), totp)
            .update_backup_code(backup_codes)
            .unwrap();

        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();

        // now check
        // == two step checks

        // Sending a PW first is an immediate fail.
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_AUTH_TYPE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }
        // check send wrong backup code, should fail immediate
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::BackupCode(backup_code_bad),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_BACKUPCODE_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
        }
        // check send good backup code, should continue
        //      then bad pw, fail pw
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::BackupCode(backup_code_good.clone()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_bad.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Denied(msg)) => assert!(msg == BAD_PASSWORD_MSG),
                _ => panic!(),
            };

            match audit_rx.try_recv() {
                Ok(AuditEvent::AuthenticationDenied { .. }) => {}
                _ => assert!(false),
            }
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
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::BackupCode(backup_code_good),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };
        }
        // Can't process BackupCodeRemoval without the server instance
        match async_rx.blocking_recv() {
            Some(DelayedAction::BackupCodeRemoval(_)) => {}
            _ => assert!(false),
        }

        // There will be a auth session record too
        match async_rx.blocking_recv() {
            Some(DelayedAction::AuthSessionRecord(_)) => {}
            _ => assert!(false),
        }

        // TOTP should also work:
        // check send good TOTP, should continue
        //      then good pw, success
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };
        }

        // There will be a auth session record too
        match async_rx.blocking_recv() {
            Some(DelayedAction::AuthSessionRecord(_)) => {}
            _ => assert!(false),
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }

    #[test]
    fn test_idm_authsession_multiple_totp_password_mech() {
        // Slightly different to the other TOTP test, this
        // checks handling when multiple TOTP's are registered.
        sketching::test_init();
        let webauthn = create_webauthn();
        let jws_signer = create_jwt_signer();
        // create the ent
        let mut account = entry_to_account!(E_ADMIN_V1);

        // Setup a fake time stamp for consistency.
        let ts = Duration::from_secs(12345);

        // manually load in a cred
        let totp_a = Totp::generate_secure(TOTP_DEFAULT_STEP);
        let totp_b = Totp::generate_secure(TOTP_DEFAULT_STEP);

        let totp_good_a = totp_a
            .do_totp_duration_from_epoch(&ts)
            .expect("failed to perform totp.");

        let totp_good_b = totp_b
            .do_totp_duration_from_epoch(&ts)
            .expect("failed to perform totp.");

        assert!(totp_good_a != totp_good_b);

        let pw_good = "test_password";

        let p = CryptoPolicy::minimum();
        let cred = Credential::new_password_only(&p, pw_good)
            .unwrap()
            .append_totp("totp_a".to_string(), totp_a)
            .append_totp("totp_b".to_string(), totp_b);
        // add totp also
        account.primary = Some(cred);

        let (async_tx, mut async_rx) = unbounded();
        let (audit_tx, mut audit_rx) = unbounded();

        // Test totp_a
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good_a),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };

            match async_rx.blocking_recv() {
                Some(DelayedAction::AuthSessionRecord(_)) => {}
                _ => assert!(false),
            }
        }

        // Test totp_b
        {
            let (mut session, _, pw_badlist_cache) =
                start_password_mfa_session!(account, &webauthn);

            match session.validate_creds(
                &AuthCredential::Totp(totp_good_b),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Continue(cont)) => assert!(cont == vec![AuthAllowed::Password]),
                _ => panic!(),
            };
            match session.validate_creds(
                &AuthCredential::Password(pw_good.to_string()),
                ts,
                &async_tx,
                &audit_tx,
                &webauthn,
                Some(&pw_badlist_cache),
                &jws_signer,
            ) {
                Ok(AuthState::Success(_, AuthIssueSession::Token)) => {}
                _ => panic!(),
            };

            match async_rx.blocking_recv() {
                Some(DelayedAction::AuthSessionRecord(_)) => {}
                _ => assert!(false),
            }
        }

        drop(async_tx);
        assert!(async_rx.blocking_recv().is_none());
        drop(audit_tx);
        assert!(audit_rx.blocking_recv().is_none());
    }
}
