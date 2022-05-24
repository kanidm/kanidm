use crate::access::AccessControlsTransaction;
use crate::credential::{BackupCodes, Credential};
use crate::idm::account::Account;
use crate::idm::server::IdmServerCredUpdateTransaction;
use crate::idm::server::IdmServerProxyWriteTransaction;
use crate::prelude::*;
use crate::value::IntentTokenState;
use hashbrown::HashSet;

use crate::credential::totp::{Totp, TOTP_DEFAULT_STEP};

use kanidm_proto::v1::{CURegState, CUStatus, CredentialDetail, PasswordFeedback, TotpSecret};

use crate::utils::{backup_code_from_random, uuid_from_duration};

use serde::{Deserialize, Serialize};

use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use time::OffsetDateTime;

// use tokio::sync::Mutex;

use core::ops::Deref;

const MAXIMUM_CRED_UPDATE_TTL: Duration = Duration::from_secs(900);
const MAXIMUM_INTENT_TTL: Duration = Duration::from_secs(86400);
const MINIMUM_INTENT_TTL: Duration = MAXIMUM_CRED_UPDATE_TTL;

#[derive(Debug)]
pub enum PasswordQuality {
    TooShort(usize),
    BadListed,
    Feedback(Vec<PasswordFeedback>),
}

#[derive(Serialize, Deserialize, Debug)]
struct CredentialUpdateIntentTokenInner {
    pub sessionid: Uuid,
    // Who is it targeting?
    pub target: Uuid,
    // Id of the intent, for checking if it's already been used against this user.
    pub uuid: Uuid,
    // How long is it valid for?
    pub max_ttl: Duration,
}

#[derive(Clone, Debug)]
pub struct CredentialUpdateIntentToken {
    pub token_enc: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CredentialUpdateSessionTokenInner {
    pub sessionid: Uuid,
    // How long is it valid for?
    pub max_ttl: Duration,
}

#[derive(Debug)]
pub struct CredentialUpdateSessionToken {
    pub token_enc: String,
}

enum MfaRegState {
    None,
    TotpInit(Totp),
    TotpTryAgain(Totp),
    TotpInvalidSha1(Totp),
}

impl fmt::Debug for MfaRegState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = match self {
            MfaRegState::None => "MfaRegState::None",
            MfaRegState::TotpInit(_) => "MfaRegState::TotpInit",
            MfaRegState::TotpTryAgain(_) => "MfaRegState::TotpTryAgain",
            MfaRegState::TotpInvalidSha1(_) => "MfaRegState::TotpInvalidSha1",
        };
        write!(f, "{}", t)
    }
}

pub(crate) struct CredentialUpdateSession {
    // Current credentials - these are on the Account!
    account: Account,
    //
    intent_token_id: Option<Uuid>,
    // Acc policy
    // The credentials as they are being updated
    primary: Option<Credential>,

    // Internal reg state.
    mfaregstate: MfaRegState,
    // trusted_devices: Map<Webauthn>?

    //
}

impl fmt::Debug for CredentialUpdateSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let primary: Option<CredentialDetail> = self.primary.as_ref().map(|c| c.into());
        f.debug_struct("CredentialUpdateSession")
            .field("account.spn", &self.account.spn)
            .field("intent_token_id", &self.intent_token_id)
            .field("primary.detail()", &primary)
            .field("mfaregstate", &self.mfaregstate)
            .finish()
    }
}

enum MfaRegStateStatus {
    // Nothing in progress.
    None,
    TotpCheck(TotpSecret),
    TotpTryAgain,
    TotpInvalidSha1,
    BackupCodes(HashSet<String>),
}

impl fmt::Debug for MfaRegStateStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = match self {
            MfaRegStateStatus::None => "MfaRegStateStatus::None",
            MfaRegStateStatus::TotpCheck(_) => "MfaRegStateStatus::TotpCheck(_)",
            MfaRegStateStatus::TotpTryAgain => "MfaRegStateStatus::TotpTryAgain",
            MfaRegStateStatus::TotpInvalidSha1 => "MfaRegStateStatus::TotpInvalidSha1",
            MfaRegStateStatus::BackupCodes(_) => "MfaRegStateStatus::BackupCodes",
        };
        write!(f, "{}", t)
    }
}

#[derive(Debug)]
pub(crate) struct CredentialUpdateSessionStatus {
    // spn: ?
    // ttl: Duration,
    //
    can_commit: bool,
    primary: Option<CredentialDetail>,
    // Any info the client needs about mfareg state.
    mfaregstate: MfaRegStateStatus,
}

impl Into<CUStatus> for CredentialUpdateSessionStatus {
    fn into(self) -> CUStatus {
        CUStatus {
            can_commit: self.can_commit,
            primary: self.primary,
            mfaregstate: match self.mfaregstate {
                MfaRegStateStatus::None => CURegState::None,
                MfaRegStateStatus::TotpCheck(c) => CURegState::TotpCheck(c),
                MfaRegStateStatus::TotpTryAgain => CURegState::TotpTryAgain,
                MfaRegStateStatus::TotpInvalidSha1 => CURegState::TotpInvalidSha1,
                MfaRegStateStatus::BackupCodes(s) => {
                    CURegState::BackupCodes(s.into_iter().collect())
                }
            },
        }
    }
}

impl From<&CredentialUpdateSession> for CredentialUpdateSessionStatus {
    fn from(session: &CredentialUpdateSession) -> Self {
        CredentialUpdateSessionStatus {
            can_commit: true,
            primary: session.primary.as_ref().map(|c| c.into()),
            mfaregstate: match &session.mfaregstate {
                MfaRegState::None => MfaRegStateStatus::None,
                MfaRegState::TotpInit(token) => MfaRegStateStatus::TotpCheck(
                    token.to_proto(session.account.name.as_str(), session.account.spn.as_str()),
                ),
                MfaRegState::TotpTryAgain(_) => MfaRegStateStatus::TotpTryAgain,
                MfaRegState::TotpInvalidSha1(_) => MfaRegStateStatus::TotpInvalidSha1,
            },
        }
    }
}

pub(crate) type CredentialUpdateSessionMutex = Arc<Mutex<CredentialUpdateSession>>;

pub struct InitCredentialUpdateIntentEvent {
    // Who initiated this?
    pub ident: Identity,
    // Who is it targetting?
    pub target: Uuid,
    // How long is it valid for?
    pub max_ttl: Option<Duration>,
}

impl InitCredentialUpdateIntentEvent {
    pub fn new(ident: Identity, target: Uuid, max_ttl: Option<Duration>) -> Self {
        InitCredentialUpdateIntentEvent {
            ident,
            target,
            max_ttl,
        }
    }

    #[cfg(test)]
    pub fn new_impersonate_entry(
        e: std::sync::Arc<Entry<EntrySealed, EntryCommitted>>,
        target: Uuid,
        max_ttl: Duration,
    ) -> Self {
        let ident = Identity::from_impersonate_entry(e);
        InitCredentialUpdateIntentEvent {
            ident,
            target,
            max_ttl: Some(max_ttl),
        }
    }
}

pub struct InitCredentialUpdateEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl InitCredentialUpdateEvent {
    pub fn new(ident: Identity, target: Uuid) -> Self {
        InitCredentialUpdateEvent { ident, target }
    }

    #[cfg(test)]
    pub fn new_impersonate_entry(e: std::sync::Arc<Entry<EntrySealed, EntryCommitted>>) -> Self {
        let ident = Identity::from_impersonate_entry(e);
        let target = ident
            .get_uuid()
            .ok_or(OperationError::InvalidState)
            .expect("Identity has no uuid associated");
        InitCredentialUpdateEvent { ident, target }
    }
}

impl<'a> IdmServerProxyWriteTransaction<'a> {
    fn validate_init_credential_update(
        &mut self,
        target: Uuid,
        ident: &Identity,
    ) -> Result<Account, OperationError> {
        let entry = self.qs_write.internal_search_uuid(&target)?;

        security_info!(
            ?entry,
            %target,
            "Initiating Credential Update Session",
        );

        // Is target an account? This checks for us.
        let account = Account::try_from_entry_rw(entry.as_ref(), &mut self.qs_write)?;

        let effective_perms = self
            .qs_write
            .get_accesscontrols()
            .effective_permission_check(
                &ident,
                Some(btreeset![AttrString::from("primary_credential")]),
                &[entry],
            )?;

        let eperm = effective_perms.get(0).ok_or_else(|| {
            admin_error!("Effective Permission check returned no results");
            OperationError::InvalidState
        })?;

        // Does the ident have permission to modify AND search the user-credentials of the target, given
        // the current status of it's authentication?

        if eperm.target != account.uuid {
            admin_error!("Effective Permission check target differs from requested entry uuid");
            return Err(OperationError::InvalidEntryState);
        }

        if !eperm.search.contains("primary_credential")
            || !eperm.modify_pres.contains("primary_credential")
            || !eperm.modify_rem.contains("primary_credential")
        {
            security_info!(
                "Requestor {} does not have permission to update credentials of {}",
                ident,
                account.spn
            );
            return Err(OperationError::NotAuthorised);
        }

        Ok(account)
    }

    fn create_credupdate_session(
        &mut self,
        sessionid: Uuid,
        intent_token_id: Option<Uuid>,
        account: Account,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionToken, OperationError> {
        // - stash the current state of all associated credentials
        let primary = account.primary.clone();
        // - store account policy (if present)

        let session = Arc::new(Mutex::new(CredentialUpdateSession {
            account,
            intent_token_id,
            primary,
            mfaregstate: MfaRegState::None,
        }));

        let max_ttl = ct + MAXIMUM_CRED_UPDATE_TTL;

        let token = CredentialUpdateSessionTokenInner { sessionid, max_ttl };

        let token_data = serde_json::to_vec(&token).map_err(|e| {
            admin_error!(err = ?e, "Unable to encode token data");
            OperationError::SerdeJsonError
        })?;

        let token_enc = self.token_enc_key.encrypt(&token_data);

        // Point of no return

        // Sneaky! Now we know it will work, prune old sessions.
        self.expire_credential_update_sessions(ct);

        // Store the update session into the map.
        self.cred_update_sessions.insert(sessionid, session);
        trace!("cred_update_sessions.insert - {}", sessionid);

        // - issue the CredentialUpdateToken (enc)
        Ok(CredentialUpdateSessionToken { token_enc })
    }

    pub fn init_credential_update_intent(
        &mut self,
        event: &InitCredentialUpdateIntentEvent,
        ct: Duration,
    ) -> Result<CredentialUpdateIntentToken, OperationError> {
        spanned!("idm::server::credupdatesession<Init>", {
            let account = self.validate_init_credential_update(event.target, &event.ident)?;

            // ==== AUTHORISATION CHECKED ===

            // Build the intent token.
            let mttl = event.max_ttl.unwrap_or_else(|| Duration::new(0, 0));
            let max_ttl = ct + mttl.clamp(MINIMUM_INTENT_TTL, MAXIMUM_INTENT_TTL);
            let sessionid = uuid_from_duration(max_ttl, self.sid);
            let uuid = Uuid::new_v4();

            let target = event.target;

            let token = CredentialUpdateIntentTokenInner {
                sessionid,
                target,
                uuid,
                max_ttl,
            };

            let token_data = serde_json::to_vec(&token).map_err(|e| {
                admin_error!(err = ?e, "Unable to encode token data");
                OperationError::SerdeJsonError
            })?;

            let token_enc = self
                .token_enc_key
                .encrypt_at_time(&token_data, ct.as_secs());

            // Mark that we have created an intent token on the user.
            let modlist = ModifyList::new_append(
                "credential_update_intent_token",
                Value::IntentToken(token.sessionid, IntentTokenState::Valid),
            );

            self.qs_write
                .internal_modify(
                    // Filter as executed
                    &filter!(f_eq("uuid", PartialValue::new_uuid(account.uuid))),
                    &modlist,
                )
                .map_err(|e| {
                    request_error!(error = ?e);
                    e
                })?;

            Ok(CredentialUpdateIntentToken { token_enc })
        })
    }

    pub fn exchange_intent_credential_update(
        &mut self,
        token: CredentialUpdateIntentToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionToken, OperationError> {
        let token: CredentialUpdateIntentTokenInner = self
            .token_enc_key
            .decrypt(&token.token_enc)
            .map_err(|e| {
                admin_error!(?e, "Failed to decrypt intent request");
                OperationError::SessionExpired
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!(err = ?e, "Failed to deserialise intent request");
                    OperationError::SerdeJsonError
                })
            })?;

        // Check the TTL
        if ct >= token.max_ttl {
            trace!(?ct, ?token.max_ttl);
            security_info!(%token.sessionid, "session expired");
            return Err(OperationError::SessionExpired);
        }

        let entry = self.qs_write.internal_search_uuid(&token.target)?;

        // Is target an account? This checks for us.
        let account = Account::try_from_entry_rw(entry.as_ref(), &mut self.qs_write)?;

        // Check there is not already a user session in progress with this intent token.
        // Is there a need to revoke intent tokens?

        match account
            .credential_update_intent_tokens
            .get(&token.sessionid)
        {
            Some(IntentTokenState::Consumed) => {
                security_info!(
                    ?entry,
                    %token.target,
                    "Rejecting Update Session - Intent Token has already been exchanged",
                );
                return Err(OperationError::SessionExpired);
            }
            Some(IntentTokenState::InProgress(si, sd)) => {
                if ct > *sd {
                    // The former session has expired, continue.
                    security_info!(
                        ?entry,
                        %token.target,
                        "Initiating Credential Update Session - Previous session {} has expired", si
                    );
                } else {
                    security_info!(
                        ?entry,
                        %token.target,
                        "Rejecting Update Session - Intent Token is in use {}. Try again later", si
                    );
                    return Err(OperationError::Wait(OffsetDateTime::unix_epoch() + *sd));
                }
            }
            Some(IntentTokenState::Valid) | None => {
                security_info!(
                    ?entry,
                    %token.target,
                    "Initiating Credential Update Session",
                );
            }
        };

        // To prevent issues with repl, we need to associate this cred update session id, with
        // this intent token id.

        // Store the intent id in the session (if needed) so that we can check the state at the
        // end of the update.

        // We need to pin the id from the intent token into the credential to ensure it's not re-used

        // Need to change this to the expiry time, so we can purge up to.
        let sessionid = uuid_from_duration(ct + MAXIMUM_CRED_UPDATE_TTL, self.sid);

        let mut modlist = ModifyList::new();

        modlist.push_mod(Modify::Removed(
            AttrString::from("credential_update_intent_token"),
            PartialValue::IntentToken(token.sessionid),
        ));
        modlist.push_mod(Modify::Present(
            AttrString::from("credential_update_intent_token"),
            Value::IntentToken(
                token.sessionid,
                IntentTokenState::InProgress(sessionid, ct + MAXIMUM_CRED_UPDATE_TTL),
            ),
        ));

        self.qs_write
            .internal_modify(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuid(account.uuid))),
                &modlist,
            )
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })?;

        // ==========
        // Okay, good to exchange.

        self.create_credupdate_session(sessionid, Some(token.sessionid), account, ct)
    }

    pub fn init_credential_update(
        &mut self,
        event: &InitCredentialUpdateEvent,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionToken, OperationError> {
        spanned!("idm::server::credupdatesession<Init>", {
            let account = self.validate_init_credential_update(event.target, &event.ident)?;

            // ==== AUTHORISATION CHECKED ===

            // This is the expiry time, so that our cleanup task can "purge up to now" rather
            // than needing to do calculations.
            let sessionid = uuid_from_duration(ct + MAXIMUM_CRED_UPDATE_TTL, self.sid);

            // Build the cred update session.
            self.create_credupdate_session(sessionid, None, account, ct)
        })
    }

    #[instrument(level = "trace", skip(self))]
    pub fn expire_credential_update_sessions(&mut self, ct: Duration) {
        let before = self.cred_update_sessions.len();
        let split_at = uuid_from_duration(ct, self.sid);
        trace!(?split_at, "expiring less than");
        self.cred_update_sessions.split_off_lt(&split_at);
        let removed = before - self.cred_update_sessions.len();
        trace!(?removed);
    }

    pub fn commit_credential_update(
        &mut self,
        cust: CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<(), OperationError> {
        let session_token: CredentialUpdateSessionTokenInner = self
            .token_enc_key
            .decrypt(&cust.token_enc)
            .map_err(|e| {
                admin_error!(?e, "Failed to decrypt credential update session request");
                OperationError::SessionExpired
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!(err = ?e, "Failed to deserialise credential update session request");
                    OperationError::SerdeJsonError
                })
            })?;

        if ct >= session_token.max_ttl {
            trace!(?ct, ?session_token.max_ttl);
            security_info!(%session_token.sessionid, "session expired");
            return Err(OperationError::SessionExpired);
        }

        let session_handle = self.cred_update_sessions.remove(&session_token.sessionid)
            .ok_or_else(|| {
                admin_error!("No such sessionid exists on this server - may be due to a load balancer failover or replay? {:?}", session_token.sessionid);
                OperationError::InvalidState
            })?;

        let session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;

        trace!(?session);

        let mut modlist = ModifyList::new();

        // Setup mods for the various bits. We always assert an *exact* state.

        match &session.primary {
            Some(ncred) => {
                modlist.push_mod(Modify::Purged(AttrString::from("primary_credential")));
                let vcred = Value::new_credential("primary", ncred.clone());
                modlist.push_mod(Modify::Present(
                    AttrString::from("primary_credential"),
                    vcred,
                ));
            }
            None => {
                modlist.push_mod(Modify::Purged(AttrString::from("primary_credential")));
            }
        };

        // If an intent token was used, remove it's former value, and add it as consumed.
        if let Some(intent_token_id) = session.intent_token_id {
            modlist.push_mod(Modify::Removed(
                AttrString::from("credential_update_intent_token"),
                PartialValue::IntentToken(intent_token_id),
            ));
            modlist.push_mod(Modify::Present(
                AttrString::from("credential_update_intent_token"),
                Value::IntentToken(intent_token_id, IntentTokenState::Consumed),
            ));
        };

        // Are any other checks needed?

        // Apply to the account!
        trace!(?modlist, "processing change");

        self.qs_write
            .internal_modify(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuid(session.account.uuid))),
                &modlist,
            )
            .map_err(|e| {
                request_error!(error = ?e);
                e
            })
    }
}

impl<'a> IdmServerCredUpdateTransaction<'a> {
    fn get_current_session(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionMutex, OperationError> {
        let session_token: CredentialUpdateSessionTokenInner = self
            .token_enc_key
            .decrypt(&cust.token_enc)
            .map_err(|e| {
                admin_error!(?e, "Failed to decrypt credential update session request");
                OperationError::SessionExpired
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!(err = ?e, "Failed to deserialise credential update session request");
                    OperationError::SerdeJsonError
                })
            })?;

        // Check the TTL
        if ct >= session_token.max_ttl {
            trace!(?ct, ?session_token.max_ttl);
            security_info!(%session_token.sessionid, "session expired");
            return Err(OperationError::SessionExpired);
        }

        self.cred_update_sessions.get(&session_token.sessionid)
            .ok_or_else(|| {
                admin_error!("No such sessionid exists on this server - may be due to a load balancer failover or token replay? {}", session_token.sessionid);
                OperationError::InvalidState
            })
            .cloned()
    }

    // I think I need this to be a try lock instead, and fail on error, because
    // of the nature of the async bits.
    pub fn credential_update_status(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        let status: CredentialUpdateSessionStatus = session.deref().into();
        Ok(status)
    }

    fn check_password_quality(
        &self,
        cleartext: &str,
        related_inputs: &[&str],
    ) -> Result<(), PasswordQuality> {
        // password strength and badlisting is always global, rather than per-pw-policy.
        // pw-policy as check on the account is about requirements for mfa for example.
        //

        // is the password at least 10 char?
        if cleartext.len() < PW_MIN_LENGTH {
            return Err(PasswordQuality::TooShort(PW_MIN_LENGTH));
        }

        // does the password pass zxcvbn?

        let entropy = zxcvbn::zxcvbn(cleartext, related_inputs).map_err(|e| {
            admin_error!("zxcvbn check failure (password empty?) {:?}", e);
            PasswordQuality::TooShort(PW_MIN_LENGTH)
        })?;

        // check account pwpolicy (for 3 or 4)? Do we need pw strength beyond this
        // or should we be enforcing mfa instead
        if entropy.score() < 3 {
            // The password is too week as per:
            // https://docs.rs/zxcvbn/2.0.0/zxcvbn/struct.Entropy.html
            let feedback: zxcvbn::feedback::Feedback = entropy
                .feedback()
                .as_ref()
                .ok_or(OperationError::InvalidState)
                .map(|v| v.clone())
                .map_err(|e| {
                    security_info!("zxcvbn returned no feedback when score < 3 -> {:?}", e);
                    PasswordQuality::TooShort(PW_MIN_LENGTH)
                })?;

            security_info!(?feedback, "pw quality feedback");

            let feedback: Vec<_> = feedback
                .suggestions()
                .iter()
                .map(|s| {
                    match s {
                            zxcvbn::feedback::Suggestion::UseAFewWordsAvoidCommonPhrases => {
                                PasswordFeedback::UseAFewWordsAvoidCommonPhrases
                            }
                            zxcvbn::feedback::Suggestion::NoNeedForSymbolsDigitsOrUppercaseLetters => {
                                PasswordFeedback::NoNeedForSymbolsDigitsOrUppercaseLetters
                            }
                            zxcvbn::feedback::Suggestion::AddAnotherWordOrTwo => {
                                PasswordFeedback::AddAnotherWordOrTwo
                            }
                            zxcvbn::feedback::Suggestion::CapitalizationDoesntHelpVeryMuch => {
                                PasswordFeedback::CapitalizationDoesntHelpVeryMuch
                            }
                            zxcvbn::feedback::Suggestion::AllUppercaseIsAlmostAsEasyToGuessAsAllLowercase => {
                                PasswordFeedback::AllUppercaseIsAlmostAsEasyToGuessAsAllLowercase
                            }
                            zxcvbn::feedback::Suggestion::ReversedWordsArentMuchHarderToGuess => {
                                PasswordFeedback::ReversedWordsArentMuchHarderToGuess
                            }
                            zxcvbn::feedback::Suggestion::PredictableSubstitutionsDontHelpVeryMuch => {
                                PasswordFeedback::PredictableSubstitutionsDontHelpVeryMuch
                            }
                            zxcvbn::feedback::Suggestion::UseALongerKeyboardPatternWithMoreTurns => {
                                PasswordFeedback::UseALongerKeyboardPatternWithMoreTurns
                            }
                            zxcvbn::feedback::Suggestion::AvoidRepeatedWordsAndCharacters => {
                                PasswordFeedback::AvoidRepeatedWordsAndCharacters
                            }
                            zxcvbn::feedback::Suggestion::AvoidSequences => {
                                PasswordFeedback::AvoidSequences
                            }
                            zxcvbn::feedback::Suggestion::AvoidRecentYears => {
                                PasswordFeedback::AvoidRecentYears
                            }
                            zxcvbn::feedback::Suggestion::AvoidYearsThatAreAssociatedWithYou => {
                                PasswordFeedback::AvoidYearsThatAreAssociatedWithYou
                            }
                            zxcvbn::feedback::Suggestion::AvoidDatesAndYearsThatAreAssociatedWithYou => {
                                PasswordFeedback::AvoidDatesAndYearsThatAreAssociatedWithYou
                            }
                        }
                })
                .chain(feedback.warning().map(|w| match w {
                    zxcvbn::feedback::Warning::StraightRowsOfKeysAreEasyToGuess => {
                        PasswordFeedback::StraightRowsOfKeysAreEasyToGuess
                    }
                    zxcvbn::feedback::Warning::ShortKeyboardPatternsAreEasyToGuess => {
                        PasswordFeedback::ShortKeyboardPatternsAreEasyToGuess
                    }
                    zxcvbn::feedback::Warning::RepeatsLikeAaaAreEasyToGuess => {
                        PasswordFeedback::RepeatsLikeAaaAreEasyToGuess
                    }
                    zxcvbn::feedback::Warning::RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess => {
                        PasswordFeedback::RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess
                    }
                    zxcvbn::feedback::Warning::ThisIsATop10Password => {
                        PasswordFeedback::ThisIsATop10Password
                    }
                    zxcvbn::feedback::Warning::ThisIsATop100Password => {
                        PasswordFeedback::ThisIsATop100Password
                    }
                    zxcvbn::feedback::Warning::ThisIsACommonPassword => {
                        PasswordFeedback::ThisIsACommonPassword
                    }
                    zxcvbn::feedback::Warning::ThisIsSimilarToACommonlyUsedPassword => {
                        PasswordFeedback::ThisIsSimilarToACommonlyUsedPassword
                    }
                    zxcvbn::feedback::Warning::SequencesLikeAbcAreEasyToGuess => {
                        PasswordFeedback::SequencesLikeAbcAreEasyToGuess
                    }
                    zxcvbn::feedback::Warning::RecentYearsAreEasyToGuess => {
                        PasswordFeedback::RecentYearsAreEasyToGuess
                    }
                    zxcvbn::feedback::Warning::AWordByItselfIsEasyToGuess => {
                        PasswordFeedback::AWordByItselfIsEasyToGuess
                    }
                    zxcvbn::feedback::Warning::DatesAreOftenEasyToGuess => {
                        PasswordFeedback::DatesAreOftenEasyToGuess
                    }
                    zxcvbn::feedback::Warning::NamesAndSurnamesByThemselvesAreEasyToGuess => {
                        PasswordFeedback::NamesAndSurnamesByThemselvesAreEasyToGuess
                    }
                    zxcvbn::feedback::Warning::CommonNamesAndSurnamesAreEasyToGuess => {
                        PasswordFeedback::CommonNamesAndSurnamesAreEasyToGuess
                    }
                }))
                .collect();

            return Err(PasswordQuality::Feedback(feedback));
        }

        // check a password badlist to eliminate more content
        // we check the password as "lower case" to help eliminate possibilities
        // also, when pw_badlist_cache is read from DB, it is read as Value (iutf8 lowercase)
        if (&*self.pw_badlist_cache).contains(&cleartext.to_lowercase()) {
            security_info!("Password found in badlist, rejecting");
            Err(PasswordQuality::BadListed)
        } else {
            Ok(())
        }
    }

    pub fn credential_primary_set_password(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
        pw: &str,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        // Check pw quality (future - acc policy applies).
        self.check_password_quality(pw, session.account.related_inputs().as_slice())
            .map_err(|e| match e {
                PasswordQuality::TooShort(sz) => {
                    OperationError::PasswordQuality(vec![PasswordFeedback::TooShort(sz)])
                }
                PasswordQuality::BadListed => {
                    OperationError::PasswordQuality(vec![PasswordFeedback::BadListed])
                }
                PasswordQuality::Feedback(feedback) => OperationError::PasswordQuality(feedback),
            })?;

        let ncred = match &session.primary {
            Some(primary) => {
                // Is there a need to update the uuid of the cred re softlocks?
                primary.set_password(self.crypto_policy, pw)?
            }
            None => Credential::new_password_only(self.crypto_policy, pw)?,
        };

        session.primary = Some(ncred);
        Ok(session.deref().into())
    }

    pub fn credential_primary_init_totp(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        // Is there something else in progress?
        // Or should this just cancel it ....
        if !matches!(session.mfaregstate, MfaRegState::None) {
            admin_info!("Invalid TOTP state, another update is in progress");
            return Err(OperationError::InvalidState);
        }

        // Generate the TOTP.
        let totp_token = Totp::generate_secure(TOTP_DEFAULT_STEP);

        session.mfaregstate = MfaRegState::TotpInit(totp_token);
        // Now that it's in the state, it'll be in the status when returned.
        Ok(session.deref().into())
    }

    pub fn credential_primary_check_totp(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
        totp_chal: u32,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        // Are we in a totp reg state?
        match &session.mfaregstate {
            MfaRegState::TotpInit(totp_token) | MfaRegState::TotpTryAgain(totp_token) => {
                if totp_token.verify(totp_chal, &ct) {
                    // It was valid. Update the credential.
                    let ncred = session
                        .primary
                        .as_ref()
                        .map(|cred| cred.update_totp(totp_token.clone()))
                        .ok_or_else(|| {
                            admin_error!("A TOTP was added, but no primary credential stub exists");
                            OperationError::InvalidState
                        })?;

                    session.primary = Some(ncred);

                    // Set the state to None.
                    session.mfaregstate = MfaRegState::None;
                    Ok(session.deref().into())
                } else {
                    // What if it's a broken authenticator app? Google authenticator
                    // and authy both force sha1 and ignore the algo we send. So lets
                    // check that just in case.
                    let token_sha1 = totp_token.clone().downgrade_to_legacy();

                    if token_sha1.verify(totp_chal, &ct) {
                        // Greeeaaaaaatttt it's a broken app. Let's check the user
                        // knows this is broken, before we proceed.
                        session.mfaregstate = MfaRegState::TotpInvalidSha1(token_sha1);
                        Ok(session.deref().into())
                    } else {
                        // Let them check again, it's a typo.
                        session.mfaregstate = MfaRegState::TotpTryAgain(totp_token.clone());
                        Ok(session.deref().into())
                    }
                }
            }
            _ => Err(OperationError::InvalidRequestState),
        }
    }

    pub fn credential_primary_accept_sha1_totp(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        // Are we in a totp reg state?
        match &session.mfaregstate {
            MfaRegState::TotpInvalidSha1(token_sha1) => {
                // They have accepted it as sha1
                let ncred = session
                    .primary
                    .as_ref()
                    .map(|cred| cred.update_totp(token_sha1.clone()))
                    .ok_or_else(|| {
                        admin_error!("A TOTP was added, but no primary credential stub exists");
                        OperationError::InvalidState
                    })?;

                security_info!("A SHA1 TOTP credential was accepted");

                session.primary = Some(ncred);

                // Set the state to None.
                session.mfaregstate = MfaRegState::None;
                Ok(session.deref().into())
            }
            _ => Err(OperationError::InvalidRequestState),
        }
    }

    pub fn credential_primary_remove_totp(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        if !matches!(session.mfaregstate, MfaRegState::None) {
            admin_info!("Invalid TOTP state, another update is in progress");
            return Err(OperationError::InvalidState);
        }

        let ncred = session
            .primary
            .as_ref()
            .map(|cred| cred.remove_totp())
            .ok_or_else(|| {
                admin_error!("Try to remove TOTP, but no primary credential stub exists");
                OperationError::InvalidState
            })?;

        session.primary = Some(ncred);

        // Set the state to None.
        session.mfaregstate = MfaRegState::None;
        Ok(session.deref().into())
    }

    pub fn credential_primary_init_backup_codes(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        // I think we override/map the status to inject the codes as a once-off state message.

        let codes = backup_code_from_random();

        let ncred = session
            .primary
            .as_ref()
            .ok_or_else(|| {
                admin_error!("Tried to add backup codes, but no primary credential stub exists");
                OperationError::InvalidState
            })
            .and_then(|cred|
                cred.update_backup_code(BackupCodes::new(codes.clone()))
                    .map_err(|_| {
                        admin_error!("Tried to add backup codes, but MFA is not enabled on this credential yet");
                        OperationError::InvalidState
                    })
            )
            ?;

        session.primary = Some(ncred);

        Ok(session.deref().into()).map(|mut status: CredentialUpdateSessionStatus| {
            status.mfaregstate = MfaRegStateStatus::BackupCodes(codes);
            status
        })
    }

    pub fn credential_primary_remove_backup_codes(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);

        let ncred = session
            .primary
            .as_ref()
            .ok_or_else(|| {
                admin_error!("Tried to add backup codes, but no primary credential stub exists");
                OperationError::InvalidState
            })
            .and_then(|cred|
                cred.remove_backup_code()
                    .map_err(|_| {
                        admin_error!("Tried to remove backup codes, but MFA is not enabled on this credential yet");
                        OperationError::InvalidState
                    })
            )
            ?;

        session.primary = Some(ncred);

        Ok(session.deref().into())
    }

    pub fn credential_update_cancel_mfareg(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);
        session.mfaregstate = MfaRegState::None;
        Ok(session.deref().into())
    }

    pub fn credential_primary_delete(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.try_lock().map_err(|_| {
            admin_error!("Session already locked, unable to proceed.");
            OperationError::InvalidState
        })?;
        trace!(?session);
        session.primary = None;
        Ok(session.deref().into())
    }

    // Generate password?
}

#[cfg(test)]
mod tests {
    use super::{
        CredentialUpdateSessionToken, InitCredentialUpdateEvent, InitCredentialUpdateIntentEvent,
        MfaRegStateStatus, MAXIMUM_CRED_UPDATE_TTL, MAXIMUM_INTENT_TTL, MINIMUM_INTENT_TTL,
    };
    use crate::credential::totp::Totp;
    use crate::event::{AuthEvent, AuthResult, CreateEvent};
    use crate::idm::server::IdmServer;
    use crate::prelude::*;
    use std::time::Duration;

    use crate::idm::AuthState;
    use compiled_uuid::uuid;
    use kanidm_proto::v1::{AuthMech, CredentialDetailType};

    use async_std::task;

    const TEST_CURRENT_TIME: u64 = 6000;
    const TESTPERSON_UUID: Uuid = uuid!("cf231fea-1a8f-4410-a520-fd9b1a379c86");

    #[test]
    fn test_idm_credential_update_session_init() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let mut idms_prox_write = idms.proxy_write(ct);

            let testaccount_uuid = Uuid::new_v4();

            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("account")),
                ("name", Value::new_iname("user_account_only")),
                ("uuid", Value::new_uuid(testaccount_uuid)),
                ("description", Value::new_utf8s("testaccount")),
                ("displayname", Value::new_utf8s("testaccount"))
            );

            let e2 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("account")),
                ("class", Value::new_class("person")),
                ("name", Value::new_iname("testperson")),
                ("uuid", Value::new_uuid(TESTPERSON_UUID)),
                ("description", Value::new_utf8s("testperson")),
                ("displayname", Value::new_utf8s("testperson"))
            );

            let ce = CreateEvent::new_internal(vec![e1, e2]);
            let cr = idms_prox_write.qs_write.create(&ce);
            assert!(cr.is_ok());

            let testaccount = idms_prox_write
                .qs_write
                .internal_search_uuid(&testaccount_uuid)
                .expect("failed");

            let testperson = idms_prox_write
                .qs_write
                .internal_search_uuid(&TESTPERSON_UUID)
                .expect("failed");

            let idm_admin = idms_prox_write
                .qs_write
                .internal_search_uuid(&UUID_IDM_ADMIN)
                .expect("failed");

            // user without permission - fail
            // - accounts don't have self-write permission.

            let cur = idms_prox_write.init_credential_update(
                &InitCredentialUpdateEvent::new_impersonate_entry(testaccount),
                ct,
            );

            assert!(matches!(cur, Err(OperationError::NotAuthorised)));

            // user with permission - success

            let cur = idms_prox_write.init_credential_update(
                &InitCredentialUpdateEvent::new_impersonate_entry(testperson),
                ct,
            );

            assert!(cur.is_ok());

            // create intent token without permission - fail

            // create intent token with permission - success

            let cur = idms_prox_write.init_credential_update_intent(
                &InitCredentialUpdateIntentEvent::new_impersonate_entry(
                    idm_admin,
                    TESTPERSON_UUID,
                    MINIMUM_INTENT_TTL,
                ),
                ct,
            );

            assert!(cur.is_ok());
            let intent_tok = cur.expect("Failed to create intent token!");

            // exchange intent token - invalid - fail
            // Expired
            let cur = idms_prox_write
                .exchange_intent_credential_update(intent_tok.clone(), ct + MINIMUM_INTENT_TTL);

            assert!(matches!(cur, Err(OperationError::SessionExpired)));

            let cur = idms_prox_write
                .exchange_intent_credential_update(intent_tok.clone(), ct + MAXIMUM_INTENT_TTL);

            assert!(matches!(cur, Err(OperationError::SessionExpired)));

            // exchange intent token - success
            let cur = idms_prox_write.exchange_intent_credential_update(intent_tok.clone(), ct);

            assert!(cur.is_ok());

            // Already used.
            let cur = idms_prox_write.exchange_intent_credential_update(intent_tok, ct);

            trace!(?cur);
            assert!(cur.is_err());
        })
    }

    fn setup_test_session(idms: &IdmServer, ct: Duration) -> CredentialUpdateSessionToken {
        let mut idms_prox_write = idms.proxy_write(ct);

        let e2 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("account")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson")),
            ("uuid", Value::new_uuid(TESTPERSON_UUID)),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("testperson"))
        );

        let ce = CreateEvent::new_internal(vec![e2]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(cr.is_ok());

        let testperson = idms_prox_write
            .qs_write
            .internal_search_uuid(&TESTPERSON_UUID)
            .expect("failed");

        let cur = idms_prox_write.init_credential_update(
            &InitCredentialUpdateEvent::new_impersonate_entry(testperson),
            ct,
        );

        idms_prox_write.commit().expect("Failed to commit txn");

        cur.expect("Failed to start update")
    }

    fn renew_test_session(idms: &IdmServer, ct: Duration) -> CredentialUpdateSessionToken {
        let mut idms_prox_write = idms.proxy_write(ct);

        let testperson = idms_prox_write
            .qs_write
            .internal_search_uuid(&TESTPERSON_UUID)
            .expect("failed");

        let cur = idms_prox_write.init_credential_update(
            &InitCredentialUpdateEvent::new_impersonate_entry(testperson),
            ct,
        );

        idms_prox_write.commit().expect("Failed to commit txn");

        cur.expect("Failed to start update")
    }

    fn commit_session(idms: &IdmServer, ct: Duration, cust: CredentialUpdateSessionToken) {
        let mut idms_prox_write = idms.proxy_write(ct);

        idms_prox_write
            .commit_credential_update(cust, ct)
            .expect("Failed to commit credential update.");

        idms_prox_write.commit().expect("Failed to commit txn");
    }

    fn check_testperson_password(idms: &IdmServer, pw: &str, ct: Duration) -> Option<String> {
        let mut idms_auth = idms.auth();

        let auth_init = AuthEvent::named_init("testperson");

        let r1 = task::block_on(idms_auth.auth(&auth_init, ct));
        let ar = r1.unwrap();
        let AuthResult {
            sessionid,
            state,
            delay: _,
        } = ar;

        if !matches!(state, AuthState::Choose(_)) {
            debug!("Can't proceed - {:?}", state);
            return None;
        };

        let auth_begin = AuthEvent::begin_mech(sessionid, AuthMech::Password);

        let r2 = task::block_on(idms_auth.auth(&auth_begin, ct));
        let ar = r2.unwrap();
        let AuthResult {
            sessionid,
            state,
            delay: _,
        } = ar;

        assert!(matches!(state, AuthState::Continue(_)));

        let pw_step = AuthEvent::cred_step_password(sessionid, pw);

        // Expect success
        let r2 = task::block_on(idms_auth.auth(&pw_step, ct));
        debug!("r2 ==> {:?}", r2);
        idms_auth.commit().expect("Must not fail");

        match r2 {
            Ok(AuthResult {
                sessionid: _,
                state: AuthState::Success(token),
                delay: _,
            }) => Some(token),
            _ => None,
        }
    }

    fn check_testperson_password_totp(
        idms: &IdmServer,
        pw: &str,
        token: &Totp,
        ct: Duration,
    ) -> Option<String> {
        let mut idms_auth = idms.auth();

        let auth_init = AuthEvent::named_init("testperson");

        let r1 = task::block_on(idms_auth.auth(&auth_init, ct));
        let ar = r1.unwrap();
        let AuthResult {
            sessionid,
            state,
            delay: _,
        } = ar;

        if !matches!(state, AuthState::Choose(_)) {
            debug!("Can't proceed - {:?}", state);
            return None;
        };

        let auth_begin = AuthEvent::begin_mech(sessionid, AuthMech::PasswordMfa);

        let r2 = task::block_on(idms_auth.auth(&auth_begin, ct));
        let ar = r2.unwrap();
        let AuthResult {
            sessionid,
            state,
            delay: _,
        } = ar;

        assert!(matches!(state, AuthState::Continue(_)));

        let totp = token
            .do_totp_duration_from_epoch(&ct)
            .expect("Failed to perform totp step");

        let totp_step = AuthEvent::cred_step_totp(sessionid, totp);
        let r2 = task::block_on(idms_auth.auth(&totp_step, ct));
        let ar = r2.unwrap();
        let AuthResult {
            sessionid,
            state,
            delay: _,
        } = ar;

        assert!(matches!(state, AuthState::Continue(_)));

        let pw_step = AuthEvent::cred_step_password(sessionid, pw);

        // Expect success
        let r3 = task::block_on(idms_auth.auth(&pw_step, ct));
        debug!("r3 ==> {:?}", r3);
        idms_auth.commit().expect("Must not fail");

        match r3 {
            Ok(AuthResult {
                sessionid: _,
                state: AuthState::Success(token),
                delay: _,
            }) => Some(token),
            _ => None,
        }
    }

    fn check_testperson_password_backup_code(
        idms: &IdmServer,
        pw: &str,
        code: &str,
        ct: Duration,
    ) -> Option<String> {
        let mut idms_auth = idms.auth();

        let auth_init = AuthEvent::named_init("testperson");

        let r1 = task::block_on(idms_auth.auth(&auth_init, ct));
        let ar = r1.unwrap();
        let AuthResult {
            sessionid,
            state,
            delay: _,
        } = ar;

        if !matches!(state, AuthState::Choose(_)) {
            debug!("Can't proceed - {:?}", state);
            return None;
        };

        let auth_begin = AuthEvent::begin_mech(sessionid, AuthMech::PasswordMfa);

        let r2 = task::block_on(idms_auth.auth(&auth_begin, ct));
        let ar = r2.unwrap();
        let AuthResult {
            sessionid,
            state,
            delay: _,
        } = ar;

        assert!(matches!(state, AuthState::Continue(_)));

        let code_step = AuthEvent::cred_step_backup_code(sessionid, code);
        let r2 = task::block_on(idms_auth.auth(&code_step, ct));
        let ar = r2.unwrap();
        let AuthResult {
            sessionid,
            state,
            delay: _,
        } = ar;

        assert!(matches!(state, AuthState::Continue(_)));

        let pw_step = AuthEvent::cred_step_password(sessionid, pw);

        // Expect success
        let r3 = task::block_on(idms_auth.auth(&pw_step, ct));
        debug!("r3 ==> {:?}", r3);
        idms_auth.commit().expect("Must not fail");

        match r3 {
            Ok(AuthResult {
                sessionid: _,
                state: AuthState::Success(token),
                delay: _,
            }) => Some(token),
            _ => None,
        }
    }

    #[test]
    fn test_idm_credential_update_session_cleanup() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let cust = setup_test_session(idms, ct);

            let cutxn = idms.cred_update_transaction();
            // The session exists
            let c_status = cutxn.credential_update_status(&cust, ct);
            assert!(c_status.is_ok());
            drop(cutxn);

            // Making a new session is what triggers the clean of old sessions.
            let _ = renew_test_session(idms, ct + MAXIMUM_CRED_UPDATE_TTL + Duration::from_secs(1));

            let cutxn = idms.cred_update_transaction();

            // Now fake going back in time .... allows the tokne to decrypt, but the sesion
            // is gone anyway!
            let c_status = cutxn
                .credential_update_status(&cust, ct)
                .expect_err("Session is still valid!");
            assert!(matches!(c_status, OperationError::InvalidState));
        })
    }

    #[test]
    fn test_idm_credential_update_onboarding_create_new_pw() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let test_pw = "fo3EitierohF9AelaNgiem0Ei6vup4equo1Oogeevaetehah8Tobeengae3Ci0ooh0uki";
            let ct = Duration::from_secs(TEST_CURRENT_TIME);

            let cust = setup_test_session(idms, ct);

            let cutxn = idms.cred_update_transaction();

            // Get the credential status - this should tell
            // us the details of the credentials, as well as
            // if they are ready and valid to commit?
            let c_status = cutxn
                .credential_update_status(&cust, ct)
                .expect("Failed to get the current session status.");

            trace!(?c_status);

            assert!(c_status.primary.is_none());

            // Test initially creating a credential.
            //   - pw first
            let c_status = cutxn
                .credential_primary_set_password(&cust, ct, test_pw)
                .expect("Failed to update the primary cred password");

            assert!(c_status.can_commit);

            drop(cutxn);
            commit_session(idms, ct, cust);

            // Check it works!
            assert!(check_testperson_password(idms, test_pw, ct).is_some());

            // Test deleting the pw
            let cust = renew_test_session(idms, ct);
            let cutxn = idms.cred_update_transaction();

            let c_status = cutxn
                .credential_update_status(&cust, ct)
                .expect("Failed to get the current session status.");
            trace!(?c_status);
            assert!(c_status.primary.is_some());

            let c_status = cutxn
                .credential_primary_delete(&cust, ct)
                .expect("Failed to delete the primary cred");
            trace!(?c_status);
            assert!(c_status.primary.is_none());

            drop(cutxn);
            commit_session(idms, ct, cust);

            // Must fail now!
            assert!(check_testperson_password(idms, test_pw, ct).is_none());
        })
    }

    // Test set of primary account password
    //    - fail pw quality checks etc
    //    - set correctly.

    // - setup TOTP
    #[test]
    fn test_idm_credential_update_onboarding_create_new_mfa_totp_basic() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let test_pw = "fo3EitierohF9AelaNgiem0Ei6vup4equo1Oogeevaetehah8Tobeengae3Ci0ooh0uki";
            let ct = Duration::from_secs(TEST_CURRENT_TIME);

            let cust = setup_test_session(idms, ct);
            let cutxn = idms.cred_update_transaction();

            // Setup the PW
            let c_status = cutxn
                .credential_primary_set_password(&cust, ct, test_pw)
                .expect("Failed to update the primary cred password");

            // Since it's pw only.
            assert!(c_status.can_commit);

            //
            let c_status = cutxn
                .credential_primary_init_totp(&cust, ct)
                .expect("Failed to update the primary cred password");

            // Check the status has the token.
            let totp_token: Totp = match c_status.mfaregstate {
                MfaRegStateStatus::TotpCheck(secret) => Some(secret.into()),

                _ => None,
            }
            .expect("Unable to retrieve totp token, invalid state.");

            trace!(?totp_token);
            let chal = totp_token
                .do_totp_duration_from_epoch(&ct)
                .expect("Failed to perform totp step");

            // Intentionally get it wrong.
            let c_status = cutxn
                .credential_primary_check_totp(&cust, ct, chal + 1)
                .expect("Failed to update the primary cred password");

            assert!(matches!(
                c_status.mfaregstate,
                MfaRegStateStatus::TotpTryAgain
            ));

            let c_status = cutxn
                .credential_primary_check_totp(&cust, ct, chal)
                .expect("Failed to update the primary cred password");

            assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
            assert!(matches!(
                c_status.primary.as_ref().map(|c| &c.type_),
                Some(CredentialDetailType::PasswordMfa(true, _, 0))
            ));

            // Should be okay now!

            drop(cutxn);
            commit_session(idms, ct, cust);

            // Check it works!
            assert!(check_testperson_password_totp(idms, test_pw, &totp_token, ct).is_some());
            // No need to test delete of the whole cred, we already did with pw above.

            // If we remove TOTP, show it reverts back.
            let cust = renew_test_session(idms, ct);
            let cutxn = idms.cred_update_transaction();

            let c_status = cutxn
                .credential_primary_remove_totp(&cust, ct)
                .expect("Failed to update the primary cred password");

            assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
            assert!(matches!(
                c_status.primary.as_ref().map(|c| &c.type_),
                Some(CredentialDetailType::Password)
            ));

            drop(cutxn);
            commit_session(idms, ct, cust);

            // Check it works with totp removed.
            assert!(check_testperson_password(idms, test_pw, ct).is_some());
        })
    }

    // Check sha1 totp.
    #[test]
    fn test_idm_credential_update_onboarding_create_new_mfa_totp_sha1() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let test_pw = "fo3EitierohF9AelaNgiem0Ei6vup4equo1Oogeevaetehah8Tobeengae3Ci0ooh0uki";
            let ct = Duration::from_secs(TEST_CURRENT_TIME);

            let cust = setup_test_session(idms, ct);
            let cutxn = idms.cred_update_transaction();

            // Setup the PW
            let c_status = cutxn
                .credential_primary_set_password(&cust, ct, test_pw)
                .expect("Failed to update the primary cred password");

            // Since it's pw only.
            assert!(c_status.can_commit);

            //
            let c_status = cutxn
                .credential_primary_init_totp(&cust, ct)
                .expect("Failed to update the primary cred password");

            // Check the status has the token.
            let totp_token: Totp = match c_status.mfaregstate {
                MfaRegStateStatus::TotpCheck(secret) => Some(secret.into()),

                _ => None,
            }
            .expect("Unable to retrieve totp token, invalid state.");

            let totp_token = totp_token.downgrade_to_legacy();

            trace!(?totp_token);
            let chal = totp_token
                .do_totp_duration_from_epoch(&ct)
                .expect("Failed to perform totp step");

            // Should getn the warn that it's sha1
            let c_status = cutxn
                .credential_primary_check_totp(&cust, ct, chal)
                .expect("Failed to update the primary cred password");

            assert!(matches!(
                c_status.mfaregstate,
                MfaRegStateStatus::TotpInvalidSha1
            ));

            // Accept it
            let c_status = cutxn
                .credential_primary_accept_sha1_totp(&cust, ct)
                .expect("Failed to update the primary cred password");

            assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
            assert!(matches!(
                c_status.primary.as_ref().map(|c| &c.type_),
                Some(CredentialDetailType::PasswordMfa(true, _, 0))
            ));

            // Should be okay now!

            drop(cutxn);
            commit_session(idms, ct, cust);

            // Check it works!
            assert!(check_testperson_password_totp(idms, test_pw, &totp_token, ct).is_some());
            // No need to test delete, we already did with pw above.
        })
    }

    #[test]
    fn test_idm_credential_update_onboarding_create_new_mfa_totp_backup_codes() {
        run_idm_test!(
            |_qs: &QueryServer, idms: &IdmServer, idms_delayed: &mut IdmServerDelayed| {
                let test_pw =
                    "fo3EitierohF9AelaNgiem0Ei6vup4equo1Oogeevaetehah8Tobeengae3Ci0ooh0uki";
                let ct = Duration::from_secs(TEST_CURRENT_TIME);

                let cust = setup_test_session(idms, ct);
                let cutxn = idms.cred_update_transaction();

                // Setup the PW
                let _c_status = cutxn
                    .credential_primary_set_password(&cust, ct, test_pw)
                    .expect("Failed to update the primary cred password");

                // Backup codes are refused to be added because we don't have mfa yet.
                assert!(matches!(
                    cutxn.credential_primary_init_backup_codes(&cust, ct),
                    Err(OperationError::InvalidState)
                ));

                let c_status = cutxn
                    .credential_primary_init_totp(&cust, ct)
                    .expect("Failed to update the primary cred password");

                let totp_token: Totp = match c_status.mfaregstate {
                    MfaRegStateStatus::TotpCheck(secret) => Some(secret.into()),

                    _ => None,
                }
                .expect("Unable to retrieve totp token, invalid state.");

                trace!(?totp_token);
                let chal = totp_token
                    .do_totp_duration_from_epoch(&ct)
                    .expect("Failed to perform totp step");

                let c_status = cutxn
                    .credential_primary_check_totp(&cust, ct, chal)
                    .expect("Failed to update the primary cred password");

                assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
                assert!(matches!(
                    c_status.primary.as_ref().map(|c| &c.type_),
                    Some(CredentialDetailType::PasswordMfa(true, _, 0))
                ));

                // Now good to go, we need to now add our backup codes.
                // Whats the right way to get these back?
                let c_status = cutxn
                    .credential_primary_init_backup_codes(&cust, ct)
                    .expect("Failed to update the primary cred password");

                let codes = match c_status.mfaregstate {
                    MfaRegStateStatus::BackupCodes(codes) => Some(codes),
                    _ => None,
                }
                .expect("Unable to retrieve backupcodes, invalid state.");

                // Should error because the number is not 0
                debug!("{:?}", c_status.primary.as_ref().map(|c| &c.type_));
                assert!(matches!(
                    c_status.primary.as_ref().map(|c| &c.type_),
                    Some(CredentialDetailType::PasswordMfa(true, _, 8))
                ));

                // Should be okay now!
                drop(cutxn);
                commit_session(idms, ct, cust);

                let backup_code = codes.iter().next().expect("No codes available");

                // Check it works!
                assert!(
                    check_testperson_password_backup_code(idms, test_pw, backup_code, ct).is_some()
                );

                // There now should be a backup code invalidation present
                let da = idms_delayed.try_recv().expect("invalid");
                let r = task::block_on(idms.delayed_action(ct, da));
                assert!(r.is_ok());

                // Renew to start the next steps
                let cust = renew_test_session(idms, ct);
                let cutxn = idms.cred_update_transaction();

                // Only 7 codes left.
                let c_status = cutxn
                    .credential_update_status(&cust, ct)
                    .expect("Failed to get the current session status.");

                assert!(matches!(
                    c_status.primary.as_ref().map(|c| &c.type_),
                    Some(CredentialDetailType::PasswordMfa(true, _, 7))
                ));

                // If we remove codes, it leaves totp.
                let c_status = cutxn
                    .credential_primary_remove_backup_codes(&cust, ct)
                    .expect("Failed to update the primary cred password");

                assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
                assert!(matches!(
                    c_status.primary.as_ref().map(|c| &c.type_),
                    Some(CredentialDetailType::PasswordMfa(true, _, 0))
                ));

                // Re-add the codes.
                let c_status = cutxn
                    .credential_primary_init_backup_codes(&cust, ct)
                    .expect("Failed to update the primary cred password");

                assert!(matches!(
                    c_status.mfaregstate,
                    MfaRegStateStatus::BackupCodes(_)
                ));
                assert!(matches!(
                    c_status.primary.as_ref().map(|c| &c.type_),
                    Some(CredentialDetailType::PasswordMfa(true, _, 8))
                ));

                // If we remove totp, it removes codes.
                let c_status = cutxn
                    .credential_primary_remove_totp(&cust, ct)
                    .expect("Failed to update the primary cred password");

                assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
                assert!(matches!(
                    c_status.primary.as_ref().map(|c| &c.type_),
                    Some(CredentialDetailType::Password)
                ));

                drop(cutxn);
                commit_session(idms, ct, cust);
            }
        )
    }

    #[test]
    fn test_idm_credential_update_onboarding_cancel_inprogress_totp() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let test_pw = "fo3EitierohF9AelaNgiem0Ei6vup4equo1Oogeevaetehah8Tobeengae3Ci0ooh0uki";
            let ct = Duration::from_secs(TEST_CURRENT_TIME);

            let cust = setup_test_session(idms, ct);
            let cutxn = idms.cred_update_transaction();

            // Setup the PW
            let c_status = cutxn
                .credential_primary_set_password(&cust, ct, test_pw)
                .expect("Failed to update the primary cred password");

            // Since it's pw only.
            assert!(c_status.can_commit);

            //
            let c_status = cutxn
                .credential_primary_init_totp(&cust, ct)
                .expect("Failed to update the primary cred password");

            // Check the status has the token.
            assert!(c_status.can_commit);
            assert!(matches!(
                c_status.mfaregstate,
                MfaRegStateStatus::TotpCheck(_)
            ));

            let c_status = cutxn
                .credential_update_cancel_mfareg(&cust, ct)
                .expect("Failed to cancel inflight totp change");

            assert!(matches!(c_status.mfaregstate, MfaRegStateStatus::None));
            assert!(c_status.can_commit);

            drop(cutxn);
            commit_session(idms, ct, cust);

            // It's pw only, since we canceled TOTP
            assert!(check_testperson_password(idms, test_pw, ct).is_some());
        })
    }

    // Primary cred must be pw or pwmfa

    // - setup webauthn
    // - remove webauthn
    // - test mulitple webauthn token.

    // W_ policy, assert can't remove MFA if it's enforced.

    // enroll trusted device
    // remove trusted device.
    // trusted device flag changes?

    // Any policy checks we care about?

    // Others in the future
}
