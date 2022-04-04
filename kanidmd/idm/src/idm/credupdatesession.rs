use crate::access::AccessControlsTransaction;
use crate::credential::Credential;
use crate::idm::account::Account;
use crate::idm::server::IdmServerCredUpdateTransaction;
use crate::idm::server::IdmServerProxyWriteTransaction;
use crate::prelude::*;
use kanidm_proto::v1::{CredentialDetail, PasswordFeedback};

use crate::utils::uuid_from_duration;

use serde::{Deserialize, Serialize};

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

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
    token_enc: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CredentialUpdateSessionTokenInner {
    pub sessionid: Uuid,
}

pub struct CredentialUpdateSessionToken {
    token_enc: String,
}

#[derive(Debug)]
pub(crate) struct CredentialUpdateSession {
    // Current credentials - these are on the Account!
    account: Account,
    // Acc policy
    // The credentials as they are being updated
    primary: Option<Credential>,
    // trusted_devices: Map<Webauthn>?
}

#[derive(Debug)]
pub(crate) struct CredentialUpdateSessionStatus {
    // spn: ?
    // ttl: Duration,
    //
    can_commit: bool,
    primary: Option<CredentialDetail>,
}

impl From<&CredentialUpdateSession> for CredentialUpdateSessionStatus {
    fn from(session: &CredentialUpdateSession) -> Self {
        CredentialUpdateSessionStatus {
            can_commit: true,
            primary: session.primary.as_ref().map(|c| c.into()),
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
    pub max_ttl: Duration,
}

impl InitCredentialUpdateIntentEvent {
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
            max_ttl,
        }
    }
}

pub struct InitCredentialUpdateEvent {
    pub ident: Identity,
    pub target: Uuid,
}

impl InitCredentialUpdateEvent {
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
        account: Account,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionToken, OperationError> {
        // - store account policy (if present)
        // - stash the current state of all associated credentials
        // -

        // Store the update session into the map.

        // - issue the CredentialUpdateToken (enc)

        // Need to change this to the expiry time, so we can purge up to.
        let sessionid = uuid_from_duration(ct + MAXIMUM_CRED_UPDATE_TTL, self.sid);
        let primary = account.primary.clone();

        let session = Arc::new(Mutex::new(CredentialUpdateSession { account, primary }));

        let token = CredentialUpdateSessionTokenInner { sessionid };

        let token_data = serde_json::to_vec(&token).map_err(|e| {
            admin_error!(err = ?e, "Unable to encode token data");
            OperationError::SerdeJsonError
        })?;

        let token_enc = self
            .token_enc_key
            .encrypt_at_time(&token_data, ct.as_secs());

        // Point of no return

        self.cred_update_sessions.insert(sessionid, session);

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

            // States For the user record
            //   - Initial (Valid)
            //   - Processing (Uuid of in flight req)
            //   - Canceled (Back to Valid)
            //   - Complete (The credential was updatded).

            // We need to actually submit a mod to the user.

            let max_ttl = ct + event.max_ttl.clamp(MINIMUM_INTENT_TTL, MAXIMUM_INTENT_TTL);
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
            .decrypt_at_time(&token.token_enc, None, ct.as_secs())
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

        security_info!(
            ?entry,
            %token.target,
            "Initiating Credential Update Session",
        );

        // Is target an account? This checks for us.
        let account = Account::try_from_entry_rw(entry.as_ref(), &mut self.qs_write)?;

        // Check there is not already a user session in progress with this intent token.
        // Is there a need to block intent tokens?

        // ==========
        // Okay, good to exchange.

        self.create_credupdate_session(account, ct)
    }

    pub fn init_credential_update(
        &mut self,
        event: &InitCredentialUpdateEvent,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionToken, OperationError> {
        spanned!("idm::server::credupdatesession<Init>", {
            let account = self.validate_init_credential_update(event.target, &event.ident)?;

            // ==== AUTHORISATION CHECKED ===

            // Build the cred update session.
            self.create_credupdate_session(account, ct)
        })
    }

    pub fn prune_sessions() {
        todo!();
    }

    pub fn commit_credential_update(
        &mut self,
        cust: CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<(), OperationError> {
        let session_token: CredentialUpdateSessionTokenInner = self
            .token_enc_key
            .decrypt_at_time(&cust.token_enc, None, ct.as_secs())
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

        let session_handle = self.cred_update_sessions.remove(&session_token.sessionid)
            .ok_or_else(|| {
                admin_error!("No such sessionid exists on this server - may be due to a load balancer failover or replay?");
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

        // Are any other checks needed?

        // Apply to the account!
        trace!(?modlist, "processing change");

        self.qs_write
            .internal_modify(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuidr(&session.account.uuid))),
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
            .decrypt_at_time(&cust.token_enc, None, ct.as_secs())
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
        // Asserted by the above.
        /*
        if ct >= token.max_ttl {
            trace!(?ct, ?token.max_ttl);
            security_info!(%token.sessionid, "session expired");
            return Err(OperationError::SessionExpired);
        }
        */

        self.cred_update_sessions.get(&session_token.sessionid)
            .ok_or_else(|| {
                admin_error!("No such sessionid exists on this server - may be due to a load balancer failover or replay?");
                OperationError::InvalidState
            })
            .cloned()
    }

    pub async fn credential_status(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let session = session_handle.lock().await;
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
                    security_info!("zxcvbn returned no feedback when score < 3");
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

    pub async fn credential_primary_set_password(
        &self,
        cust: &CredentialUpdateSessionToken,
        ct: Duration,
        pw: &str,
    ) -> Result<CredentialUpdateSessionStatus, OperationError> {
        let session_handle = self.get_current_session(cust, ct)?;
        let mut session = session_handle.lock().await;
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

    // Generate password?
}

#[cfg(test)]
mod tests {
    use super::{
        CredentialUpdateSessionToken, InitCredentialUpdateEvent, InitCredentialUpdateIntentEvent,
        MAXIMUM_INTENT_TTL, MINIMUM_INTENT_TTL,
    };
    use crate::event::CreateEvent;
    use crate::idm::server::IdmServer;
    use crate::prelude::*;
    use std::time::Duration;

    use async_std::task;

    const TEST_CURRENT_TIME: u64 = 6000;

    #[test]
    fn test_idm_credential_update_session_init() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let mut idms_prox_write = idms.proxy_write(ct);

            let testaccount_uuid = Uuid::new_v4();
            let testperson_uuid = Uuid::new_v4();

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
                ("uuid", Value::new_uuid(testperson_uuid)),
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
                .internal_search_uuid(&testperson_uuid)
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
                    testperson_uuid,
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

            assert!(cur.is_err());
        })
    }

    fn setup_test_session(idms: &IdmServer, ct: Duration) -> CredentialUpdateSessionToken {
        let mut idms_prox_write = idms.proxy_write(ct);

        let testperson_uuid = Uuid::new_v4();

        let e2 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("account")),
            ("class", Value::new_class("person")),
            ("name", Value::new_iname("testperson")),
            ("uuid", Value::new_uuid(testperson_uuid)),
            ("description", Value::new_utf8s("testperson")),
            ("displayname", Value::new_utf8s("testperson"))
        );

        let ce = CreateEvent::new_internal(vec![e2]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(cr.is_ok());

        let testperson = idms_prox_write
            .qs_write
            .internal_search_uuid(&testperson_uuid)
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

    #[test]
    fn test_idm_credential_update_onboarding() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);

            let cust = setup_test_session(idms, ct);

            let cutxn = idms.cred_update_transaction();

            // Get the credential status - this should tell
            // us the details of the credentials, as well as
            // if they are ready and valid to commit?
            let c_status = task::block_on(cutxn.credential_status(&cust, ct))
                .expect("Failed to get the current session status.");

            trace!(?c_status);

            assert!(matches!(c_status.primary, None));

            // Test initially creating a credential.
            //   - pw first
            let c_res = task::block_on(cutxn.credential_primary_set_password(
                &cust,
                ct,
                "fo3EitierohF9AelaNgiem0Ei6vup4equo1Oogeevaetehah8Tobeengae3Ci0ooh0uki",
            ))
            .expect("Failed to update the primary cred password");

            // - assert we are consistent to commit.
            let c_status = task::block_on(cutxn.credential_status(&cust, ct))
                .expect("Failed to get the current session status.");

            assert!(c_status.can_commit);

            drop(cutxn);

            commit_session(idms, ct, cust);

            // Check it?
        })
    }

    // Test set of primary account password
    //    - fail pw quality checks etc
    //    - set correctly.

    //  Assert pw can't be unset - whole credential must be deleted?

    // Primary cred must be pw or pwmfa

    // - setup TOTP
    // - remove totp.

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
