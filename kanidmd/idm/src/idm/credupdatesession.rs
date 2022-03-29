use crate::access::AccessControlsTransaction;
use crate::idm::account::Account;
use crate::idm::server::IdmServerProxyWriteTransaction;
use crate::prelude::*;

use crate::utils::uuid_from_duration;

use serde::{Deserialize, Serialize};

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

const MAXIMUM_CRED_UPDATE_TTL: Duration = Duration::from_secs(900);
const MAXIMUM_INTENT_TTL: Duration = Duration::from_secs(86400);
const MINIMUM_INTENT_TTL: Duration = MAXIMUM_CRED_UPDATE_TTL;

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

pub(crate) struct CredentialUpdateSession {
    account: Account,
    // Current credentials
    // Acc policy
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

    fn create_credupdate_session(&mut self,
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

            let session = Arc::new(Mutex::new(CredentialUpdateSession { account }));

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

            Ok(CredentialUpdateSessionToken {
                token_enc })
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

            let max_ttl = event.max_ttl.clamp(MINIMUM_INTENT_TTL, MAXIMUM_INTENT_TTL);
            let sessionid = uuid_from_duration(ct + max_ttl, self.sid);
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

            Ok(CredentialUpdateIntentToken {
                token_enc
            })
        })
    }

    pub fn exchange_intent_credential_update(&mut self,
        token: CredentialUpdateIntentToken,
        ct: Duration,
    ) -> Result<CredentialUpdateSessionToken, OperationError> {
        let token: CredentialUpdateIntentTokenInner = self.token_enc_key
            .decrypt_at_time(&token.token_enc, Some(MAXIMUM_INTENT_TTL.as_secs()), ct.as_secs())
            .map_err(|_| {
                admin_error!("Failed to decrypt intent request");
                OperationError::CryptographyError
            })
            .and_then(|data| {
                serde_json::from_slice(&data).map_err(|e| {
                    admin_error!(err = ?e, "Failed to deserialise intent request");
                    OperationError::SerdeJsonError
                })
            })?;

        // Check the TTL
        if ct > token.max_ttl {
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

    pub fn finalise_credential_update(
        &mut self,
        ct: Duration,
    ) -> Result<(), OperationError> {
        unimplemented!();
    }
}

impl<'a> IdmServerCredUpdateTransaction<'a> {
    pub fn do_something(&self,

        ct: Duration,
    ) -> Result<(), OperationError> {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    // use crate::prelude::*;
    use super::InitCredentialUpdateEvent;
    use crate::event::CreateEvent;
    use std::time::Duration;

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

            // exchange intent token - invalid - fail
            // Expired
            // To early (somehow)
            // Already used.

            // exchange intent token - success
        })
    }
}
