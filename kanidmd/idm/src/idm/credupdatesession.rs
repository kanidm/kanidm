use crate::idm::server::IdmServerProxyWriteTransaction;
use crate::idm::account::Account;
use crate::access::AccessControlsTransaction;
use crate::prelude::*;

use crate::utils::uuid_from_duration;

use serde::{Deserialize, Serialize};

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

#[derive(Serialize, Deserialize, Debug)]
struct CredentialUpdateSessionToken {
    pub sessionid: Uuid,
    // Current credentials
    // Acc policy
}

pub(crate) struct CredentialUpdateSession {
    account: Account,
}

pub(crate) type CredentialUpdateSessionMutex = Arc<Mutex<CredentialUpdateSession>>;

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
    pub fn init_credential_update(&mut self,
        event: &InitCredentialUpdateEvent,
        ct: Duration,
    ) -> Result<String, OperationError> {
        spanned!("idm::server::credupdatesession<Init>", {
            admin_error!("init_credential_update");

            let entry = self.qs_write.internal_search_uuid(&event.target)?;

            security_info!(
                ?entry,
                uuid = %event.target,
                "Initiating Credential Update Session",
            );

            // Is target an account? This checks for us.
            let account = Account::try_from_entry_rw(entry.as_ref(), &mut self.qs_write)?;

            let effective_perms = self.qs_write.get_accesscontrols()
                .effective_permission_check(
                    &event.ident,
                    Some(btreeset![AttrString::from("primary_credential")]),
                    &[entry],
                )?;

            let eperm = effective_perms.get(0)
                .ok_or_else(|| {
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
                || !eperm.modify_rem.contains("primary_credential") {

                security_info!("Requestor {} does not have permission to update credentials of {}", event.ident, account.uuid);
                return Err(OperationError::NotAuthorised);
            }

            // ==== AUTHORISATION CHECKED ===

            // Build the cred update session.
            // - store account policy (if present)
            // - stash the current state of all associated credentials
            // -

            // Store the update session into the map.




            // - issue the CredentialUpdateToken (enc)
            let sessionid = uuid_from_duration(ct, self.sid);

            let session = Arc::new(Mutex::new(CredentialUpdateSession {
                account,
            }));

            let token = CredentialUpdateSessionToken {
                sessionid,
            };

            let token_data = serde_json::to_vec(&token).map_err(|e| {
                admin_error!(err = ?e, "Unable to encode token data");
                OperationError::SerdeJsonError
            })?;

            let token_enc = self.token_enc_key.encrypt_at_time(&token_data, ct.as_secs());

            // Point of no return

            self.cred_update_sessions.insert(sessionid, session);

            Ok(token_enc)
        })
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
            // user without permission - fail
            // - create a user
            // - remove the permission self mod credentials?
            // - init the session with the user via their uat.

            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let mut idms_prox_write = idms.proxy_write(ct);

            let testperson_uuid = Uuid::new_v4();

            let e = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("account")),
                ("name", Value::new_iname("user_account_only")),
                ("uuid", Value::new_uuid(testperson_uuid)),
                ("description", Value::new_utf8s("testperson")),
                ("displayname", Value::new_utf8s("testperson"))
            );

            let ce = CreateEvent::new_internal(vec![e.clone()]);
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

            assert!(cur.is_ok())

            // user with permission - success

            // create intent token without permission - fail

            // create intent token with permission - success

            // exchange intent token - invalid - fail

            // exchange intent token - success
        })
    }
}
