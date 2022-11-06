use std::collections::BTreeMap;
use std::time::Duration;

use base64urlsafedata::Base64UrlSafeData;

use compact_jwt::{Jws, JwsSigner};
use kanidm_proto::scim_v1::*;
use kanidm_proto::v1::ApiTokenPurpose;
use serde::{Deserialize, Serialize};

use crate::idm::server::{IdmServerProxyReadTransaction, IdmServerProxyWriteTransaction};
use crate::prelude::*;
use crate::value::Session;

// Internals of a Scim Sync token

#[allow(dead_code)]
pub(crate) struct SyncAccount {
    pub name: String,
    pub uuid: Uuid,
    pub sync_tokens: BTreeMap<Uuid, Session>,
    pub jws_key: JwsSigner,
}

macro_rules! try_from_entry {
    ($value:expr) => {{
        // Check the classes
        if !$value.attribute_equality("class", &PVCLASS_SYNC_ACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: sync account".to_string(),
            ));
        }

        let name = $value
            .get_ava_single_iname("name")
            .map(|s| s.to_string())
            .ok_or(OperationError::InvalidAccountState(
                "Missing attribute: name".to_string(),
            ))?;

        let jws_key = $value
            .get_ava_single_jws_key_es256("jws_es256_private_key")
            .cloned()
            .ok_or(OperationError::InvalidAccountState(
                "Missing attribute: jws_es256_private_key".to_string(),
            ))?;

        let sync_tokens = $value
            .get_ava_as_session_map("sync_token_session")
            .cloned()
            .unwrap_or_default();

        let uuid = $value.get_uuid().clone();

        Ok(SyncAccount {
            name,
            uuid,
            sync_tokens,
            jws_key,
        })
    }};
}

impl SyncAccount {
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn try_from_entry_rw(
        value: &Entry<EntrySealed, EntryCommitted>,
        // qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        // let groups = Group::try_from_account_entry_rw(value, qs)?;
        try_from_entry!(value)
    }

    pub(crate) fn check_sync_token_valid(
        _ct: Duration,
        sst: &ScimSyncToken,
        entry: &Entry<EntrySealed, EntryCommitted>,
    ) -> bool {
        let valid_purpose = matches!(sst.purpose, ApiTokenPurpose::Synchronise);

        // Get the sessions. There are no gracewindows on sync, we are much stricter.
        let session_present = entry
            .get_ava_as_session_map("sync_token_session")
            .map(|session_map| session_map.get(&sst.token_id).is_some())
            .unwrap_or(false);

        debug!(?session_present, valid_purpose);

        session_present && valid_purpose
    }
}

// Need to create a Sync input source
//

pub struct GenerateScimSyncTokenEvent {
    // Who initiated this?
    pub ident: Identity,
    // Who is it targetting?
    pub target: Uuid,
    // The label
    pub label: String,
}

impl GenerateScimSyncTokenEvent {
    #[cfg(test)]
    pub fn new_internal(target: Uuid, label: &str) -> Self {
        GenerateScimSyncTokenEvent {
            ident: Identity::from_internal(),
            target,
            label: label.to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub(crate) struct ScimSyncToken {
    // uuid of the token?
    pub token_id: Uuid,
    #[serde(with = "time::serde::timestamp")]
    pub issued_at: time::OffsetDateTime,
    #[serde(default)]
    pub purpose: ApiTokenPurpose,
}

impl<'a> IdmServerProxyWriteTransaction<'a> {
    pub fn scim_sync_generate_token(
        &mut self,
        gte: &GenerateScimSyncTokenEvent,
        ct: Duration,
    ) -> Result<String, OperationError> {
        // Get the target signing key.
        let sync_account = self
            .qs_write
            .internal_search_uuid(&gte.target)
            .and_then(|entry| SyncAccount::try_from_entry_rw(&entry))
            .map_err(|e| {
                admin_error!(?e, "Failed to search service account");
                e
            })?;

        let session_id = Uuid::new_v4();
        let issued_at = time::OffsetDateTime::unix_epoch() + ct;

        let purpose = ApiTokenPurpose::Synchronise;

        let session = Value::Session(
            session_id,
            Session {
                label: gte.label.clone(),
                expiry: None,
                // Need the other inner bits?
                // for the gracewindow.
                issued_at,
                // Who actually created this?
                issued_by: gte.ident.get_event_origin_id(),
                // What is the access scope of this session? This is
                // for auditing purposes.
                scope: (&purpose).into(),
            },
        );

        let token = Jws::new(ScimSyncToken {
            token_id: session_id,
            issued_at,
            purpose,
        });

        let modlist = ModifyList::new_list(vec![Modify::Present(
            AttrString::from("sync_token_session"),
            session,
        )]);

        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::new_uuid(gte.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::new_uuid(gte.target))),
                &modlist,
                // Provide the event to impersonate
                &gte.ident,
            )
            .and_then(|_| {
                // The modify succeeded and was allowed, now sign the token for return.
                token
                    .sign(&sync_account.jws_key)
                    .map(|jws_signed| jws_signed.to_string())
                    .map_err(|e| {
                        admin_error!(err = ?e, "Unable to sign sync token");
                        OperationError::CryptographyError
                    })
            })
            .map_err(|e| {
                admin_error!("Failed to generate sync token {:?}", e);
                e
            })
        // Done!
    }

    pub fn sync_account_destroy_token(
        &mut self,
        ident: &Identity,
        target: Uuid,
        _ct: Duration,
    ) -> Result<(), OperationError> {
        let modlist =
            ModifyList::new_list(vec![Modify::Purged(AttrString::from("sync_token_session"))]);

        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::Uuid(target))),
                // Filter as intended (acp)
                &filter!(f_eq("uuid", PartialValue::Uuid(target))),
                &modlist,
                // Provide the event to impersonate
                ident,
            )
            .map_err(|e| {
                admin_error!("Failed to destroy api token {:?}", e);
                e
            })
    }
}

pub struct ScimSyncUpdateEvent {
    pub ident: Identity,
}

impl<'a> IdmServerProxyWriteTransaction<'a> {
    pub fn scim_sync_apply(
        &mut self,
        sse: &ScimSyncUpdateEvent,
        _ct: Duration,
    ) -> Result<(), OperationError> {
        let _sync_uuid = match &sse.ident.origin {
            IdentType::User(_) | IdentType::Internal => {
                warn!("Ident type is not synchronise");
                return Err(OperationError::AccessDenied);
            }
            IdentType::Synch(u) => {
                // Ok!
                u
            }
        };

        match sse.ident.access_scope() {
            AccessScope::IdentityOnly | AccessScope::ReadOnly | AccessScope::ReadWrite => {
                warn!("Ident access scope is not synchronise");
                return Err(OperationError::AccessDenied);
            }
            AccessScope::Synchronise => {
                // As you were
            }
        };

        // Only update entries related to this uuid
        // Make a sync_authority uuid to relate back to on creates.

        // How to check for re-use of a cookie?

        // How to handle delete then re-add of same syncuuid?
        // Syncuuid could be a seperate attr so that we avoid this?

        // Should deleted by synced item be exempt on recycle purge? Should
        // it just go direct to tombstone?

        Err(OperationError::AccessDenied)
    }
}

impl<'a> IdmServerProxyReadTransaction<'a> {
    pub fn scim_sync_get_state(&self, ident: &Identity) -> Result<ScimSyncState, OperationError> {
        // We must be *extra* careful in these functions since we do *internal* searches
        // which are *bypassing* normal access checks!

        // The ident *must* be a synchronise session.
        let sync_uuid = match &ident.origin {
            IdentType::User(_) | IdentType::Internal => {
                warn!("Ident type is not synchronise");
                return Err(OperationError::AccessDenied);
            }
            IdentType::Synch(u) => {
                // Ok!
                u
            }
        };

        match ident.access_scope() {
            AccessScope::IdentityOnly | AccessScope::ReadOnly | AccessScope::ReadWrite => {
                warn!("Ident access scope is not synchronise");
                return Err(OperationError::AccessDenied);
            }
            AccessScope::Synchronise => {
                // As you were
            }
        };

        // Get the sync cookie of that session.
        let sync_entry = self.qs_read.internal_search_uuid(sync_uuid)?;

        Ok(
            match sync_entry.get_ava_single_private_binary("sync_cookie") {
                Some(b) => ScimSyncState::Active {
                    cookie: Base64UrlSafeData(b.to_vec()),
                },
                None => ScimSyncState::Initial,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::event::CreateEvent;
    use crate::event::ModifyEvent;
    use crate::idm::server::{IdmServerProxyWriteTransaction, IdmServerTransaction};
    use crate::prelude::*;
    use compact_jwt::Jws;
    use kanidm_proto::scim_v1::*;
    use kanidm_proto::v1::ApiTokenPurpose;
    use std::time::Duration;

    use super::{GenerateScimSyncTokenEvent, ScimSyncToken};

    use async_std::task;

    const TEST_CURRENT_TIME: u64 = 6000;

    fn create_scim_sync_account(
        idms_prox_write: &mut IdmServerProxyWriteTransaction<'_>,
        ct: Duration,
    ) -> (Uuid, String) {
        let sync_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("sync_account")),
            ("name", Value::new_iname("test_scim_sync")),
            ("uuid", Value::new_uuid(sync_uuid)),
            ("description", Value::new_utf8s("A test sync agreement"))
        );

        let ce = CreateEvent::new_internal(vec![e1]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(cr.is_ok());

        let gte = GenerateScimSyncTokenEvent::new_internal(sync_uuid, "Sync Connector");

        let sync_token = idms_prox_write
            .scim_sync_generate_token(&gte, ct)
            .expect("failed to generate new scim sync token");

        (sync_uuid, sync_token)
    }

    #[test]
    fn test_idm_scim_sync_basic_function() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);

            let mut idms_prox_write = task::block_on(idms.proxy_write(ct));
            let (sync_uuid, sync_token) = create_scim_sync_account(&mut idms_prox_write, ct);

            assert!(idms_prox_write.commit().is_ok());

            // Do a get_state to get the current "state cookie" if any.
            let idms_prox_read = task::block_on(idms.proxy_read());

            let ident = idms_prox_read
                .validate_and_parse_sync_token_to_ident(Some(sync_token.as_str()), ct)
                .expect("Failed to validate sync token");

            assert!(Some(sync_uuid) == ident.get_uuid());

            let sync_state = idms_prox_read
                .scim_sync_get_state(&ident)
                .expect("Failed to get current sync state");
            trace!(?sync_state);

            assert!(matches!(sync_state, ScimSyncState::Initial));

            drop(idms_prox_read);

            // Use the current state and update.

            // TODO!!!
        })
    }

    #[test]
    fn test_idm_scim_sync_token_security() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);

            let mut idms_prox_write = task::block_on(idms.proxy_write(ct));

            let sync_uuid = Uuid::new_v4();

            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("sync_account")),
                ("name", Value::new_iname("test_scim_sync")),
                ("uuid", Value::new_uuid(sync_uuid)),
                ("description", Value::new_utf8s("A test sync agreement"))
            );

            let ce = CreateEvent::new_internal(vec![e1]);
            let cr = idms_prox_write.qs_write.create(&ce);
            assert!(cr.is_ok());

            let gte = GenerateScimSyncTokenEvent::new_internal(sync_uuid, "Sync Connector");

            let sync_token = idms_prox_write
                .scim_sync_generate_token(&gte, ct)
                .expect("failed to generate new scim sync token");

            assert!(idms_prox_write.commit().is_ok());

            // -- Check the happy path.
            let idms_prox_read = task::block_on(idms.proxy_read());
            let ident = idms_prox_read
                .validate_and_parse_sync_token_to_ident(Some(sync_token.as_str()), ct)
                .expect("Failed to validate sync token");
            assert!(Some(sync_uuid) == ident.get_uuid());
            drop(idms_prox_read);

            // -- Revoke the session

            let mut idms_prox_write = task::block_on(idms.proxy_write(ct));
            let me_inv_m = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("test_scim_sync"))),
                    ModifyList::new_list(vec![Modify::Purged(AttrString::from(
                        "sync_token_session",
                    ))]),
                )
            };
            assert!(idms_prox_write.qs_write.modify(&me_inv_m).is_ok());
            assert!(idms_prox_write.commit().is_ok());

            // Must fail
            let idms_prox_read = task::block_on(idms.proxy_read());
            let fail = idms_prox_read
                .validate_and_parse_sync_token_to_ident(Some(sync_token.as_str()), ct);
            assert!(matches!(fail, Err(OperationError::NotAuthenticated)));
            drop(idms_prox_read);

            // -- New session, reset the JWS
            let mut idms_prox_write = task::block_on(idms.proxy_write(ct));

            let gte = GenerateScimSyncTokenEvent::new_internal(sync_uuid, "Sync Connector");
            let sync_token = idms_prox_write
                .scim_sync_generate_token(&gte, ct)
                .expect("failed to generate new scim sync token");

            let me_inv_m = unsafe {
                ModifyEvent::new_internal_invalid(
                    filter!(f_eq("name", PartialValue::new_iname("test_scim_sync"))),
                    ModifyList::new_list(vec![Modify::Purged(AttrString::from(
                        "jws_es256_private_key",
                    ))]),
                )
            };
            assert!(idms_prox_write.qs_write.modify(&me_inv_m).is_ok());
            assert!(idms_prox_write.commit().is_ok());

            let idms_prox_read = task::block_on(idms.proxy_read());
            let fail = idms_prox_read
                .validate_and_parse_sync_token_to_ident(Some(sync_token.as_str()), ct);
            assert!(matches!(fail, Err(OperationError::NotAuthenticated)));

            // -- Forge a session, use wrong types

            let sync_entry = idms_prox_read
                .qs_read
                .internal_search_uuid(&sync_uuid)
                .expect("Unable to access sync entry");

            let jws_key = sync_entry
                .get_ava_single_jws_key_es256("jws_es256_private_key")
                .cloned()
                .expect("Missing attribute: jws_es256_private_key");

            let sync_tokens = sync_entry
                .get_ava_as_session_map("sync_token_session")
                .cloned()
                .unwrap_or_default();

            // Steal these from the legit sesh.
            let (token_id, issued_at) = sync_tokens
                .iter()
                .next()
                .map(|(k, v)| (*k, v.issued_at.clone()))
                .expect("No sync tokens present");

            let purpose = ApiTokenPurpose::ReadWrite;

            let token = Jws::new(ScimSyncToken {
                token_id,
                issued_at,
                purpose,
            });

            let forged_token = token
                .sign(&jws_key)
                .map(|jws_signed| jws_signed.to_string())
                .expect("Unable to sign forged token");

            let fail = idms_prox_read
                .validate_and_parse_sync_token_to_ident(Some(forged_token.as_str()), ct);
            assert!(matches!(fail, Err(OperationError::NotAuthenticated)));
        })
    }

    // Need to delete different phases such as conflictn and end of the agreement.
}
