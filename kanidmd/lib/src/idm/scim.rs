use std::collections::BTreeMap;
use std::time::Duration;

use base64urlsafedata::Base64UrlSafeData;

use compact_jwt::{Jws, JwsSigner};
use kanidm_proto::scim_v1::ScimSyncRequest;
use kanidm_proto::scim_v1::*;
use kanidm_proto::v1::ApiTokenPurpose;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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
        changes: &ScimSyncRequest,
        _ct: Duration,
    ) -> Result<(), OperationError> {
        let (sync_uuid, _sync_authority_set, change_entries) =
            self.scim_sync_apply_phase_1(sse, changes)?;

        // TODO: If the from_state is refresh and the to_state is active, then we need to
        // do delete all entries NOT present in the refresh set.
        // This accounts for the state of:
        //      active -> refresh -> active
        // which can occur when ldap asks us to do a refresh. Because of this entries may have
        // been removed, and will NOT be present in a delete_uuids phase. We can't just blanket
        // delete here as some entries may have been modified by users with authority over the
        // attributes.

        let _sync_entries =
            self.qs_write
                .scim_sync_apply_phase_2(sse, &change_entries, sync_uuid)?;

        Err(OperationError::AccessDenied)
    }

    fn scim_sync_apply_phase_1<'b>(
        &mut self,
        sse: &'b ScimSyncUpdateEvent,
        changes: &'b ScimSyncRequest,
    ) -> Result<(Uuid, BTreeSet<String>, BTreeMap<Uuid, &'b ScimEntry>), OperationError> {
        // Assert the token is valid.
        let sync_uuid = match &sse.ident.origin {
            IdentType::User(_) | IdentType::Internal => {
                warn!("Ident type is not synchronise");
                return Err(OperationError::AccessDenied);
            }
            IdentType::Synch(u) => {
                // Ok!
                *u
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

        // Retrieve the related sync entry.
        let sync_entry = self
            .qs_write
            .internal_search_uuid(&sync_uuid)
            .map_err(|e| {
                error!("Failed to located sync entry related to {}", sync_uuid);
                e
            })?;

        // Assert that the requested "from" state is consistent to this entry.
        // OperationError::InvalidSyncState

        match (
            &changes.from_state,
            sync_entry.get_ava_single_private_binary("sync_cookie"),
        ) {
            (ScimSyncState::Refresh, None) => {
                // valid
                info!("Refresh Sync");
            }
            (ScimSyncState::Active { cookie }, Some(sync_cookie)) => {
                // Check cookies.
                if cookie.0 != sync_cookie {
                    // Invalid
                    error!(
                        "Invalid Sync State - Active, but agreement has divegent external cookie."
                    );
                    return Err(OperationError::InvalidSyncState);
                } else {
                    // Valid
                    info!("Active Sync with valid cookie");
                }
            }
            (ScimSyncState::Refresh, Some(_)) => {
                error!("Invalid Sync State - Refresh, but agreement has Active sync.");
                return Err(OperationError::InvalidSyncState);
            }
            (ScimSyncState::Active { cookie: _ }, None) => {
                error!("Invalid Sync State - Active, but agreement has Refresh Required.");
                return Err(OperationError::InvalidSyncState);
            }
        };

        // Retrieve the sync_authority_set
        let sync_authority_set = BTreeSet::default();

        // Return these.

        // Transform the changes into something that supports lookups.
        let change_entries: BTreeMap<Uuid, &ScimEntry> = changes
            .entries
            .iter()
            .map(|scim_entry| (scim_entry.id, scim_entry))
            .collect();

        Ok((sync_uuid, sync_authority_set, change_entries))
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
                None => ScimSyncState::Refresh,
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
    use base64urlsafedata::Base64UrlSafeData;
    use compact_jwt::Jws;
    use kanidm_proto::scim_v1::*;
    use kanidm_proto::v1::ApiTokenPurpose;
    use std::time::Duration;

    use super::{GenerateScimSyncTokenEvent, ScimSyncToken, ScimSyncUpdateEvent};

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

            assert!(matches!(sync_state, ScimSyncState::Refresh));

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

    fn test_scim_sync_apply_setup_ident(
        idms_prox_write: &mut IdmServerProxyWriteTransaction,
        ct: Duration,
    ) -> (Uuid, Identity) {
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

        let ident = idms_prox_write
            .validate_and_parse_sync_token_to_ident(Some(sync_token.as_str()), ct)
            .expect("Failed to process sync token to ident");

        (sync_uuid, ident)
    }

    #[test]
    fn test_idm_scim_sync_apply_phase_1_inconsistent() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let mut idms_prox_write = task::block_on(idms.proxy_write(ct));
            let (_sync_uuid, ident) = test_scim_sync_apply_setup_ident(&mut idms_prox_write, ct);
            let sse = ScimSyncUpdateEvent { ident };

            let changes = ScimSyncRequest {
                from_state: ScimSyncState::Active {
                    cookie: Base64UrlSafeData(vec![1, 2, 3, 4]),
                },
                to_state: ScimSyncState::Refresh,
                entries: Vec::default(),
                delete_uuids: Vec::default(),
            };

            let res = idms_prox_write.scim_sync_apply_phase_1(&sse, &changes);

            assert!(matches!(res, Err(OperationError::InvalidSyncState)));

            assert!(idms_prox_write.commit().is_ok());
        })
    }

    #[test]
    fn test_idm_scim_sync_apply_phase_2_basic() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let mut idms_prox_write = task::block_on(idms.proxy_write(ct));
            let (_sync_uuid, ident) = test_scim_sync_apply_setup_ident(&mut idms_prox_write, ct);
            let sse = ScimSyncUpdateEvent { ident };

            let changes = ScimSyncRequest {
                from_state: ScimSyncState::Refresh,
                to_state: ScimSyncState::Active {
                    cookie: Base64UrlSafeData(vec![1, 2, 3, 4]),
                },
                entries: vec![ScimEntry {
                    schemas: vec![SCIM_SCHEMA_SYNC_PERSON.to_string()],
                    id: uuid::uuid!("91b7aaf2-2445-46ce-8998-96d9f186cc69"),
                    external_id: Some("dn=william,ou=people,dc=test".to_string()),
                    meta: None,
                    attrs: btreemap!((
                        "name".to_string(),
                        ScimAttr::SingleSimple(ScimSimpleAttr::String("william".to_string()))
                    ),),
                }],
                delete_uuids: Vec::default(),
            };

            let (sync_uuid, _sync_authority_set, change_entries) = idms_prox_write
                .scim_sync_apply_phase_1(&sse, &changes)
                .expect("Failed to run phase 1");

            let _ = idms_prox_write
                .qs_write
                .scim_sync_apply_phase_2(&sse, &change_entries, sync_uuid)
                .expect("Failed to run phase 2");

            assert!(idms_prox_write.commit().is_ok());
        })
    }

    #[test]
    fn test_idm_scim_sync_refresh_1() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {
            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let mut idms_prox_write = task::block_on(idms.proxy_write(ct));
            let (_sync_uuid, ident) = test_scim_sync_apply_setup_ident(&mut idms_prox_write, ct);
            let sse = ScimSyncUpdateEvent { ident };

            let changes =
                serde_json::from_str(TEST_SYNC_SCIM_IPA_1).expect("failed to parse scim sync");

            let res = idms_prox_write.scim_sync_apply(&sse, &changes, ct);

            // Currently in testing this is just access denied.
            assert!(matches!(res, Err(OperationError::AccessDenied)));

            assert!(idms_prox_write.commit().is_ok());
        })
    }

    const TEST_SYNC_SCIM_IPA_1: &str = r#"
    {
      "from_state": "Refresh",
      "to_state": {
        "Active": {
          "cookie": "aXBhLXN5bmNyZXBsLWthbmkuZGV2LmJsYWNraGF0cy5uZXQuYXU6Mzg5I2NuPWRpcmVjdG9yeSBtYW5hZ2VyOmRjPWRldixkYz1ibGFja2hhdHMsZGM9bmV0LGRjPWF1Oih8KCYob2JqZWN0Q2xhc3M9cGVyc29uKShvYmplY3RDbGFzcz1pcGFudHVzZXJhdHRycykob2JqZWN0Q2xhc3M9cG9zaXhhY2NvdW50KSkoJihvYmplY3RDbGFzcz1ncm91cG9mbmFtZXMpKG9iamVjdENsYXNzPWlwYXVzZXJncm91cCkoIShvYmplY3RDbGFzcz1tZXBtYW5hZ2VkZW50cnkpKSghKGNuPWFkbWlucykpKCEoY249aXBhdXNlcnMpKSkoJihvYmplY3RDbGFzcz1pcGF0b2tlbikob2JqZWN0Q2xhc3M9aXBhdG9rZW50b3RwKSkpIzEwOQ"
        }
      },
      "entries": [
        {
          "schemas": [
            "urn:ietf:params:scim:schemas:kanidm:1.0:sync:person"
          ],
          "id": "ac60034b-3498-11ed-a50d-919b4b1a5ec0",
          "externalId": "uid=admin,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
          "displayName": "Administrator",
          "gidNumber": 8200000,
          "homeDirectory": "/home/admin",
          "loginShell": "/bin/bash",
          "passwordImport": "CVBguEizG80swI8sftaknw",
          "userName": "admin"
        },
        {
          "schemas": [
            "urn:ietf:params:scim:schemas:kanidm:1.0:sync:group"
          ],
          "id": "ac60034e-3498-11ed-a50d-919b4b1a5ec0",
          "externalId": "cn=editors,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
          "description": "Limited admins who can edit other users",
          "gidNumber": 8200002,
          "name": "editors"
        },
        {
          "schemas": [
            "urn:ietf:params:scim:schemas:kanidm:1.0:sync:group"
          ],
          "id": "0c56a965-3499-11ed-a50d-919b4b1a5ec0",
          "externalId": "cn=trust admins,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
          "description": "Trusts administrators group",
          "members": [
            {
              "external_id": "uid=admin,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au"
            }
          ],
          "name": "trust admins"
        },
        {
          "schemas": [
            "urn:ietf:params:scim:schemas:kanidm:1.0:sync:person"
          ],
          "id": "babb8302-43a1-11ed-a50d-919b4b1a5ec0",
          "externalId": "uid=testuser,cn=users,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
          "displayName": "Test User",
          "gidNumber": 12345,
          "homeDirectory": "/home/testuser",
          "loginShell": "/bin/sh",
          "passwordImport": "iEb36u6PsRetBr3YMLdYbA",
          "userName": "testuser"
        },
        {
          "schemas": [
            "urn:ietf:params:scim:schemas:kanidm:1.0:sync:group"
          ],
          "id": "d547c581-5f26-11ed-a50d-919b4b1a5ec0",
          "externalId": "cn=testgroup,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
          "description": "Test group",
          "name": "testgroup"
        },
        {
          "schemas": [
            "urn:ietf:params:scim:schemas:kanidm:1.0:sync:group"
          ],
          "id": "d547c583-5f26-11ed-a50d-919b4b1a5ec0",
          "externalId": "cn=testexternal,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
          "name": "testexternal"
        },
        {
          "schemas": [
            "urn:ietf:params:scim:schemas:kanidm:1.0:sync:group"
          ],
          "id": "f90b0b81-5f26-11ed-a50d-919b4b1a5ec0",
          "externalId": "cn=testposix,cn=groups,cn=accounts,dc=dev,dc=blackhats,dc=net,dc=au",
          "gidNumber": 1234567,
          "name": "testposix"
        }
      ],
      "delete_uuids": []
    }
    "#;
}
