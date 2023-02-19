use std::collections::BTreeMap;
use std::time::Duration;

use compact_jwt::{Jws, JwsSigner};
use kanidm_proto::v1::{ApiToken, ApiTokenPurpose};
use time::OffsetDateTime;

use crate::event::SearchEvent;
use crate::idm::account::Account;
use crate::idm::server::{IdmServerProxyReadTransaction, IdmServerProxyWriteTransaction};
use crate::prelude::*;
use crate::value::Session;

// Need to add KID to es256 der for lookups ✅

// Need to generate the es256 on the account on modifies ✅

// Add migration to generate the es256 on startup at least once. ✅

// Create new valueset type to store sessions w_ labels ✅

// Able to lookup from KID to get service account

// Able to take token -> ident
//   -- check still valid

// revoke

macro_rules! try_from_entry {
    ($value:expr) => {{
        // Check the classes
        if !$value.attribute_equality("class", &PVCLASS_SERVICE_ACCOUNT) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: service account".to_string(),
            ));
        }

        let spn = $value.get_ava_single_proto_string("spn").ok_or(
            OperationError::InvalidAccountState("Missing attribute: spn".to_string()),
        )?;

        let jws_key = $value
            .get_ava_single_jws_key_es256("jws_es256_private_key")
            .cloned()
            .ok_or(OperationError::InvalidAccountState(
                "Missing attribute: jws_es256_private_key".to_string(),
            ))?;

        let api_tokens = $value
            .get_ava_as_session_map("api_token_session")
            .cloned()
            .unwrap_or_default();

        let valid_from = $value.get_ava_single_datetime("account_valid_from");

        let expire = $value.get_ava_single_datetime("account_expire");

        let uuid = $value.get_uuid().clone();

        Ok(ServiceAccount {
            spn,
            uuid,
            valid_from,
            expire,
            api_tokens,
            jws_key,
        })
    }};
}

pub struct ServiceAccount {
    pub spn: String,
    pub uuid: Uuid,

    pub valid_from: Option<OffsetDateTime>,
    pub expire: Option<OffsetDateTime>,

    pub api_tokens: BTreeMap<Uuid, Session>,

    pub jws_key: JwsSigner,
}

impl ServiceAccount {
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn try_from_entry_rw(
        value: &Entry<EntrySealed, EntryCommitted>,
        // qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        // let groups = Group::try_from_account_entry_rw(value, qs)?;
        try_from_entry!(value)
    }

    pub(crate) fn check_api_token_valid(
        ct: Duration,
        apit: &ApiToken,
        entry: &Entry<EntrySealed, EntryCommitted>,
    ) -> bool {
        let within_valid_window = Account::check_within_valid_time(
            ct,
            entry.get_ava_single_datetime("account_valid_from").as_ref(),
            entry.get_ava_single_datetime("account_expire").as_ref(),
        );

        if !within_valid_window {
            security_info!("Account has expired or is not yet valid, not allowing to proceed");
            return false;
        }

        // Get the sessions.
        let session_present = entry
            .get_ava_as_session_map("api_token_session")
            .map(|session_map| session_map.get(&apit.token_id).is_some())
            .unwrap_or(false);

        if session_present {
            security_info!("A valid session value exists for this token");
            true
        } else {
            let grace = apit.issued_at + GRACE_WINDOW;
            let current = time::OffsetDateTime::unix_epoch() + ct;
            trace!(%grace, %current);
            if current >= grace {
                security_info!(
                    "The token grace window has passed, and no session exists. Assuming invalid."
                );
                false
            } else {
                security_info!("The token grace window is in effect. Assuming valid.");
                true
            }
        }
    }
}

pub struct ListApiTokenEvent {
    // Who initiated this?
    pub ident: Identity,
    // Who is it targeting?
    pub target: Uuid,
}

pub struct GenerateApiTokenEvent {
    // Who initiated this?
    pub ident: Identity,
    // Who is it targeting?
    pub target: Uuid,
    // The label
    pub label: String,
    // When should it expire?
    pub expiry: Option<time::OffsetDateTime>,
    // Is it read_write capable?
    pub read_write: bool,
    // Limits?
}

impl GenerateApiTokenEvent {
    #[cfg(test)]
    pub fn new_internal(target: Uuid, label: &str, expiry: Option<Duration>) -> Self {
        GenerateApiTokenEvent {
            ident: Identity::from_internal(),
            target,
            label: label.to_string(),
            expiry: expiry.map(|ct| time::OffsetDateTime::unix_epoch() + ct),
            read_write: false,
        }
    }
}

pub struct DestroyApiTokenEvent {
    // Who initiated this?
    pub ident: Identity,
    // Who is it targeting?
    pub target: Uuid,
    // Which token id.
    pub token_id: Uuid,
}

impl DestroyApiTokenEvent {
    #[cfg(test)]
    pub fn new_internal(target: Uuid, token_id: Uuid) -> Self {
        DestroyApiTokenEvent {
            ident: Identity::from_internal(),
            target,
            token_id,
        }
    }
}

impl<'a> IdmServerProxyWriteTransaction<'a> {
    pub fn service_account_generate_api_token(
        &mut self,
        gte: &GenerateApiTokenEvent,
        ct: Duration,
    ) -> Result<String, OperationError> {
        let service_account = self
            .qs_write
            .internal_search_uuid(gte.target)
            .and_then(|account_entry| ServiceAccount::try_from_entry_rw(&account_entry))
            .map_err(|e| {
                admin_error!(?e, "Failed to search service account");
                e
            })?;

        let session_id = Uuid::new_v4();
        let issued_at = time::OffsetDateTime::unix_epoch() + ct;

        // Normalise to UTC in case it was provided as something else.
        let expiry = gte.expiry.map(|odt| odt.to_offset(time::UtcOffset::UTC));

        let purpose = if gte.read_write {
            ApiTokenPurpose::ReadWrite
        } else {
            ApiTokenPurpose::ReadOnly
        };

        // create a new session
        let session = Value::Session(
            session_id,
            Session {
                label: gte.label.clone(),
                expiry,
                // Need the other inner bits?
                // for the gracewindow.
                issued_at,
                // Who actually created this?
                issued_by: gte.ident.get_event_origin_id(),
                // random id
                cred_id: Uuid::new_v4(),
                // What is the access scope of this session? This is
                // for auditing purposes.
                scope: (&purpose).into(),
            },
        );

        // create the session token (not yet signed)
        let token = Jws::new(ApiToken {
            account_id: service_account.uuid,
            token_id: session_id,
            label: gte.label.clone(),
            expiry: gte.expiry,
            issued_at,
            purpose,
        });

        // modify the account to put the session onto it.
        let modlist = ModifyList::new_list(vec![Modify::Present(
            AttrString::from("api_token_session"),
            session,
        )]);

        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq("uuid", PartialValue::Uuid(gte.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq("uuid", PartialValue::Uuid(gte.target))),
                &modlist,
                // Provide the event to impersonate
                &gte.ident,
            )
            .and_then(|_| {
                // The modify succeeded and was allowed, now sign the token for return.
                token
                    .sign_embed_public_jwk(&service_account.jws_key)
                    .map(|jws_signed| jws_signed.to_string())
                    .map_err(|e| {
                        admin_error!(err = ?e, "Unable to sign api token");
                        OperationError::CryptographyError
                    })
            })
            .map_err(|e| {
                admin_error!("Failed to generate api token {:?}", e);
                e
            })
        // Done!
    }

    pub fn service_account_destroy_api_token(
        &mut self,
        dte: &DestroyApiTokenEvent,
    ) -> Result<(), OperationError> {
        // Delete the attribute with uuid.
        let modlist = ModifyList::new_list(vec![Modify::Removed(
            AttrString::from("api_token_session"),
            PartialValue::Refer(dte.token_id),
        )]);

        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_and!([
                    f_eq("uuid", PartialValue::Uuid(dte.target)),
                    f_eq("api_token_session", PartialValue::Refer(dte.token_id))
                ])),
                // Filter as intended (acp)
                &filter_all!(f_and!([
                    f_eq("uuid", PartialValue::Uuid(dte.target)),
                    f_eq("api_token_session", PartialValue::Refer(dte.token_id))
                ])),
                &modlist,
                // Provide the event to impersonate
                &dte.ident,
            )
            .map_err(|e| {
                admin_error!("Failed to destroy api token {:?}", e);
                e
            })
    }
}

impl<'a> IdmServerProxyReadTransaction<'a> {
    pub fn service_account_list_api_token(
        &mut self,
        lte: &ListApiTokenEvent,
    ) -> Result<Vec<ApiToken>, OperationError> {
        // Make an event from the request
        let srch = match SearchEvent::from_target_uuid_request(
            lte.ident.clone(),
            lte.target,
            &self.qs_read,
        ) {
            Ok(s) => s,
            Err(e) => {
                admin_error!("Failed to begin service account api token list: {:?}", e);
                return Err(e);
            }
        };

        match self.qs_read.search_ext(&srch) {
            Ok(mut entries) => {
                entries
                    .pop()
                    // get the first entry
                    .and_then(|e| {
                        let account_id = e.get_uuid();
                        // From the entry, turn it into the value
                        e.get_ava_as_session_map("api_token_session").map(|smap| {
                            smap.iter()
                                .map(|(u, s)| {
                                    s.scope
                                        .try_into()
                                        .map(|purpose| ApiToken {
                                            account_id,
                                            token_id: *u,
                                            label: s.label.clone(),
                                            expiry: s.expiry,
                                            issued_at: s.issued_at,
                                            purpose,
                                        })
                                        .map_err(|e| {
                                            admin_error!("Invalid api_token {}", u);
                                            e
                                        })
                                })
                                .collect::<Result<Vec<_>, _>>()
                        })
                    })
                    .unwrap_or_else(|| {
                        // No matching entry? Return none.
                        Ok(Vec::new())
                    })
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration;

    use compact_jwt::{Jws, JwsUnverified};
    use kanidm_proto::v1::ApiToken;

    use super::{DestroyApiTokenEvent, GenerateApiTokenEvent};
    use crate::event::CreateEvent;
    use crate::idm::server::IdmServerTransaction;
    use crate::prelude::*;

    const TEST_CURRENT_TIME: u64 = 6000;

    #[idm_test]
    async fn test_idm_service_account_api_token(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let past_grc = Duration::from_secs(TEST_CURRENT_TIME + 1) + GRACE_WINDOW;
        let exp = Duration::from_secs(TEST_CURRENT_TIME + 6000);
        let post_exp = Duration::from_secs(TEST_CURRENT_TIME + 6010);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let testaccount_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            ("class", Value::new_class("object")),
            ("class", Value::new_class("account")),
            ("class", Value::new_class("service_account")),
            ("name", Value::new_iname("test_account_only")),
            ("uuid", Value::Uuid(testaccount_uuid)),
            ("description", Value::new_utf8s("testaccount")),
            ("displayname", Value::new_utf8s("testaccount"))
        );

        let ce = CreateEvent::new_internal(vec![e1]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(cr.is_ok());

        let gte = GenerateApiTokenEvent::new_internal(testaccount_uuid, "TestToken", Some(exp));

        let api_token = idms_prox_write
            .service_account_generate_api_token(&gte, ct)
            .expect("failed to generate new api token");

        trace!(?api_token);

        // Deserialise it.
        let apitoken_unverified =
            JwsUnverified::from_str(&api_token).expect("Failed to parse apitoken");
        let apitoken_inner: Jws<ApiToken> = apitoken_unverified
            .validate_embeded()
            .expect("Embedded jwk not found");
        let apitoken_inner = apitoken_inner.into_inner();

        let ident = idms_prox_write
            .validate_and_parse_token_to_ident(Some(&api_token), ct)
            .expect("Unable to verify api token.");

        assert!(ident.get_uuid() == Some(testaccount_uuid));

        // Woohoo! Okay lets test the other edge cases.

        // Check the expiry
        assert!(
            idms_prox_write
                .validate_and_parse_token_to_ident(Some(&api_token), post_exp)
                .expect_err("Should not succeed")
                == OperationError::SessionExpired
        );

        // Delete session
        let dte =
            DestroyApiTokenEvent::new_internal(apitoken_inner.account_id, apitoken_inner.token_id);
        assert!(idms_prox_write
            .service_account_destroy_api_token(&dte)
            .is_ok());

        // Within gracewindow?
        // This is okay, because we are within the gracewindow.
        let ident = idms_prox_write
            .validate_and_parse_token_to_ident(Some(&api_token), ct)
            .expect("Unable to verify api token.");
        assert!(ident.get_uuid() == Some(testaccount_uuid));

        // Past gracewindow?
        assert!(
            idms_prox_write
                .validate_and_parse_token_to_ident(Some(&api_token), past_grc)
                .expect_err("Should not succeed")
                == OperationError::SessionExpired
        );

        assert!(idms_prox_write.commit().is_ok());
    }
}
