use crate::idm::server::IdmServerProxyWriteTransaction;
use crate::prelude::*;
use crate::value::Session;

use compact_jwt::{Jws, JwsSigner};
use std::collections::BTreeMap;
use std::time::Duration;
use time::OffsetDateTime;

use kanidm_proto::v1::ApiToken;

// Need to add KID to es256 der for lookups ✅

// Need to generate the es256 on the account on modifies ✅

// Add migration to generate the es256 on startup at least once. ✅

// Create new valueset type to store sessions w_ labels ✅

// Able to lookup from KID to get service account

// Able to take token -> ident
//   -- check still valid

// revoke

lazy_static! {
    static ref PVCLASS_SERVICE_ACCOUNT: PartialValue = PartialValue::new_class("service_account");
}

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

struct ServiceAccount {
    pub spn: String,
    pub uuid: Uuid,

    pub valid_from: Option<OffsetDateTime>,
    pub expire: Option<OffsetDateTime>,

    pub api_tokens: BTreeMap<Uuid, Session>,

    pub jws_key: JwsSigner,
}

impl ServiceAccount {
    pub(crate) fn try_from_entry_rw(
        value: &Entry<EntrySealed, EntryCommitted>,
        // qs: &mut QueryServerWriteTransaction,
    ) -> Result<Self, OperationError> {
        spanned!("idm::serviceaccount::try_from_entry_rw", {
            // let groups = Group::try_from_account_entry_rw(value, qs)?;
            try_from_entry!(value)
        })
    }
}

pub struct GenerateApiTokenEvent {
    // Who initiated this?
    pub ident: Identity,
    // Who is it targetting?
    pub target: Uuid,
    // The label
    pub label: String,
    // When should it expire?
    pub expiry: Option<time::OffsetDateTime>,
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
        }
    }
}

impl<'a> IdmServerProxyWriteTransaction<'a> {
    pub fn service_account_generate_api_token(
        &self,
        gte: &GenerateApiTokenEvent,
        ct: Duration,
    ) -> Result<String, OperationError> {
        let service_account = self
            .qs_write
            .internal_search_uuid(&gte.target)
            .and_then(|account_entry| ServiceAccount::try_from_entry_rw(&account_entry))
            .map_err(|e| {
                admin_error!(?e, "Failed to search service account");
                e
            })?;

        let session_id = Uuid::new_v4();
        let issued_at = time::OffsetDateTime::unix_epoch() + ct;

        // create a new session
        let session = Value::Session(
            session_id,
            Session {
                label: gte.label.clone(),
                expiry: gte.expiry.clone(),
                // Need the other inner bits?
                // for the gracewindow.
                issued_at,
                // Who actually created this?
                issued_by: gte.ident.get_event_origin_id(),
            },
        );

        // create the session token (not yet signed)
        let token = Jws::new(ApiToken {
            token_id: session_id,
            label: gte.label.clone(),
            expiry: gte.expiry.clone(),
            issued_at,
        });

        // modify the account to put the session onto it.
        let modlist = ModifyList::new_list(vec![Modify::Present(
            AttrString::from("api_token_session"),
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
                    .sign(&service_account.jws_key)
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

    pub fn service_account_destroy_api_token(&self, _uuid: Uuid) -> Result<(), OperationError> {
        // Delete the attribute with uuid.

        todo!();
    }
}

#[cfg(test)]
mod tests {
    use super::GenerateApiTokenEvent;
    use crate::prelude::*;
    use crate::idm::server::IdmServerTransaction;

    use crate::event::CreateEvent;
    use compact_jwt::Jws;
    use std::time::Duration;

    const TEST_CURRENT_TIME: u64 = 6000;

    #[test]
    fn test_idm_service_account_api_token() {
        run_idm_test!(|_qs: &QueryServer,
                       idms: &IdmServer,
                       _idms_delayed: &mut IdmServerDelayed| {

            let ct = Duration::from_secs(TEST_CURRENT_TIME);
            let mut idms_prox_write = idms.proxy_write(ct);

            let testaccount_uuid = Uuid::new_v4();

            let e1 = entry_init!(
                ("class", Value::new_class("object")),
                ("class", Value::new_class("account")),
                ("class", Value::new_class("service_account")),
                ("name", Value::new_iname("test_account_only")),
                ("uuid", Value::new_uuid(testaccount_uuid)),
                ("description", Value::new_utf8s("testaccount")),
                ("displayname", Value::new_utf8s("testaccount"))
            );

            let ce = CreateEvent::new_internal(vec![e1]);
            let cr = idms_prox_write.qs_write.create(&ce);
            assert!(cr.is_ok());

            let gte = GenerateApiTokenEvent::new_internal(testaccount_uuid, "TestToken", None);

            let api_token = idms_prox_write
                .service_account_generate_api_token(&gte, ct)
                .expect("failed to generate new api token");

            trace!("api_token");

            let ident = idms_prox_write
                .validate_and_parse_token_to_ident(Some(&api_token), ct)
                .expect("Unable to verify api token.");
        });
    }
}
