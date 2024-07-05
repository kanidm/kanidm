use std::collections::BTreeMap;
use std::time::Duration;

use compact_jwt::{Jws, JwsCompact, JwsEs256Signer, JwsSigner};
use kanidm_proto::internal::ApiToken as ProtoApiToken;
use time::OffsetDateTime;

use crate::credential::Credential;
use crate::event::SearchEvent;
use crate::idm::account::Account;
use crate::idm::event::GeneratePasswordEvent;
use crate::idm::server::{IdmServerProxyReadTransaction, IdmServerProxyWriteTransaction};
use crate::prelude::*;
use crate::utils::password_from_random;
use crate::value::ApiToken;

macro_rules! try_from_entry {
    ($value:expr) => {{
        // Check the classes
        if !$value.attribute_equality(Attribute::Class, &EntryClass::ServiceAccount.into()) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: service account".to_string(),
            ));
        }

        let spn = $value.get_ava_single_proto_string(Attribute::Spn).ok_or(
            OperationError::InvalidAccountState(format!("Missing attribute: {}", Attribute::Spn)),
        )?;

        let jws_key = $value
            .get_ava_single_jws_key_es256(Attribute::JwsEs256PrivateKey)
            .cloned()
            .map(|jws_key| {
                jws_key
                    .set_sign_option_embed_jwk(true)
                    .set_sign_option_legacy_kid(true)
            });

        let api_tokens = $value
            .get_ava_as_apitoken_map(Attribute::ApiTokenSession)
            .cloned()
            .unwrap_or_default();

        let valid_from = $value.get_ava_single_datetime(Attribute::AccountValidFrom);

        let expire = $value.get_ava_single_datetime(Attribute::AccountExpire);

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

    pub api_tokens: BTreeMap<Uuid, ApiToken>,

    pub jws_key: Option<JwsEs256Signer>,
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
        apit: &ProtoApiToken,
        entry: &Entry<EntrySealed, EntryCommitted>,
    ) -> bool {
        let within_valid_window = Account::check_within_valid_time(
            ct,
            entry
                .get_ava_single_datetime(Attribute::AccountValidFrom)
                .as_ref(),
            entry
                .get_ava_single_datetime(Attribute::AccountExpire)
                .as_ref(),
        );

        if !within_valid_window {
            security_info!("Account has expired or is not yet valid, not allowing to proceed");
            return false;
        }

        // Get the sessions.
        let session_present = entry
            .get_ava_as_apitoken_map(Attribute::ApiTokenSession)
            .map(|session_map| session_map.get(&apit.token_id).is_some())
            .unwrap_or(false);

        if session_present {
            security_info!("A valid session value exists for this token");
            true
        } else {
            let grace = apit.issued_at + GRACE_WINDOW;
            let current = time::OffsetDateTime::UNIX_EPOCH + ct;
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
            expiry: expiry.map(|ct| time::OffsetDateTime::UNIX_EPOCH + ct),
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
    ) -> Result<JwsCompact, OperationError> {
        let service_account = self
            .qs_write
            .internal_search_uuid(gte.target)
            .and_then(|account_entry| ServiceAccount::try_from_entry_rw(&account_entry))
            .map_err(|e| {
                admin_error!(?e, "Failed to search service account");
                e
            })?;

        let session_id = Uuid::new_v4();
        let issued_at = time::OffsetDateTime::UNIX_EPOCH + ct;

        // Normalise to UTC in case it was provided as something else.
        let expiry = gte.expiry.map(|odt| odt.to_offset(time::UtcOffset::UTC));

        let scope = if gte.read_write {
            ApiTokenScope::ReadWrite
        } else {
            ApiTokenScope::ReadOnly
        };
        let purpose = scope.try_into()?;

        // create a new session
        let session = Value::ApiToken(
            session_id,
            ApiToken {
                label: gte.label.clone(),
                expiry,
                // Need the other inner bits?
                // for the gracewindow.
                issued_at,
                // Who actually created this?
                issued_by: gte.ident.get_event_origin_id(),
                // What is the access scope of this session? This is
                // for auditing purposes.
                scope,
            },
        );

        // create the session token (not yet signed)
        let proto_api_token = ProtoApiToken {
            account_id: service_account.uuid,
            token_id: session_id,
            label: gte.label.clone(),
            expiry: gte.expiry,
            issued_at,
            purpose,
        };

        let token = Jws::into_json(&proto_api_token).map_err(|err| {
            error!(?err, "Unable to serialise JWS");
            OperationError::SerdeJsonError
        })?;

        // modify the account to put the session onto it.
        let modlist = ModifyList::new_list(vec![Modify::Present(
            Attribute::ApiTokenSession.into(),
            session,
        )]);

        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(gte.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(gte.target))),
                &modlist,
                // Provide the event to impersonate
                &gte.ident,
            )
            .map_err(|err| {
                error!(?err, "Failed to generate api token");
                err
            })?;

        if self.qs_write.get_domain_version() < DOMAIN_LEVEL_6 {
            service_account
                .jws_key
                .as_ref()
                .ok_or_else(|| {
                    admin_error!("Unable to sign sync token, no sync keys available");
                    OperationError::CryptographyError
                })
                .and_then(|jws_key| {
                    jws_key.sign(&token).map_err(|err| {
                        admin_error!(?err, "Unable to sign sync token");
                        OperationError::CryptographyError
                    })
                })
        } else {
            self.qs_write
                .get_domain_key_object_handle()?
                .jws_es256_sign(&token, ct)
        }
    }

    pub fn service_account_destroy_api_token(
        &mut self,
        dte: &DestroyApiTokenEvent,
    ) -> Result<(), OperationError> {
        // Delete the attribute with uuid.
        let modlist = ModifyList::new_list(vec![Modify::Removed(
            Attribute::ApiTokenSession.into(),
            PartialValue::Refer(dte.token_id),
        )]);

        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_and!([
                    f_eq(Attribute::Uuid, PartialValue::Uuid(dte.target)),
                    f_eq(
                        Attribute::ApiTokenSession,
                        PartialValue::Refer(dte.token_id)
                    )
                ])),
                // Filter as intended (acp)
                &filter_all!(f_and!([
                    f_eq(Attribute::Uuid, PartialValue::Uuid(dte.target)),
                    f_eq(
                        Attribute::ApiTokenSession,
                        PartialValue::Refer(dte.token_id)
                    )
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

    pub fn generate_service_account_password(
        &mut self,
        gpe: &GeneratePasswordEvent,
    ) -> Result<String, OperationError> {
        // Generate a new random, long pw.
        // Because this is generated, we can bypass policy checks!
        let cleartext = password_from_random();
        let ncred = Credential::new_generatedpassword_only(self.crypto_policy(), &cleartext)
            .map_err(|e| {
                admin_error!("Unable to generate password mod {:?}", e);
                e
            })?;
        let vcred = Value::new_credential("primary", ncred);
        // We need to remove other credentials too.
        let modlist = ModifyList::new_list(vec![
            m_purge(Attribute::PassKeys),
            m_purge(Attribute::PrimaryCredential),
            Modify::Present(Attribute::PrimaryCredential.into(), vcred),
        ]);

        trace!(?modlist, "processing change");
        // given the new credential generate a modify
        // We use impersonate here to get the event from ae
        self.qs_write
            .impersonate_modify(
                // Filter as executed
                &filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(gpe.target))),
                // Filter as intended (acp)
                &filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(gpe.target))),
                &modlist,
                // Provide the event to impersonate
                &gpe.ident,
            )
            .map(|_| cleartext)
            .map_err(|e| {
                admin_error!("Failed to generate account password {:?}", e);
                e
            })
    }
}

impl<'a> IdmServerProxyReadTransaction<'a> {
    pub fn service_account_list_api_token(
        &mut self,
        lte: &ListApiTokenEvent,
    ) -> Result<Vec<ProtoApiToken>, OperationError> {
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
                        e.get_ava_as_apitoken_map(Attribute::ApiTokenSession)
                            .map(|smap| {
                                smap.iter()
                                    .map(|(u, s)| {
                                        s.scope
                                            .try_into()
                                            .map(|purpose| ProtoApiToken {
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
                        Ok(Vec::with_capacity(0))
                    })
            }
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use compact_jwt::traits::JwsVerifiable;
    use compact_jwt::{dangernoverify::JwsDangerReleaseWithoutVerify, JwsVerifier};
    use kanidm_proto::internal::ApiToken;

    use super::{DestroyApiTokenEvent, GenerateApiTokenEvent};
    use crate::idm::server::IdmServerTransaction;
    use crate::prelude::*;
    use crate::server::keys::KeyProvidersTransaction;
    use crate::value::KeyStatus;

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
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname("test_account_only")),
            (Attribute::Uuid, Value::Uuid(testaccount_uuid)),
            (Attribute::Description, Value::new_utf8s("testaccount")),
            (Attribute::DisplayName, Value::new_utf8s("testaccount"))
        );

        idms_prox_write
            .qs_write
            .internal_create(vec![e1])
            .expect("Failed to create service account");

        let gte = GenerateApiTokenEvent::new_internal(testaccount_uuid, "TestToken", Some(exp));

        let api_token = idms_prox_write
            .service_account_generate_api_token(&gte, ct)
            .expect("failed to generate new api token");

        trace!(?api_token);

        // Deserialise it.
        let jws_verifier = JwsDangerReleaseWithoutVerify::default();

        let apitoken_inner = jws_verifier
            .verify(&api_token)
            .unwrap()
            .from_json::<ApiToken>()
            .unwrap();

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(api_token.clone().into(), ct)
            .expect("Unable to verify api token.");

        assert!(ident.get_uuid() == Some(testaccount_uuid));

        // Woohoo! Okay lets test the other edge cases.

        // Check the expiry
        assert!(
            idms_prox_write
                .validate_client_auth_info_to_ident(api_token.clone().into(), post_exp)
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
            .validate_client_auth_info_to_ident(api_token.clone().into(), ct)
            .expect("Unable to verify api token.");
        assert!(ident.get_uuid() == Some(testaccount_uuid));

        // Past gracewindow?
        assert!(
            idms_prox_write
                .validate_client_auth_info_to_ident(api_token.into(), past_grc)
                .expect_err("Should not succeed")
                == OperationError::SessionExpired
        );

        assert!(idms_prox_write.commit().is_ok());
    }

    #[idm_test(domain_level=DOMAIN_LEVEL_5)]
    async fn test_idm_service_account_dl5_dl6_api_token(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let exp = Duration::from_secs(TEST_CURRENT_TIME + 6000);

        let mut idms_prox_write = idms.proxy_write(ct).await;

        assert_eq!(
            idms_prox_write.qs_write.get_domain_version(),
            DOMAIN_LEVEL_5
        );

        let testaccount_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname("test_account_only")),
            (Attribute::Uuid, Value::Uuid(testaccount_uuid)),
            (Attribute::Description, Value::new_utf8s("testaccount")),
            (Attribute::DisplayName, Value::new_utf8s("testaccount"))
        );

        idms_prox_write
            .qs_write
            .internal_create(vec![e1])
            .expect("Failed to create service account");

        let gte = GenerateApiTokenEvent::new_internal(testaccount_uuid, "TestToken", Some(exp));

        let api_token = idms_prox_write
            .service_account_generate_api_token(&gte, ct)
            .expect("failed to generate new api token");

        trace!(?api_token);

        assert!(idms_prox_write.commit().is_ok());

        // Now trigger 5 -> 6
        let mut idms_prox_write = idms.proxy_write(ct).await;
        idms_prox_write
            .qs_write
            .internal_apply_domain_migration(DOMAIN_LEVEL_6)
            .expect("Unable to set domain level to version 6");
        assert!(idms_prox_write.commit().is_ok());

        // Now check our api token still validates.
        let mut idms_prox_write = idms.proxy_write(ct).await;

        // Check a new token is domain key signed.
        let gte = GenerateApiTokenEvent::new_internal(testaccount_uuid, "TestToken", Some(exp));

        let new_api_token = idms_prox_write
            .service_account_generate_api_token(&gte, ct)
            .expect("failed to generate new api token");

        assert_ne!(api_token.kid(), new_api_token.kid());

        // Check that both tokens verify and work.
        let _ident = idms_prox_write
            .validate_client_auth_info_to_ident(api_token.clone().into(), ct)
            .expect("Unable to verify old api token.");

        let _ident = idms_prox_write
            .validate_client_auth_info_to_ident(new_api_token.clone().into(), ct)
            .expect("Unable to verify new api token.");

        // The former key is now on the domain object.
        let key_object = idms_prox_write
            .qs_write
            .get_key_providers()
            .get_key_object(UUID_DOMAIN_INFO)
            .expect("Unable to retrieve key object by uuid");

        // Assert the former key is now in the domain key object, and now is "retained".
        let former_kid = api_token.kid().unwrap().to_string();
        let status = key_object
            .kid_status(&former_kid)
            .expect("Failed to access kid status");
        assert_eq!(status, Some(KeyStatus::Retained));

        assert!(idms_prox_write.commit().is_ok());

        // Now trigger 6 -> 7
        let mut idms_prox_write = idms.proxy_write(ct).await;
        idms_prox_write
            .qs_write
            .internal_apply_domain_migration(DOMAIN_LEVEL_7)
            .expect("Unable to set domain level to version 7");
        assert!(idms_prox_write.commit().is_ok());

        // The key on the service account is removed.
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let service_entry = idms_prox_write
            .qs_write
            .internal_search_uuid(testaccount_uuid)
            .expect("Unable to access service account");

        assert!(!service_entry.attribute_pres(Attribute::JwsEs256PrivateKey));

        assert!(idms_prox_write.commit().is_ok());
    }
}
