use super::ldap::{LdapBoundToken, LdapSession};
use crate::idm::account::Account;
use crate::idm::event::LdapApplicationAuthEvent;
use crate::idm::server::{IdmServerAuthTransaction, IdmServerTransaction};
use crate::prelude::*;

pub(crate) struct Application {
    pub uuid: Uuid,
    pub name: String,
    pub linked_group: Option<Uuid>,
}

impl Application {
    pub(crate) fn try_from_entry_ro(
        value: &Entry<EntrySealed, EntryCommitted>,
        _qs: &mut QueryServerReadTransaction,
    ) -> Result<Self, OperationError> {
        if !value.attribute_equality(Attribute::Class, &EntryClass::Application.to_partialvalue()) {
            return Err(OperationError::InvalidAccountState(
                "Missing class: application".to_string(),
            ));
        }

        let uuid = value.get_uuid();

        let name = value
            .get_ava_single_iname(Attribute::Name)
            .map(|s| s.to_string())
            .ok_or_else(|| {
                OperationError::InvalidAccountState(format!(
                    "Missing attribute: {}",
                    Attribute::Name
                ))
            })?;

        let linked_group: Option<Uuid> = value.get_ava_single_refer(Attribute::LinkedGroup);

        Ok(Application {
            name,
            uuid,
            linked_group,
        })
    }
}

impl<'a> IdmServerAuthTransaction<'a> {
    pub async fn application_auth_ldap(
        &mut self,
        lae: &LdapApplicationAuthEvent,
    ) -> Result<Option<LdapBoundToken>, OperationError> {
        let usr_entry = self.get_qs_txn().internal_search_uuid(lae.target)?;

        let account: Account =
            Account::try_from_entry_ro(&usr_entry, self.get_qs_txn()).map_err(|e| {
                admin_error!("Failed to search account {:?}", e);
                e
            })?;

        if account.is_anonymous() {
            return Err(OperationError::InvalidUuid);
        }

        let application: Application = self
            .get_qs_txn()
            .internal_search(filter!(f_and!([
                f_eq(Attribute::Class, EntryClass::Application.into()),
                f_eq(
                    Attribute::Name,
                    PartialValue::new_iname(lae.application.as_str())
                )
            ])))
            .and_then(|mut vs| match vs.pop() {
                Some(entry) if vs.is_empty() => Ok(entry),
                _ => {
                    admin_error!(
                        ?lae.application,
                        "entries was empty, or matched multiple results for name"
                    );
                    Err(OperationError::NotAuthenticated)
                }
            })
            .and_then(|entry| Application::try_from_entry_ro(&entry, self.get_qs_txn()))
            .map_err(|e| {
                admin_error!("Failed to search application {:?}", e);
                e
            })?;

        // Check linked group membership
        let linked_group_uuid = match application.linked_group {
            Some(u) => u,
            None => {
                admin_warn!(
                    "Application {:?} does not have a linked group.",
                    application.name
                );
                return Ok(None);
            }
        };

        let is_memberof = usr_entry
            .get_ava_refer(Attribute::MemberOf)
            .map(|member_of_set| member_of_set.contains(&linked_group_uuid))
            .unwrap_or_default();

        if !is_memberof {
            trace!(
                "User {:?} not member of application {:?} linked group {:?}",
                account.uuid,
                application.uuid,
                linked_group_uuid
            );
            return Ok(None);
        }

        match account.verify_application_password(&application, lae.cleartext.as_str())? {
            Some(_) => {
                let session_id = Uuid::new_v4();
                security_info!(
                    "Starting session {} for {} {}",
                    session_id,
                    account.spn,
                    account.uuid
                );

                Ok(Some(LdapBoundToken {
                    spn: account.spn,
                    session_id,
                    effective_session: LdapSession::UnixBind(account.uuid),
                }))
            }
            None => {
                security_info!("Account does not have a configured application password.");
                Ok(None)
            }
        }
    }
}

#[derive(Debug)]
pub struct GenerateApplicationPasswordEvent {
    pub ident: Identity,
    pub target: Uuid,
    pub application: Uuid,
    pub label: String,
}

impl GenerateApplicationPasswordEvent {
    pub fn from_parts(
        ident: Identity,
        target: Uuid,
        application: Uuid,
        label: String,
    ) -> Result<Self, OperationError> {
        Ok(GenerateApplicationPasswordEvent {
            ident,
            target,
            application,
            label,
        })
    }

    pub fn new_internal(target: Uuid, application: Uuid, label: String) -> Self {
        GenerateApplicationPasswordEvent {
            ident: Identity::from_internal(),
            target,
            application,
            label,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::event::CreateEvent;
    use crate::idm::application::Application;
    use crate::idm::server::IdmServerTransaction;
    use crate::idm::serviceaccount::{DestroyApiTokenEvent, GenerateApiTokenEvent};
    use crate::prelude::*;
    use compact_jwt::{dangernoverify::JwsDangerReleaseWithoutVerify, JwsVerifier};
    use kanidm_proto::internal::ApiToken as ProtoApiToken;
    use std::time::Duration;

    const TEST_CURRENT_TIME: u64 = 6000;

    // Tests that only the correct combinations of [Account, Person, Application and
    // ServiceAccount] classes are allowed.
    #[idm_test]
    async fn test_idm_application_excludes(idms: &IdmServer, _idms_delayed: &mut IdmServerDelayed) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        // ServiceAccount, Application and Person not allowed together
        let test_grp_name = "testgroup1";
        let test_grp_uuid = Uuid::new_v4();
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname(test_grp_name)),
            (Attribute::Uuid, Value::Uuid(test_grp_uuid))
        );
        let test_entry_uuid = Uuid::new_v4();
        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Class, EntryClass::Application.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("test_app_name")),
            (Attribute::Uuid, Value::Uuid(test_entry_uuid)),
            (Attribute::Description, Value::new_utf8s("test_app_desc")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_app_dispname")
            ),
            (Attribute::LinkedGroup, Value::Refer(test_grp_uuid))
        );
        let ce = CreateEvent::new_internal(vec![e1, e2]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(!cr.is_ok());

        // Application and Person not allowed together
        let test_grp_name = "testgroup1";
        let test_grp_uuid = Uuid::new_v4();
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname(test_grp_name)),
            (Attribute::Uuid, Value::Uuid(test_grp_uuid))
        );
        let test_entry_uuid = Uuid::new_v4();
        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Application.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Name, Value::new_iname("test_app_name")),
            (Attribute::Uuid, Value::Uuid(test_entry_uuid)),
            (Attribute::Description, Value::new_utf8s("test_app_desc")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_app_dispname")
            ),
            (Attribute::LinkedGroup, Value::Refer(test_grp_uuid))
        );
        let ce = CreateEvent::new_internal(vec![e1, e2]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(!cr.is_ok());

        // Supplements not satisfied, Application supplements ServiceAccount
        let test_grp_name = "testgroup1";
        let test_grp_uuid = Uuid::new_v4();
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname(test_grp_name)),
            (Attribute::Uuid, Value::Uuid(test_grp_uuid))
        );
        let test_entry_uuid = Uuid::new_v4();
        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::Application.to_value()),
            (Attribute::Name, Value::new_iname("test_app_name")),
            (Attribute::Uuid, Value::Uuid(test_entry_uuid)),
            (Attribute::Description, Value::new_utf8s("test_app_desc")),
            (Attribute::LinkedGroup, Value::Refer(test_grp_uuid))
        );
        let ce = CreateEvent::new_internal(vec![e1, e2]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(!cr.is_ok());

        // Supplements not satisfied, Application supplements ServiceAccount
        let test_grp_name = "testgroup1";
        let test_grp_uuid = Uuid::new_v4();
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname(test_grp_name)),
            (Attribute::Uuid, Value::Uuid(test_grp_uuid))
        );
        let test_entry_uuid = Uuid::new_v4();
        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Application.to_value()),
            (Attribute::Name, Value::new_iname("test_app_name")),
            (Attribute::Uuid, Value::Uuid(test_entry_uuid)),
            (Attribute::Description, Value::new_utf8s("test_app_desc")),
            (Attribute::LinkedGroup, Value::Refer(test_grp_uuid))
        );
        let ce = CreateEvent::new_internal(vec![e1, e2]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(!cr.is_ok());

        // Supplements satisfied, Application supplements ServiceAccount
        let test_grp_name = "testgroup1";
        let test_grp_uuid = Uuid::new_v4();
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname(test_grp_name)),
            (Attribute::Uuid, Value::Uuid(test_grp_uuid))
        );
        let test_entry_uuid = Uuid::new_v4();
        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Application.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Name, Value::new_iname("test_app_name")),
            (Attribute::Uuid, Value::Uuid(test_entry_uuid)),
            (Attribute::Description, Value::new_utf8s("test_app_desc")),
            (Attribute::LinkedGroup, Value::Refer(test_grp_uuid))
        );
        let ce = CreateEvent::new_internal(vec![e1, e2]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(cr.is_ok());
    }

    // Tests it is not possible to create an applicatin without the linked group attribute
    #[idm_test]
    async fn test_idm_application_no_linked_group(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let test_entry_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Class, EntryClass::Application.to_value()),
            (Attribute::Name, Value::new_iname("test_app_name")),
            (Attribute::Uuid, Value::Uuid(test_entry_uuid)),
            (Attribute::Description, Value::new_utf8s("test_app_desc")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_app_dispname")
            )
        );

        let ce = CreateEvent::new_internal(vec![e1]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(!cr.is_ok());
    }

    // Tests creating an applicatin with a real linked group attribute
    #[idm_test]
    async fn test_idm_application_linked_group(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let test_entry_name = "test_app_name";
        let test_entry_uuid = Uuid::new_v4();
        let test_grp_name = "testgroup1";
        let test_grp_uuid = Uuid::new_v4();

        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname(test_grp_name)),
            (Attribute::Uuid, Value::Uuid(test_grp_uuid))
        );
        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Class, EntryClass::Application.to_value()),
            (Attribute::Name, Value::new_iname(test_entry_name)),
            (Attribute::Uuid, Value::Uuid(test_entry_uuid)),
            (Attribute::Description, Value::new_utf8s("test_app_desc")),
            (
                Attribute::DisplayName,
                Value::new_utf8s("test_app_dispname")
            ),
            (Attribute::LinkedGroup, Value::Refer(test_grp_uuid))
        );

        let ce = CreateEvent::new_internal(vec![e1, e2]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(cr.is_ok());

        let cr = idms_prox_write.qs_write.commit();
        assert!(cr.is_ok());

        let mut idms_prox_read = idms.proxy_read().await;
        let app = idms_prox_read
            .qs_read
            .internal_search_uuid(test_entry_uuid)
            .and_then(|entry| Application::try_from_entry_ro(&entry, &mut idms_prox_read.qs_read))
            .map_err(|e| {
                trace!("Error: {:?}", e);
                e
            });
        assert!(app.is_ok());

        let app = app.unwrap();
        assert!(app.name == "test_app_name");
        assert!(app.uuid == test_entry_uuid);
        assert!(app.linked_group.is_some_and(|u| u == test_grp_uuid));
    }

    // Test apitoken for application entries
    #[idm_test]
    async fn test_idm_application_api_token(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        let ct = Duration::from_secs(TEST_CURRENT_TIME);
        let past_grc = Duration::from_secs(TEST_CURRENT_TIME + 1) + GRACE_WINDOW;
        let exp = Duration::from_secs(TEST_CURRENT_TIME + 6000);
        let post_exp = Duration::from_secs(TEST_CURRENT_TIME + 6010);
        let mut idms_prox_write = idms.proxy_write(ct).await;

        let test_entry_uuid = Uuid::new_v4();
        let test_group_uuid = Uuid::new_v4();

        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Group.to_value()),
            (Attribute::Name, Value::new_iname("test_group")),
            (Attribute::Uuid, Value::Uuid(test_group_uuid))
        );

        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::ServiceAccount.to_value()),
            (Attribute::Class, EntryClass::Application.to_value()),
            (Attribute::Name, Value::new_iname("test_app_name")),
            (Attribute::Uuid, Value::Uuid(test_entry_uuid)),
            (Attribute::Description, Value::new_utf8s("test_app_desc")),
            (Attribute::LinkedGroup, Value::Refer(test_group_uuid))
        );

        let ce = CreateEvent::new_internal(vec![e1, e2]);
        let cr = idms_prox_write.qs_write.create(&ce);
        assert!(cr.is_ok());

        let gte = GenerateApiTokenEvent::new_internal(test_entry_uuid, "TestToken", Some(exp));

        let api_token = idms_prox_write
            .service_account_generate_api_token(&gte, ct)
            .expect("failed to generate new api token");

        trace!(?api_token);

        // Deserialise it.
        let jws_verifier = JwsDangerReleaseWithoutVerify::default();

        let apitoken_inner = jws_verifier
            .verify(&api_token)
            .unwrap()
            .from_json::<ProtoApiToken>()
            .unwrap();

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(api_token.clone().into(), ct)
            .expect("Unable to verify api token.");

        assert!(ident.get_uuid() == Some(test_entry_uuid));

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
        assert!(ident.get_uuid() == Some(test_entry_uuid));

        // Past gracewindow?
        assert!(
            idms_prox_write
                .validate_client_auth_info_to_ident(api_token.clone().into(), past_grc)
                .expect_err("Should not succeed")
                == OperationError::SessionExpired
        );

        assert!(idms_prox_write.commit().is_ok());
    }
}
