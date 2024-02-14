#[cfg(test)]
mod tests {
    use crate::event::CreateEvent;
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
