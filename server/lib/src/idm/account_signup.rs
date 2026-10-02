use crate::{
    idm::server::IdmServerProxyWriteTransaction, prelude::*, utils::readable_password_from_random,
};
use crypto_glue::{s256::Sha256, traits::Digest};
use kanidm_proto::v1::OutboundMessage;

pub struct AccountSignupRequestEvent {
    // Who initiated this? By default I think
    // this will be an internal identity?
    pub ident: Identity,
    username: String,
    display_name: String,
    email: String,
}

pub struct AccountSignupVerifyEvent {
    pub ident: Identity,
    intent_id: String,
}

impl IdmServerProxyWriteTransaction<'_> {
    pub fn account_signup_request(
        &mut self,
        asre: AccountSignupRequestEvent,
    ) -> Result<(), OperationError> {
        // If the feature is not enabled, error.
        if !self.qs_write.get_feature_account_signup_config().enabled {
            warn!("Attempt to perform account signup while feature is disabled.");
            return Err(OperationError::AS0001FeatureDisabled);
        }

        // Generates a new account signup request entry that needs further processing.
        // It needs a "delete after" tag.

        let AccountSignupRequestEvent {
            ident,
            username,
            display_name,
            email,
        } = asre;

        let curtime_odt = self.qs_write.get_curtime_odt();
        let delete_after_odt = curtime_odt + DEFAULT_ACCOUNT_SIGNUP_RETENTION;

        let intent_id = readable_password_from_random();
        // We treat this like pkce - we store a sha256, and the requestor has to present the plaintext
        // code to accept the request.
        let intent_sha256 = Sha256::digest(intent_id.as_bytes());

        let account_signup_entry = EntryInitNew::from_iter([
            (
                Attribute::Class,
                ValueSetIutf8N::new(EntryClass::AccountSignupRequest.into()) as ValueSet,
            ),
            (Attribute::Name, ValueSetIname::new(&username) as ValueSet),
            (
                Attribute::DisplayName,
                ValueSetUtf8::new(display_name) as ValueSet,
            ),
            (
                Attribute::Mail,
                ValueSetEmailAddress::new(email.clone()) as ValueSet,
            ),
            (
                Attribute::DeleteAfter,
                ValueSetDateTime::new(delete_after_odt),
            ),
            (
                Attribute::S256,
                ValueSetSha256::new(intent_sha256) as ValueSet,
            ),
        ]);

        // Create
        let ce = CreateEvent {
            ident,
            entries: vec![account_signup_entry],
            return_created_uuids: false,
        };

        self.qs_write.create(&ce)?;

        let message = OutboundMessage::AccountSignupRequestV1 {
            username,
            intent_id,
            expiry_time: delete_after_odt,
        };

        let mail_ident = Identity::message_queue();

        let _message_id = self.qs_write.queue_message(&mail_ident, message, email)?;

        Ok(())
    }

    // We need a post-process handler for any events on the signup request. In a way this
    // is kind of similar to a plugin but it doesn't have access to send emails via
    // the delayed event queue.

    pub fn account_signup_request_verify(
        &mut self,
        asre: AccountSignupVerifyEvent,
    ) -> Result<(), OperationError> {
        // If the feature is not enabled, error.
        if !self.qs_write.get_feature_account_signup_config().enabled {
            warn!("Attempt to perform account signup while feature is disabled.");
            return Err(OperationError::AS0001FeatureDisabled);
        }

        let AccountSignupVerifyEvent { ident, intent_id } = asre;

        let intent_sha256 = Sha256::digest(intent_id.as_bytes());

        let filter = filter_all!(f_and(vec![
            f_eq(Attribute::Class, EntryClass::AccountSignupRequest.into()),
            f_eq(Attribute::S256, intent_sha256.into())
        ]));

        let signup_entry = self.qs_write.ident_search_single(&ident, filter)?;

        debug!(?signup_entry);

        // Delete the signup request.
        self.qs_write
            .ident_delete_uuid(&ident, signup_entry.get_uuid())?;

        // Create the account, with the values from the request.
        let attr_iter = signup_entry.get_ava_iter().filter_map(|(a, vs)| match a {
            Attribute::Name | Attribute::DisplayName | Attribute::Mail => {
                Some((a.clone(), vs.clone()))
            }
            _ => None,
        });

        let account_entry = EntryInitNew::from_iter(
            std::iter::once((
                Attribute::Class,
                ValueSetIutf8::from_iter([
                    EntryClass::Object.into(),
                    EntryClass::Account.into(),
                    EntryClass::Person.into(),
                ]) as ValueSet,
            ))
            .chain(attr_iter),
        );

        // Create
        let ce = CreateEvent {
            ident,
            entries: vec![account_entry],
            return_created_uuids: false,
        };

        self.qs_write.create(&ce)?;

        // Initiate a credential update.

        Ok(())
    }

    /*
    fn account_signup_validate_request_state(
        &mut self,

    ) -> Result<(), OperationError> {
        // This processes the request and determines if it has passed the needed steps and should
        // be allowed to continue to a creation.
    }
    */
}

#[cfg(test)]
mod tests {
    use super::{AccountSignupRequestEvent, AccountSignupVerifyEvent};
    use crate::prelude::*;
    use kanidm_proto::v1::OutboundMessage;

    const TESTPERSON_NAME: &str = "testperson";
    const TESTPERSON_DISPLAY_NAME: &str = "Test Personington";
    const TESTPERSON_EMAIL: &str = "testperson@example.com";

    #[idm_test]
    async fn test_account_signup_request_feature_disable(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // If the feature is disabled, the request implicitly fails.
        let ct = duration_from_epoch_now();
        let mut write_txn = idms.proxy_write(ct).await.unwrap();

        let account_signup_req = AccountSignupRequestEvent {
            ident: Identity::account_request(),
            username: TESTPERSON_NAME.into(),
            display_name: TESTPERSON_DISPLAY_NAME.into(),
            email: TESTPERSON_EMAIL.into(),
        };

        let result = write_txn
            .account_signup_request(account_signup_req)
            .unwrap_err();

        assert_eq!(result, OperationError::AS0001FeatureDisabled);

        // Even though we don't have a real intent id here, the feature
        // check always denies first.
        let account_signup_verify = AccountSignupVerifyEvent {
            ident: Identity::account_request(),
            intent_id: String::default(),
        };

        let result = write_txn
            .account_signup_request_verify(account_signup_verify)
            .unwrap_err();

        assert_eq!(result, OperationError::AS0001FeatureDisabled);
    }

    #[idm_test]
    async fn test_account_signup_request_basic(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // Enable the feature.
        let ct = duration_from_epoch_now();
        let mut write_txn = idms.proxy_write(ct).await.unwrap();

        write_txn
            .qs_write
            .internal_batch_modify(
                [(
                    UUID_ACCOUNT_SIGNUP_FEATURE,
                    ModifyList::from_iter([(Attribute::Enabled, Some(vs_bool!(true) as ValueSet))]),
                )]
                .into_iter(),
            )
            .unwrap();

        write_txn.qs_write.reload().unwrap();

        // Create a new request.
        let account_signup_req = AccountSignupRequestEvent {
            ident: Identity::account_request(),
            username: TESTPERSON_NAME.into(),
            display_name: TESTPERSON_DISPLAY_NAME.into(),
            email: TESTPERSON_EMAIL.into(),
        };

        write_txn
            .account_signup_request(account_signup_req)
            .unwrap();

        // Since there are no validation rules in place, it should immediately succeed.

        // Validate the person

        // TODO: Validate the message in the delayed queue
        let idm_admin_identity = write_txn
            .qs_write
            .impersonate_uuid_as_readwrite_identity(UUID_IDM_ADMIN)
            .expect("Failed to retrieve identity");

        let filter = filter!(f_and(vec![
            f_eq(Attribute::Class, EntryClass::OutboundMessage.into()),
            f_eq(
                Attribute::MailDestination,
                PartialValue::EmailAddress(TESTPERSON_EMAIL.into())
            )
        ]));

        let mut entries = write_txn
            .qs_write
            .impersonate_search(filter.clone(), filter, &idm_admin_identity)
            .expect("Unable to search message queue");

        assert_eq!(entries.len(), 1);
        let message_entry = entries.pop().unwrap();

        let message = message_entry
            .get_ava_set(Attribute::MessageTemplate)
            .and_then(|vs| vs.as_message())
            .unwrap();

        let intent_id = match message {
            OutboundMessage::AccountSignupRequestV1 {
                username,
                intent_id,
                ..
            } => {
                assert_eq!(username, TESTPERSON_NAME);
                intent_id.clone()
            }
            _ => panic!("Wrong message type!"),
        };

        let account_signup_verify = AccountSignupVerifyEvent {
            ident: Identity::account_request(),
            intent_id,
        };

        let _result = write_txn
            .account_signup_request_verify(account_signup_verify)
            .expect("Unable to process account signup verification");

        // Now use the intent_id to complete the signup.
        assert!(write_txn.commit().is_ok());
    }
}
