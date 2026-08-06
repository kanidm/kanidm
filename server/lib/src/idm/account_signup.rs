use crate::idm::server::IdmServerProxyWriteTransaction;
use crate::prelude::*;
// use kanidm_proto::scim_v1::client::

pub struct AccountSignupRequestEvent {
    // Who initiated this? By default I think
    // this will be an internal identity?
    pub ident: Identity,
    // username: String,
    // display_name: String,
    // email: String,
}

impl IdmServerProxyWriteTransaction<'_> {
    pub fn account_signup_request(
        &mut self,
        _asre: AccountSignupRequestEvent,
    ) -> Result<(), OperationError> {
        // If the feature is not enabled, error.
        if !self.qs_write.get_feature_account_signup_config().enabled {
            warn!("Attempt to perform account signup while feature is disabled.");
            return Err(OperationError::AS0001FeatureDisabled);
        }

        // Generates a new account signup request entry that needs further processing.

        // It needs a "delete after" tag.

        // Perform the post process on the request.

        todo!();
    }

    // We need a post-process handler for any events on the signup request. In a way this
    // is kind of similar to a plugin but it doesn't have access to send emails via
    // the delayed event queue.

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
    use super::AccountSignupRequestEvent;
    use crate::prelude::*;

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
        };

        let result = write_txn
            .account_signup_request(account_signup_req)
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

        // Since there are no validation rules in place, it should immediately succeed.

        // Validate the person
        // Validate the message in the delayed queue
    }
}
