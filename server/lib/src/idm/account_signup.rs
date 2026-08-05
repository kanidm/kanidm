use crate::idm::server::IdmServerProxyWriteTransaction;
use std::time::Duration;
use crate::prelude::*;

pub struct AccountSignupRequestEvent {
    // Who initiated this? By default I think
    // this will be an internal identity?
    pub ident: Identity,
}

impl IdmServerProxyWriteTransaction<'_> {
    pub fn account_signup_request(
        &mut self,
        asre: AccountSignupRequestEvent,
        ct: Duration,
    ) -> Result<(), OperationError> {

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
    use crate::prelude::*;

    #[idm_test]
    async fn test_account_signup_request_feature_disable(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // If the feature is disabled, the request implicitly fails.
        

    }

    #[idm_test]
    async fn test_account_signup_request_basic(
        idms: &IdmServer,
        _idms_delayed: &mut IdmServerDelayed,
    ) {
        // Enable the feature.

        // Create a new request.

        // Since there are no validation rules in place, it should immediately succeed.

        // Validate the person
        // Validate the message in the delayed queue

    }
}


