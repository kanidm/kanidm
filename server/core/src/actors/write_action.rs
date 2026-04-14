use super::QueryServerWriteV1;
use kanidmd_lib::idm::credupdatesession::CredentialUpdateAnonymousAccountRequest;
use kanidmd_lib::prelude::{duration_from_epoch_now, OperationError};
use uuid::Uuid;

impl QueryServerWriteV1 {
    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub(crate) async fn action_credential_reset_email(
        &self,
        email: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let event = CredentialUpdateAnonymousAccountRequest {
            email,
            max_ttl: None,
        };

        let result = idms_prox_write
            .credential_update_anonymous_account_request(event, ct)
            .and_then(move |tok| idms_prox_write.commit().map(|_| tok))
            .inspect_err(|err| {
                error!(
                    ?err,
                    "Failed to process credential_update_anonymous_account_request"
                );
            });

        // Return the result.
        result
    }
}
