use super::QueryServerWriteV1;
use kanidmd_lib::identity::Identity;

impl QueryServerWriteV1 {
    #[instrument(level = "debug", skip_all)]
    async fn action_credential_reset_email(
        &self,
        email: String,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;


        // Use the internal AccountRequest role to authenticate the credential reset.
        let ident = Identity::account_request();

        let event = InitCredentialUpdateIntentSendEvent {
            ident,
            target,
            max_ttl,
            email,
        };

        idms_prox_write
            .init_credential_update_intent_send(event, ct)
            .and_then(|tok| idms_prox_write.commit().map(|_| tok))
            .inspect_err(|err| {
                error!(?err, "Failed to process init_credential_update_intent_send",);
            })


    }
}
