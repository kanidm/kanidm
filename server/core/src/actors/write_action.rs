use super::QueryServerWriteV1;
use kanidmd_lib::{
    idm::{
        account_signup::AccountSignupRequestEvent,
        credupdatesession::CredentialUpdateAccountRecovery,
    },
    prelude::{duration_from_epoch_now, OperationError},
};
use uuid::Uuid;

impl QueryServerWriteV1 {
    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub(crate) async fn action_account_recovery(
        &self,
        email: String,
        eventid: Uuid,
    ) -> Result<Uuid, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let event = CredentialUpdateAccountRecovery {
            email,
            max_ttl: None,
        };

        idms_prox_write
            .credential_update_account_recovery(event, ct)
            .and_then(|tok| idms_prox_write.commit().map(|_| tok))
            .inspect_err(|err| {
                error!(?err, "Failed to process credential_update_account_recovery");
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub(crate) async fn action_account_signup(
        &self,
        username: String,
        display_name: String,
        email: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let event = AccountSignupRequestEvent::new(username, display_name, email);

        idms_prox_write
            .account_signup_request(event)
            .and_then(|()| idms_prox_write.commit())
            .inspect_err(|err| {
                error!(?err, "Failed to process account_signup_request");
            })
    }
}
