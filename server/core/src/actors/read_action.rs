use super::QueryServerReadV1;
use kanidmd_lib::{
    idm::account_signup::{AccountSignupDisplay, AccountSignupDisplayEvent},
    prelude::OperationError,
};
use uuid::Uuid;

impl QueryServerReadV1 {
    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub(crate) async fn action_account_signup_display(
        &self,
        intent_id: String,
        eventid: Uuid,
    ) -> Result<AccountSignupDisplay, OperationError> {
        let mut idms_prox_read = self.idms.proxy_read().await?;

        let event = AccountSignupDisplayEvent::new(intent_id);

        idms_prox_read
            .account_signup_display(event)
            .inspect_err(|err| {
                error!(?err, "Failed to process action_account_signup");
            })
    }
}
