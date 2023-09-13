use crate::{ClientError, KanidmClient};
use kanidm_proto::v1::Entry;

impl KanidmClient {
    pub async fn idm_application_list(&self) -> Result<Vec<Entry>, ClientError> {
        self.perform_get_request("/v1/application").await
    }
}
