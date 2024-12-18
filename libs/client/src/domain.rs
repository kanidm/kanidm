use crate::{ClientError, KanidmClient};
use kanidm_proto::constants::ATTR_DOMAIN_ALLOW_EASTER_EGGS;
use kanidm_proto::internal::ImageValue;
use reqwest::multipart;

impl KanidmClient {
    /// Clear the current domain logo/image
    pub async fn idm_domain_delete_image(&self) -> Result<(), ClientError> {
        self.perform_delete_request("/v1/domain/_image").await
    }

    pub async fn idm_set_domain_allow_easter_eggs(&self, enable: bool) -> Result<(), ClientError> {
        self.perform_put_request(
            &format!("{}{}", "/v1/domain/_attr/", ATTR_DOMAIN_ALLOW_EASTER_EGGS),
            vec![enable.to_string()],
        )
        .await
    }

    /// Add or update the domain logo/image
    pub async fn idm_domain_update_image(&self, image: ImageValue) -> Result<(), ClientError> {
        let file_content_type = image.filetype.as_content_type_str();

        let file_data = match multipart::Part::bytes(image.contents.clone())
            .file_name(image.filename)
            .mime_str(file_content_type)
        {
            Ok(part) => part,
            Err(err) => {
                error!(
                    "Failed to generate multipart body from image data: {:}",
                    err
                );
                return Err(ClientError::SystemError);
            }
        };

        let form = multipart::Form::new().part("image", file_data);

        // send it
        let response = self
            .client
            .post(self.make_url("/v1/domain/_image"))
            .multipart(form);

        let response = {
            let tguard = self.bearer_token.read().await;
            if let Some(token) = &(*tguard) {
                response.bearer_auth(token)
            } else {
                response
            }
        };
        let response = response
            .send()
            .await
            .map_err(|err| self.handle_response_error(err))?;
        self.expect_version(&response).await;

        let opid = self.get_kopid_from_response(&response);

        match response.status() {
            reqwest::StatusCode::OK => {}
            unexpect => {
                return Err(ClientError::Http(
                    unexpect,
                    response.json().await.ok(),
                    opid,
                ))
            }
        }
        response
            .json()
            .await
            .map_err(|e| ClientError::JsonDecode(e, opid))
    }
}
