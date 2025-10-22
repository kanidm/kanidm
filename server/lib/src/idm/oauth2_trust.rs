use crate::idm::server::IdmServerProxyWriteTransaction;
use crate::prelude::*;
use std::collections::BTreeSet;
use std::fmt;

// TODO: Move to constants once we have a good path here. Will probably need to be part
// of the axum config etc.
// I'm pretty sure this can preserve query strings if we wanted to stash info or flag things?
pub const OAUTH2_CLIENT_AUTHORISATION_RESPONSE_PATH: &str = "/ui/login/oauth2_trust_landing";

#[derive(Clone)]
pub struct OAuth2TrustProvider {
    pub(crate) name: String,
    pub(crate) uuid: Uuid,
    pub(crate) client_id: String,
    pub(crate) client_basic_secret: String,
    /// This is the origin of THIS kanidm server.
    pub(crate) client_redirect_uri: Url,
    pub(crate) request_scopes: BTreeSet<String>,
    pub(crate) authorisation_endpoint: Url,
    pub(crate) token_endpoint: Url,
}

impl fmt::Debug for OAuth2TrustProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuth2TrustProvider")
            .field("provider_id", &self.name)
            .field("provider_name", &self.uuid)
            .field("client_id", &self.client_id)
            .finish()
    }
}

impl OAuth2TrustProvider {
    #[cfg(test)]
    pub fn new_test<'a, I: IntoIterator<Item = &'a str>>(
        client_id: &str,
        domain: &str,
        request_scopes: I,
    ) -> OAuth2TrustProvider {
        // In prod will be build from our true origin + the actual landing pad.
        let mut client_redirect_uri =
            Url::parse("https://idm.example.com").expect("invalid test data");
        client_redirect_uri.set_path(OAUTH2_CLIENT_AUTHORISATION_RESPONSE_PATH);

        let mut domain = Url::parse(domain).expect("invalid test data");

        domain.set_path("/oauth2/authorise");
        let authorisation_endpoint = domain.clone();

        domain.set_path("/oauth2/token");
        let token_endpoint = domain.clone();

        let client_basic_secret = crate::utils::password_from_random();

        let request_scopes = request_scopes.into_iter().map(String::from).collect();

        OAuth2TrustProvider {
            name: "test_trust_provider".to_string(),
            uuid: Uuid::new_v4(),
            client_id: client_id.to_string(),
            client_basic_secret,
            client_redirect_uri,
            request_scopes,
            authorisation_endpoint,
            token_endpoint,
        }
    }
}

impl IdmServerProxyWriteTransaction<'_> {
    #[instrument(level = "debug", skip_all)]
    pub(crate) fn reload_oauth2_trust_providers(&mut self) -> Result<(), OperationError> {
        let oauth2_trust_provider_entries = self.qs_write.internal_search(filter!(f_eq(
            Attribute::Class,
            EntryClass::OAuth2TrustClient.into(),
        )))?;

        // Preprocess
        let mut oauth2_trust_provider_structs =
            Vec::with_capacity(oauth2_trust_provider_entries.len());

        let mut client_redirect_uri = self.origin.clone();
        client_redirect_uri.set_path(OAUTH2_CLIENT_AUTHORISATION_RESPONSE_PATH);

        for provider_entry in oauth2_trust_provider_entries {
            let uuid = provider_entry.get_uuid();
            trace!(?uuid, "Checking OAuth2 Provider configuration");

            let name = provider_entry
                .get_ava_single_iname(Attribute::Name)
                .map(str::to_string)
                .ok_or(OperationError::InvalidValueState)?;

            let client_id = provider_entry
                .get_ava_single_utf8(Attribute::OAuth2ClientId)
                .map(str::to_string)
                .ok_or(OperationError::InvalidValueState)?;

            let client_basic_secret = provider_entry
                .get_ava_single_utf8(Attribute::OAuth2ClientSecret)
                .map(str::to_string)
                .ok_or(OperationError::InvalidValueState)?;

            let authorisation_endpoint = provider_entry
                .get_ava_single_url(Attribute::OAuth2AuthorisationEndpoint)
                .cloned()
                .ok_or(OperationError::InvalidValueState)?;

            let token_endpoint = provider_entry
                .get_ava_single_url(Attribute::OAuth2TokenEndpoint)
                .cloned()
                .ok_or(OperationError::InvalidValueState)?;

            let request_scopes = provider_entry
                .get_ava_as_oauthscopes(Attribute::OAuth2RequestScopes)
                .ok_or(OperationError::InvalidValueState)?
                .map(str::to_string)
                .collect();

            let provider = OAuth2TrustProvider {
                name,
                uuid,
                client_id,
                client_basic_secret,
                client_redirect_uri: client_redirect_uri.clone(),
                request_scopes,
                authorisation_endpoint,
                token_endpoint,
            };

            oauth2_trust_provider_structs.push((uuid, provider));
        }

        // Clear the existing set.
        self.oauth2_trust_providers.clear();

        // Add them all
        self.oauth2_trust_providers
            .extend(oauth2_trust_provider_structs);

        // Done!
        Ok(())
    }
}
