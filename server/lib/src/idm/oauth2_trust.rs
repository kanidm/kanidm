use crate::prelude::*;
use crate::utils;
use std::collections::BTreeSet;

// TODO: Move to constants once we have a good path here. Will probably need to be part
// of the axum config etc.
// I'm pretty sure this can preserve query strings if we wanted to stash info or flag things?
pub const OAUTH2_CLIENT_AUTHORISATION_RESPONSE_PATH: &str = "/login/oauth2_trust_landing";

pub struct OAuth2TrustProvider {
    pub(crate) name: String,
    pub(crate) uuid: Uuid,
    /// This is the origin of THIS kanidm server.
    pub(crate) client_redirect_uri: Url,
    pub(crate) client_id: String,
    pub(crate) basic_secret: String,
    pub(crate) request_scopes: BTreeSet<String>,
    pub(crate) authorisation_endpoint: Url,
    pub(crate) token_endpoint: Url,
    pub(crate) introspection_endpoint: Option<Url>,
    pub(crate) revocation_endpoint: Option<Url>,
}

impl OAuth2TrustProvider {
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    #[cfg(test)]
    pub fn new_test<'a, I: IntoIterator<Item = &'a str>>(
        client_id: &str,
        domain: &str,
        request_scopes: I,
        introspection_endpoint: bool,
        revocation_endpoint: bool,
    ) -> OAuth2TrustProvider {
        // In prod will be build from our true origin + the actual landing pad.
        let mut client_redirect_uri =
            Url::parse("https://idm.example.com").expect("invalid test data");
        client_redirect_uri.set_path(OAUTH2_CLIENT_AUTHORISATION_RESPONSE_PATH);

        let mut domain = Url::parse(domain).expect("invalid test data");

        domain.set_path("/oauth2/authorise");
        let mut authorisation_endpoint = domain.clone();

        domain.set_path("/oauth2/token");
        let token_endpoint = domain.clone();

        let introspection_endpoint = introspection_endpoint.then(|| {
            domain.set_path("/oauth2/introspect");
            domain.clone()
        });

        let revocation_endpoint = revocation_endpoint.then(|| {
            domain.set_path("/oauth2/revoke");
            domain.clone()
        });

        let basic_secret = utils::password_from_random();

        let request_scopes = request_scopes.into_iter().map(String::from).collect();

        OAuth2TrustProvider {
            name: "test_trust_provider".to_string(),
            uuid: Uuid::new_v4(),
            client_id: client_id.to_string(),
            client_redirect_uri,
            basic_secret,
            request_scopes,
            authorisation_endpoint,
            token_endpoint,
            introspection_endpoint,
            revocation_endpoint,
        }
    }
}
