use crate::prelude::*;
use crate::utils;
use std::collections::BTreeSet;

pub struct OAuth2TrustProvider {
    uuid: Uuid,
    client_id: String,
    basic_secret: String,
    request_scopes: BTreeSet<String>,
    authorisation_endpoint: Url,
    token_endpoint: Url,
    introspection_endpoint: Option<Url>,
    revocation_endpoint: Option<Url>,
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
            uuid: Uuid::new_v4(),
            client_id: client_id.to_string(),
            basic_secret,
            request_scopes,
            authorisation_endpoint,
            token_endpoint,
            introspection_endpoint,
            revocation_endpoint,
        }
    }
}
