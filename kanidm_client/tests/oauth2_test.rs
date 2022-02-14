mod common;
use crate::common::{run_test, ADMIN_TEST_PASSWORD};
use kanidm_client::KanidmClient;

use compact_jwt::{JwkKeySet, JwsValidator, OidcToken, OidcUnverified};
use kanidm_proto::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenIntrospectResponse, AccessTokenRequest,
    AccessTokenResponse, ConsentRequest, OidcDiscoveryResponse,
};
use oauth2_ext::PkceCodeChallenge;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::str::FromStr;
use url::Url;

macro_rules! assert_no_cache {
    ($response:expr) => {{
        // Check we have correct nocache headers.
        let cache_header: &str = $response
            .headers()
            .get("cache-control")
            .expect("missing cache-control header")
            .to_str()
            .expect("invalid cache-control header");

        assert!(cache_header.contains("no-store"));
        assert!(cache_header.contains("max-age=0"));

        let pragma_header: &str = $response
            .headers()
            .get("pragma")
            .expect("missing cache-control header")
            .to_str()
            .expect("invalid cache-control header");

        assert!(pragma_header.contains("no-cache"));
    }};
}

#[test]
fn test_oauth2_openid_basic_flow() {
    run_test(|rsclient: KanidmClient| {
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());

        // Create an oauth2 application integration.
        rsclient
            .idm_oauth2_rs_basic_create(
                "test_integration",
                "Test Integration",
                "https://demo.example.com",
            )
            .expect("Failed to create oauth2 config");

        // Extend the admin account with extended details for openid claims.
        rsclient
            .idm_group_add_members("idm_hp_people_extend_priv", &["admin"])
            .unwrap();

        rsclient
            .idm_account_person_extend(
                "admin",
                Some(&["admin@idm.example.com".to_string()]),
                Some("Admin Istrator"),
            )
            .expect("Failed to extend account details");

        rsclient
            .idm_oauth2_rs_update(
                "test_integration",
                None,
                None,
                None,
                Some(vec!["read", "email", "openid"]),
                false,
                false,
                false,
            )
            .expect("Failed to update oauth2 config");

        let oauth2_config = rsclient
            .idm_oauth2_rs_get("test_integration")
            .ok()
            .flatten()
            .expect("Failed to retrieve test_integration config");

        let client_secret = oauth2_config
            .attrs
            .get("oauth2_rs_basic_secret")
            .map(|s| s[0].to_string())
            .expect("No basic secret present");

        // Get our admin's auth token for our new client.
        // We have to re-auth to update the mail field.
        let res = rsclient.auth_simple_password("admin", ADMIN_TEST_PASSWORD);
        assert!(res.is_ok());
        let admin_uat = rsclient.get_token().expect("No user auth token found");

        let url = rsclient.get_url().to_string();

        // We need a new reqwest client here.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to start tokio");
        rt.block_on(async {
            // from here, we can now begin what would be a "interaction" to the oauth server.
            // Create a new reqwest client - we'll be using this manually.
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .expect("Failed to create client.");

            // Step 0 - get the openid discovery details and the public key.
            let response = client
                .get(format!(
                    "{}/oauth2/openid/test_integration/.well-known/openid-configuration",
                    url
                ))
                .send()
                .await
                .expect("Failed to send request.");

            assert!(response.status() == reqwest::StatusCode::OK);
            assert_no_cache!(response);

            let discovery: OidcDiscoveryResponse = response
                .json()
                .await
                .expect("Failed to access response body");

            // Most values are checked in idm/oauth2.rs, but we want to sanity check
            // the urls here as an extended function smoke test.
            assert!(
                discovery.issuer
                    == Url::parse("https://idm.example.com/oauth2/openid/test_integration")
                        .unwrap()
            );

            assert!(
                discovery.authorization_endpoint
                    == Url::parse("https://idm.example.com/ui/oauth2").unwrap()
            );

            assert!(
                discovery.token_endpoint
                    == Url::parse("https://idm.example.com/oauth2/token").unwrap()
            );

            assert!(
                discovery.userinfo_endpoint
                    == Some(
                        Url::parse(
                            "https://idm.example.com/oauth2/openid/test_integration/userinfo"
                        )
                        .unwrap()
                    )
            );

            assert!(
                discovery.jwks_uri
                    == Url::parse(
                        "https://idm.example.com/oauth2/openid/test_integration/public_key.jwk"
                    )
                    .unwrap()
            );

            // Step 0 - get the jwks public key.
            let response = client
                .get(format!(
                    "{}/oauth2/openid/test_integration/public_key.jwk",
                    url
                ))
                .send()
                .await
                .expect("Failed to send request.");

            assert!(response.status() == reqwest::StatusCode::OK);
            assert_no_cache!(response);

            let mut jwk_set: JwkKeySet = response
                .json()
                .await
                .expect("Failed to access response body");

            let public_jwk = jwk_set.keys.pop().expect("No public key in set!");

            let jws_validator =
                JwsValidator::try_from(&public_jwk).expect("failed to build validator");

            // Step 1 - the Oauth2 Resource Server would send a redirect to the authorisation
            // server, where the url contains a series of authorisation request parameters.
            //
            // Since we are a client, we can just "pretend" we got the redirect, and issue the
            // get call directly. This should be a 200. (?)

            let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

            let response = client
                .get(format!("{}/oauth2/authorise", url))
                .bearer_auth(admin_uat.clone())
                .query(&[
                    ("response_type", "code"),
                    ("client_id", "test_integration"),
                    ("state", "YWJjZGVm"),
                    ("code_challenge", pkce_code_challenge.as_str()),
                    ("code_challenge_method", "S256"),
                    ("redirect_uri", "https://demo.example.com/oauth2/flow"),
                    ("scope", "email read openid"),
                ])
                .send()
                .await
                .expect("Failed to send request.");

            assert!(response.status() == reqwest::StatusCode::OK);
            assert_no_cache!(response);

            let consent_req: ConsentRequest = response
                .json()
                .await
                .expect("Failed to access response body");

            // Step 2 - we now send the consent get to the server which yields a redirect with a
            // state and code.

            let response = client
                .get(format!("{}/oauth2/authorise/permit", url))
                .bearer_auth(admin_uat)
                .query(&[("token", consent_req.consent_token.as_str())])
                .send()
                .await
                .expect("Failed to send request.");

            // This should yield a 302 redirect with some query params.
            assert!(response.status() == reqwest::StatusCode::FOUND);
            assert_no_cache!(response);

            // And we should have a URL in the location header.
            let redir_str = response
                .headers()
                .get("Location")
                .map(|hv| hv.to_str().ok().map(str::to_string))
                .flatten()
                .expect("Invalid redirect url");

            // Now check it's content
            let redir_url = Url::parse(&redir_str).expect("Url parse failure");

            // We should have state and code.
            let pairs: HashMap<_, _> = redir_url.query_pairs().collect();

            let code = pairs.get("code").expect("code not found!");

            let state = pairs.get("state").expect("state not found!");

            assert!(state == "YWJjZGVm");

            // Step 3 - the "resource server" then uses this state and code to directly contact
            // the authorisation server to request a token.

            let form_req = AccessTokenRequest {
                grant_type: "authorization_code".to_string(),
                code: code.to_string(),
                redirect_uri: Url::parse("https://demo.example.com/oauth2/flow")
                    .expect("Invalid URL"),
                client_id: None,
                client_secret: None,
                code_verifier: Some(pkce_code_verifier.secret().clone()),
            };

            let response = client
                .post(format!("{}/oauth2/token", url))
                .basic_auth("test_integration", Some(client_secret.clone()))
                .form(&form_req)
                .send()
                .await
                .expect("Failed to send code exchange request.");

            assert!(response.status() == reqwest::StatusCode::OK);
            assert_no_cache!(response);

            // The body is a json AccessTokenResponse

            let atr = response
                .json::<AccessTokenResponse>()
                .await
                .expect("Unable to decode AccessTokenResponse");

            // Step 4 - inspect the granted token.
            let intr_request = AccessTokenIntrospectRequest {
                token: atr.access_token.clone(),
                token_type_hint: None,
            };

            let response = client
                .post(format!("{}/oauth2/token/introspect", url))
                .basic_auth("test_integration", Some(client_secret))
                .form(&intr_request)
                .send()
                .await
                .expect("Failed to send token introspect request.");

            assert!(response.status() == reqwest::StatusCode::OK);
            assert_no_cache!(response);

            let tir = response
                .json::<AccessTokenIntrospectResponse>()
                .await
                .expect("Unable to decode AccessTokenIntrospectResponse");

            assert!(tir.active);
            assert!(tir.scope.is_some());
            assert!(tir.client_id.as_deref() == Some("test_integration"));
            assert!(tir.username.as_deref() == Some("admin@idm.example.com"));
            assert!(tir.token_type.as_deref() == Some("access_token"));
            assert!(tir.exp.is_some());
            assert!(tir.iat.is_some());
            assert!(tir.nbf.is_some());
            assert!(tir.sub.is_some());
            assert!(tir.aud.as_deref() == Some("test_integration"));
            assert!(tir.iss.is_none());
            assert!(tir.jti.is_none());

            // Step 5 - check that the id_token (openid) matches the userinfo endpoint.
            let oidc_unverified = OidcUnverified::from_str(atr.id_token.as_ref().unwrap())
                .expect("Failed to parse id_token");

            let oidc = oidc_unverified
                .validate(&jws_validator, 0)
                .expect("Failed to verify oidc");

            // This is mostly checked inside of idm/oauth2.rs. This is more to check the oidc
            // token and the userinfo endpoints.
            assert!(
                oidc.iss
                    == Url::parse("https://idm.example.com/oauth2/openid/test_integration")
                        .unwrap()
            );
            assert!(oidc.s_claims.email.as_deref() == Some("admin@idm.example.com"));
            assert!(oidc.s_claims.email_verified == Some(true));

            let response = client
                .get(format!("{}/oauth2/openid/test_integration/userinfo", url))
                .bearer_auth(atr.access_token.clone())
                .send()
                .await
                .expect("Failed to send userinfo request.");

            let userinfo = response
                .json::<OidcToken>()
                .await
                .expect("Unable to decode OidcToken from userinfo");

            assert!(userinfo == oidc);
        })
    })
}
