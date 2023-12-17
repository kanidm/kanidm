#![deny(warnings)]
use std::collections::HashMap;
use std::convert::TryFrom;
use std::str::FromStr;

use compact_jwt::{JwkKeySet, JwsEs256Verifier, JwsVerifier, OidcToken, OidcUnverified};
use kanidm_proto::constants::uri::{OAUTH2_AUTHORISE, OAUTH2_AUTHORISE_PERMIT};
use kanidm_proto::constants::*;
use kanidm_proto::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenIntrospectResponse, AccessTokenRequest,
    AccessTokenResponse, AuthorisationResponse, GrantTypeReq, OidcDiscoveryResponse,
};
use kanidmd_lib::prelude::{Attribute, IDM_ALL_ACCOUNTS};
use oauth2_ext::PkceCodeChallenge;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use reqwest::StatusCode;
use url::Url;

use kanidm_client::KanidmClient;
use kanidmd_testkit::ADMIN_TEST_PASSWORD;

macro_rules! assert_no_cache {
    ($response:expr) => {{
        // Check we have correct nocache headers.
        let cache_header: &str = $response
            .headers()
            .get(http::header::CACHE_CONTROL)
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

const TEST_INTEGRATION_RS_ID: &str = "test_integration";
const TEST_INTEGRATION_RS_GROUP_ALL: &str = "idm_all_accounts";
const TEST_INTEGRATION_RS_DISPLAY: &str = "Test Integration";
const TEST_INTEGRATION_RS_URL: &str = "https://demo.example.com";

#[kanidmd_testkit::test]
async fn test_oauth2_openid_basic_flow(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Create an oauth2 application integration.
    rsclient
        .idm_oauth2_rs_basic_create(
            TEST_INTEGRATION_RS_ID,
            TEST_INTEGRATION_RS_DISPLAY,
            TEST_INTEGRATION_RS_URL,
        )
        .await
        .expect("Failed to create oauth2 config");

    // Extend the admin account with extended details for openid claims.
    rsclient
        .idm_person_account_create("oauth_test", "oauth_test")
        .await
        .expect("Failed to create account details");

    rsclient
        .idm_person_account_set_attr(
            "oauth_test",
            Attribute::Mail.as_ref(),
            &["oauth_test@localhost"],
        )
        .await
        .expect("Failed to create account mail");

    rsclient
        .idm_person_account_primary_credential_set_password("oauth_test", ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to configure account password");

    rsclient
        .idm_oauth2_rs_update("test_integration", None, None, None, None, true, true, true)
        .await
        .expect("Failed to update oauth2 config");

    rsclient
        .idm_oauth2_rs_update_scope_map(
            "test_integration",
            IDM_ALL_ACCOUNTS.name,
            vec![OAUTH2_SCOPE_READ, OAUTH2_SCOPE_EMAIL, OAUTH2_SCOPE_OPENID],
        )
        .await
        .expect("Failed to update oauth2 scopes");

    rsclient
        .idm_oauth2_rs_update_sup_scope_map(
            "test_integration",
            IDM_ALL_ACCOUNTS.name,
            vec!["admin"],
        )
        .await
        .expect("Failed to update oauth2 scopes");

    let client_secret = rsclient
        .idm_oauth2_rs_get_basic_secret("test_integration")
        .await
        .ok()
        .flatten()
        .expect("Failed to retrieve test_integration basic secret");

    // Get our admin's auth token for our new client.
    // We have to re-auth to update the mail field.
    let res = rsclient
        .auth_simple_password("oauth_test", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    let oauth_test_uat = rsclient
        .get_token()
        .await
        .expect("No user auth token found");

    // We need a new reqwest client here.

    // from here, we can now begin what would be a "interaction" to the oauth server.
    // Create a new reqwest client - we'll be using this manually.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("Failed to create client.");

    // Step 0 - get the openid discovery details and the public key.
    let response = client
        .request(
            reqwest::Method::OPTIONS,
            rsclient.make_url("/oauth2/openid/test_integration/.well-known/openid-configuration"),
        )
        .send()
        .await
        .expect("Failed to send discovery preflight request.");

    assert!(response.status() == reqwest::StatusCode::OK);

    let cors_header: &str = response
        .headers()
        .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .expect("missing access-control-allow-origin header")
        .to_str()
        .expect("invalid access-control-allow-origin header");
    assert!(cors_header.eq("*"));

    let response = client
        .get(rsclient.make_url("/oauth2/openid/test_integration/.well-known/openid-configuration"))
        .send()
        .await
        .expect("Failed to send request.");

    assert!(response.status() == reqwest::StatusCode::OK);
    assert_no_cache!(response);

    let discovery: OidcDiscoveryResponse = response
        .json()
        .await
        .expect("Failed to access response body");

    tracing::trace!(?discovery);

    // Most values are checked in idm/oauth2.rs, but we want to sanity check
    // the urls here as an extended function smoke test.
    assert!(discovery.issuer == rsclient.make_url("/oauth2/openid/test_integration"));

    assert!(discovery.authorization_endpoint == rsclient.make_url("/ui/oauth2"));

    assert!(discovery.token_endpoint == rsclient.make_url("/oauth2/token"));

    assert!(
        discovery.userinfo_endpoint
            == Some(rsclient.make_url("/oauth2/openid/test_integration/userinfo"))
    );

    assert!(
        discovery.jwks_uri == rsclient.make_url("/oauth2/openid/test_integration/public_key.jwk")
    );

    // Step 0 - get the jwks public key.
    let response = client
        .get(rsclient.make_url("/oauth2/openid/test_integration/public_key.jwk"))
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

    let jws_validator = JwsEs256Verifier::try_from(&public_jwk).expect("failed to build validator");

    // Step 1 - the Oauth2 Resource Server would send a redirect to the authorisation
    // server, where the url contains a series of authorisation request parameters.
    //
    // Since we are a client, we can just "pretend" we got the redirect, and issue the
    // get call directly. This should be a 200. (?)

    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let response = client
        .get(rsclient.make_url(OAUTH2_AUTHORISE))
        .bearer_auth(oauth_test_uat.clone())
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

    let consent_req: AuthorisationResponse = response
        .json()
        .await
        .expect("Failed to access response body");

    let consent_token = if let AuthorisationResponse::ConsentRequested {
        consent_token,
        scopes,
        ..
    } = consent_req
    {
        // Note the supplemental scope here (admin)
        assert!(scopes.contains(&"admin".to_string()));
        consent_token
    } else {
        unreachable!();
    };

    // Step 2 - we now send the consent get to the server which yields a redirect with a
    // state and code.

    let response = client
        .get(rsclient.make_url(OAUTH2_AUTHORISE_PERMIT))
        .bearer_auth(oauth_test_uat)
        .query(&[("token", consent_token.as_str())])
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
        .and_then(|hv| hv.to_str().ok().map(str::to_string))
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

    let form_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
        code: code.to_string(),
        redirect_uri: Url::parse("https://demo.example.com/oauth2/flow").expect("Invalid URL"),
        code_verifier: Some(pkce_code_verifier.secret().clone()),
    }
    .into();

    let response = client
        .post(rsclient.make_url("/oauth2/token"))
        .basic_auth("test_integration", Some(client_secret.clone()))
        .form(&form_req)
        .send()
        .await
        .expect("Failed to send code exchange request.");

    assert!(response.status() == reqwest::StatusCode::OK);
    assert!(
        response.headers().get(CONTENT_TYPE) == Some(&HeaderValue::from_static(APPLICATION_JSON))
    );
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
        .post(rsclient.make_url("/oauth2/token/introspect"))
        .basic_auth("test_integration", Some(client_secret))
        .form(&intr_request)
        .send()
        .await
        .expect("Failed to send token introspect request.");

    assert!(response.status() == reqwest::StatusCode::OK);
    tracing::trace!("{:?}", response.headers());
    assert!(
        response.headers().get(CONTENT_TYPE) == Some(&HeaderValue::from_static(APPLICATION_JSON))
    );
    assert_no_cache!(response);

    let tir = response
        .json::<AccessTokenIntrospectResponse>()
        .await
        .expect("Unable to decode AccessTokenIntrospectResponse");

    assert!(tir.active);
    assert!(tir.scope.is_some());
    assert!(tir.client_id.as_deref() == Some("test_integration"));
    assert!(tir.username.as_deref() == Some("oauth_test@localhost"));
    assert!(tir.token_type.as_deref() == Some("access_token"));
    assert!(tir.exp.is_some());
    assert!(tir.iat.is_some());
    assert!(tir.nbf.is_some());
    assert!(tir.sub.is_some());
    assert!(tir.aud.as_deref() == Some("test_integration"));
    assert!(tir.iss.is_none());
    assert!(tir.jti.is_none());

    // Step 5 - check that the id_token (openid) matches the userinfo endpoint.
    let oidc_unverified =
        OidcUnverified::from_str(atr.id_token.as_ref().unwrap()).expect("Failed to parse id_token");

    let oidc = jws_validator
        .verify(&oidc_unverified)
        .expect("Failed to verify oidc")
        .verify_exp(0)
        .expect("Failed to check exp");

    // This is mostly checked inside of idm/oauth2.rs. This is more to check the oidc
    // token and the userinfo endpoints.
    assert!(oidc.iss == rsclient.make_url("/oauth2/openid/test_integration"));
    eprintln!("{:?}", oidc.s_claims.email);
    assert!(oidc.s_claims.email.as_deref() == Some("oauth_test@localhost"));
    assert!(oidc.s_claims.email_verified == Some(true));

    let response = client
        .get(rsclient.make_url("/oauth2/openid/test_integration/userinfo"))
        .bearer_auth(atr.access_token.clone())
        .send()
        .await
        .expect("Failed to send userinfo request.");

    tracing::trace!("{:?}", response.headers());
    assert!(
        response.headers().get(CONTENT_TYPE) == Some(&HeaderValue::from_static(APPLICATION_JSON))
    );
    let userinfo = response
        .json::<OidcToken>()
        .await
        .expect("Unable to decode OidcToken from userinfo");

    eprintln!("userinfo {userinfo:?}");
    eprintln!("oidc {oidc:?}");

    assert!(userinfo == oidc);

    // auth back with admin so we can test deleting things
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    rsclient
        .idm_oauth2_rs_delete_sup_scope_map("test_integration", TEST_INTEGRATION_RS_GROUP_ALL)
        .await
        .expect("Failed to update oauth2 scopes");
}

#[kanidmd_testkit::test]
async fn test_oauth2_openid_public_flow(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // Create an oauth2 application integration.
    rsclient
        .idm_oauth2_rs_public_create(
            TEST_INTEGRATION_RS_ID,
            TEST_INTEGRATION_RS_DISPLAY,
            TEST_INTEGRATION_RS_URL,
        )
        .await
        .expect("Failed to create oauth2 config");

    // Extend the admin account with extended details for openid claims.
    rsclient
        .idm_person_account_create("oauth_test", "oauth_test")
        .await
        .expect("Failed to create account details");

    rsclient
        .idm_person_account_set_attr(
            "oauth_test",
            Attribute::Mail.as_ref(),
            &["oauth_test@localhost"],
        )
        .await
        .expect("Failed to create account mail");

    rsclient
        .idm_person_account_primary_credential_set_password("oauth_test", ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to configure account password");

    rsclient
        .idm_oauth2_rs_update("test_integration", None, None, None, None, true, true, true)
        .await
        .expect("Failed to update oauth2 config");

    rsclient
        .idm_oauth2_rs_update_scope_map(
            "test_integration",
            IDM_ALL_ACCOUNTS.name,
            vec![OAUTH2_SCOPE_READ, OAUTH2_SCOPE_EMAIL, OAUTH2_SCOPE_OPENID],
        )
        .await
        .expect("Failed to update oauth2 scopes");

    rsclient
        .idm_oauth2_rs_update_sup_scope_map(
            "test_integration",
            IDM_ALL_ACCOUNTS.name,
            vec!["admin"],
        )
        .await
        .expect("Failed to update oauth2 scopes");

    // Get our admin's auth token for our new client.
    // We have to re-auth to update the mail field.
    let res = rsclient
        .auth_simple_password("oauth_test", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    let oauth_test_uat = rsclient
        .get_token()
        .await
        .expect("No user auth token found");

    // We need a new reqwest client here.

    // from here, we can now begin what would be a "interaction" to the oauth server.
    // Create a new reqwest client - we'll be using this manually.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("Failed to create client.");

    // Step 0 - get the jwks public key.
    let response = client
        .get(rsclient.make_url("/oauth2/openid/test_integration/public_key.jwk"))
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

    let jws_validator = JwsEs256Verifier::try_from(&public_jwk).expect("failed to build validator");

    // Step 1 - the Oauth2 Resource Server would send a redirect to the authorisation
    // server, where the url contains a series of authorisation request parameters.
    //
    // Since we are a client, we can just "pretend" we got the redirect, and issue the
    // get call directly. This should be a 200. (?)
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let response = client
        .get(rsclient.make_url(OAUTH2_AUTHORISE))
        .bearer_auth(oauth_test_uat.clone())
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

    let consent_req: AuthorisationResponse = response
        .json()
        .await
        .expect("Failed to access response body");

    let consent_token = if let AuthorisationResponse::ConsentRequested {
        consent_token,
        scopes,
        ..
    } = consent_req
    {
        // Note the supplemental scope here (admin)
        assert!(scopes.contains(&"admin".to_string()));
        consent_token
    } else {
        unreachable!();
    };

    // Step 2 - we now send the consent get to the server which yields a redirect with a
    // state and code.
    let response = client
        .get(rsclient.make_url(OAUTH2_AUTHORISE_PERMIT))
        .bearer_auth(oauth_test_uat)
        .query(&[("token", consent_token.as_str())])
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
        .and_then(|hv| hv.to_str().ok().map(str::to_string))
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
        grant_type: GrantTypeReq::AuthorizationCode {
            code: code.to_string(),
            redirect_uri: Url::parse("https://demo.example.com/oauth2/flow").expect("Invalid URL"),
            code_verifier: Some(pkce_code_verifier.secret().clone()),
        },
        client_id: Some("test_integration".to_string()),
        client_secret: None,
    };

    let response = client
        .post(rsclient.make_url("/oauth2/token"))
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

    // Step 5 - check that the id_token (openid) matches the userinfo endpoint.
    let oidc_unverified =
        OidcUnverified::from_str(atr.id_token.as_ref().unwrap()).expect("Failed to parse id_token");

    let oidc = jws_validator
        .verify(&oidc_unverified)
        .expect("Failed to verify oidc")
        .verify_exp(0)
        .expect("Failed to check exp");

    // This is mostly checked inside of idm/oauth2.rs. This is more to check the oidc
    // token and the userinfo endpoints.
    assert!(oidc.iss == rsclient.make_url("/oauth2/openid/test_integration"));
    eprintln!("{:?}", oidc.s_claims.email);
    assert!(oidc.s_claims.email.as_deref() == Some("oauth_test@localhost"));
    assert!(oidc.s_claims.email_verified == Some(true));

    // Check the preflight works.
    let response = client
        .request(
            reqwest::Method::OPTIONS,
            rsclient.make_url("/oauth2/openid/test_integration/userinfo"),
        )
        .send()
        .await
        .expect("Failed to send userinfo preflight request.");

    assert!(response.status() == reqwest::StatusCode::OK);
    let cors_header: &str = response
        .headers()
        .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .expect("missing access-control-allow-origin header")
        .to_str()
        .expect("invalid access-control-allow-origin header");
    assert!(cors_header.eq("*"));

    let response = client
        .get(rsclient.make_url("/oauth2/openid/test_integration/userinfo"))
        .bearer_auth(atr.access_token.clone())
        .send()
        .await
        .expect("Failed to send userinfo request.");

    let userinfo = response
        .json::<OidcToken>()
        .await
        .expect("Unable to decode OidcToken from userinfo");

    eprintln!("userinfo {userinfo:?}");
    eprintln!("oidc {oidc:?}");

    assert!(userinfo == oidc);

    // auth back with admin so we can test deleting things
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    rsclient
        .idm_oauth2_rs_delete_sup_scope_map("test_integration", TEST_INTEGRATION_RS_GROUP_ALL)
        .await
        .expect("Failed to update oauth2 scopes");
}

#[kanidmd_testkit::test]
async fn test_oauth2_token_post_bad_bodies(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("Failed to create client.");

    // test for a bad-body request on token
    let response = client
        .post(rsclient.make_url("/oauth2/token"))
        .form(&serde_json::json!({}))
        // .bearer_auth(atr.access_token.clone())
        .send()
        .await
        .expect("Failed to send token request.");
    println!("{:?}", response);
    assert!(response.status() == StatusCode::UNPROCESSABLE_ENTITY);

    // test for a bad-auth request
    let response = client
        .post(rsclient.make_url("/oauth2/token/introspect"))
        .form(&serde_json::json!({ "token": "lol" }))
        .send()
        .await
        .expect("Failed to send token introspection request.");
    println!("{:?}", response);
    assert!(response.status() == StatusCode::UNAUTHORIZED);
}

#[kanidmd_testkit::test]
async fn test_oauth2_token_revoke_post(rsclient: KanidmClient) {
    let res = rsclient
        .auth_simple_password("admin", ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("Failed to create client.");

    // test for a bad-body request on token
    let response = client
        .post(rsclient.make_url("/oauth2/token/revoke"))
        .form(&serde_json::json!({}))
        .bearer_auth("lolol")
        .send()
        .await
        .expect("Failed to send token request.");
    println!("{:?}", response);
    assert!(response.status() == StatusCode::UNPROCESSABLE_ENTITY);

    // test for a invalid format request on token
    let response = client
        .post(rsclient.make_url("/oauth2/token/revoke"))
        .json("")
        .bearer_auth("lolol")
        .send()
        .await
        .expect("Failed to send token request.");
    println!("{:?}", response);

    assert!(response.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // test for a bad-body request on token
    let response = client
        .post(rsclient.make_url("/oauth2/token/revoke"))
        .form(&serde_json::json!({}))
        .bearer_auth("Basic lolol")
        .send()
        .await
        .expect("Failed to send token request.");
    println!("{:?}", response);
    assert!(response.status() == StatusCode::UNPROCESSABLE_ENTITY);

    // test for a bad-body request on token
    let response = client
        .post(rsclient.make_url("/oauth2/token/revoke"))
        .body(serde_json::json!({}).to_string())
        .bearer_auth("Basic lolol")
        .send()
        .await
        .expect("Failed to send token request.");
    println!("{:?}", response);
    assert!(response.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE);
}
