#![deny(warnings)]
use compact_jwt::{JwkKeySet, JwsEs256Verifier, JwsVerifier, OidcToken, OidcUnverified};
use kanidm_client::{http::header, KanidmClient, StatusCode};
use kanidm_proto::constants::uri::{OAUTH2_AUTHORISE, OAUTH2_AUTHORISE_PERMIT};
use kanidm_proto::constants::*;
use kanidm_proto::internal::Oauth2ClaimMapJoin;
use kanidm_proto::oauth2::{
    AccessTokenIntrospectRequest, AccessTokenIntrospectResponse, AccessTokenRequest,
    AccessTokenResponse, AccessTokenType, AuthorisationResponse, ClientPostAuth, GrantTypeReq,
    OidcDiscoveryResponse, TokenRevokeRequest,
};
use kanidmd_lib::constants::NAME_IDM_ALL_ACCOUNTS;
use kanidmd_lib::prelude::Attribute;
use kanidmd_testkit::{
    assert_no_cache, ADMIN_TEST_PASSWORD, ADMIN_TEST_USER, NOT_ADMIN_TEST_EMAIL,
    NOT_ADMIN_TEST_PASSWORD, NOT_ADMIN_TEST_USERNAME, TEST_INTEGRATION_RS_DISPLAY,
    TEST_INTEGRATION_RS_GROUP_ALL, TEST_INTEGRATION_RS_ID, TEST_INTEGRATION_RS_REDIRECT_URL,
    TEST_INTEGRATION_RS_URL, TEST_INTEGRATION_STATE_VALUE,
};
use oauth2_ext::PkceCodeChallenge;
use reqwest::header::{HeaderValue, CONTENT_TYPE};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::str::FromStr;
use time::OffsetDateTime;
use uri::{OAUTH2_TOKEN_ENDPOINT, OAUTH2_TOKEN_INTROSPECT_ENDPOINT, OAUTH2_TOKEN_REVOKE_ENDPOINT};
use url::{form_urlencoded::parse as query_parse, Url};

enum AuthMethod {
    Basic,
    ClientSecretPost,
}

/// Tests an OAuth 2.0 / OpenID confidential client Authorisation Client flow.
///
/// ## Arguments
///
/// * `response_mode`: If `Some`, the `response_mode` parameter to pass in the
///   `/oauth2/authorise` request.
///
/// * `response_in_fragment`: If `false`, use the `code` passed in the
///   callback URI's query parameter, and require the fragment to be empty.
///
///   If `true`, use the `code` passed in the callback URI's fragment, and
///   require the query parameter to be empty.
async fn test_oauth2_openid_basic_flow_impl(
    rsclient: &KanidmClient,
    response_mode: Option<&str>,
    response_in_fragment: bool,
    state: Option<&str>,
    auth_method: AuthMethod,
) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
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

    rsclient
        .idm_oauth2_client_add_origin(
            TEST_INTEGRATION_RS_ID,
            &Url::parse(TEST_INTEGRATION_RS_REDIRECT_URL).expect("Invalid URL"),
        )
        .await
        .expect("Failed to update oauth2 config");

    // Extend the admin account with extended details for openid claims.
    rsclient
        .idm_person_account_create(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_USERNAME)
        .await
        .expect("Failed to create account details");

    rsclient
        .idm_person_account_set_attr(
            NOT_ADMIN_TEST_USERNAME,
            Attribute::Mail.as_ref(),
            &[NOT_ADMIN_TEST_EMAIL],
        )
        .await
        .expect("Failed to create account mail");

    rsclient
        .idm_person_account_primary_credential_set_password(
            NOT_ADMIN_TEST_USERNAME,
            NOT_ADMIN_TEST_PASSWORD,
        )
        .await
        .expect("Failed to configure account password");

    rsclient
        .idm_oauth2_rs_update(TEST_INTEGRATION_RS_ID, None, None, None, true)
        .await
        .expect("Failed to update oauth2 config");

    rsclient
        .idm_oauth2_rs_rotate_keys(TEST_INTEGRATION_RS_ID, OffsetDateTime::now_utc())
        .await
        .expect("Failed to rotate oauth2 keys");

    rsclient
        .idm_oauth2_rs_update_scope_map(
            TEST_INTEGRATION_RS_ID,
            NAME_IDM_ALL_ACCOUNTS,
            vec![OAUTH2_SCOPE_READ, OAUTH2_SCOPE_EMAIL, OAUTH2_SCOPE_OPENID],
        )
        .await
        .expect("Failed to update oauth2 scopes");

    rsclient
        .idm_oauth2_rs_update_sup_scope_map(
            TEST_INTEGRATION_RS_ID,
            NAME_IDM_ALL_ACCOUNTS,
            vec![ADMIN_TEST_USER],
        )
        .await
        .expect("Failed to update oauth2 scopes");

    let client_secret = rsclient
        .idm_oauth2_rs_get_basic_secret(TEST_INTEGRATION_RS_ID)
        .await
        .ok()
        .flatten()
        .expect("Failed to retrieve test_integration basic secret");

    // Get our admin's auth token for our new client.
    // We have to re-auth to update the mail field.
    let res = rsclient
        .auth_simple_password(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_PASSWORD)
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
        .tls_built_in_native_certs(false)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .expect("Failed to create client.");

    // Step 0 - get the openid discovery details and the public key.
    let response = client
        .request(
            reqwest::Method::OPTIONS,
            rsclient.make_url(&format!(
                "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/.well-known/openid-configuration",
            )),
        )
        .send()
        .await
        .expect("Failed to send discovery preflight request.");

    assert_eq!(response.status(), StatusCode::OK);

    let cors_header: &str = response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .expect("missing access-control-allow-origin header")
        .to_str()
        .expect("invalid access-control-allow-origin header");
    assert!(cors_header.eq("*"));

    let response = client
        .get(rsclient.make_url(&format!(
            "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/.well-known/openid-configuration"
        )))
        .send()
        .await
        .expect("Failed to send request.");

    assert_eq!(response.status(), StatusCode::OK);

    // Assert CORS on the GET too.
    let cors_header: &str = response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .expect("missing access-control-allow-origin header")
        .to_str()
        .expect("invalid access-control-allow-origin header");
    assert!(cors_header.eq("*"));

    assert_no_cache!(response);

    let discovery: OidcDiscoveryResponse = response
        .json()
        .await
        .expect("Failed to access response body");

    tracing::trace!(?discovery);

    // Most values are checked in idm/oauth2.rs, but we want to sanity check
    // the urls here as an extended function smoke test.
    assert_eq!(
        discovery.issuer,
        rsclient.make_url(&format!("/oauth2/openid/{TEST_INTEGRATION_RS_ID}"))
    );

    assert_eq!(
        discovery.authorization_endpoint,
        rsclient.make_url("/ui/oauth2")
    );

    assert_eq!(
        discovery.token_endpoint,
        rsclient.make_url(OAUTH2_TOKEN_ENDPOINT)
    );

    assert!(
        discovery.userinfo_endpoint
            == Some(
                rsclient.make_url(&format!("/oauth2/openid/{TEST_INTEGRATION_RS_ID}/userinfo"))
            )
    );

    assert!(
        discovery.jwks_uri
            == rsclient.make_url(&format!(
                "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/public_key.jwk"
            ))
    );

    // Step 0 - get the jwks public key.
    let response = client
        .get(rsclient.make_url(&format!(
            "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/public_key.jwk"
        )))
        .send()
        .await
        .expect("Failed to send request.");

    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache!(response);

    let jwk_set: JwkKeySet = response
        .json()
        .await
        .expect("Failed to access response body");

    let public_jwk = jwk_set.keys.first().expect("No public key in set!");

    let jws_validator = JwsEs256Verifier::try_from(public_jwk).expect("failed to build validator");

    // Step 1 - the Oauth2 Resource Server would send a redirect to the authorisation
    // server, where the url contains a series of authorisation request parameters.
    //
    // Since we are a client, we can just "pretend" we got the redirect, and issue the
    // get call directly. This should be a 200. (?)

    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut query = vec![
        ("response_type", "code"),
        ("client_id", TEST_INTEGRATION_RS_ID),
        ("code_challenge", pkce_code_challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("redirect_uri", TEST_INTEGRATION_RS_REDIRECT_URL),
        ("scope", "email read openid"),
        ("max_age", "1"),
    ];

    if let Some(response_mode) = response_mode {
        query.push(("response_mode", response_mode));
    }

    if let Some(state) = state {
        query.push(("state", state));
    }

    let response = client
        .get(rsclient.make_url(OAUTH2_AUTHORISE))
        .bearer_auth(oauth_test_uat.clone())
        .query(&query)
        .send()
        .await
        .expect("Failed to send request.");

    assert_eq!(response.status(), StatusCode::OK);
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
        dbg!(&scopes);
        assert!(scopes.contains("admin"));
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
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_no_cache!(response);

    // And we should have a URL in the location header.
    let redir_str = response
        .headers()
        .get("Location")
        .and_then(|hv| hv.to_str().ok().map(str::to_string))
        .expect("Invalid redirect url");

    // Now check it's content
    let redir_url = Url::parse(&redir_str).expect("Url parse failure");
    let pairs: BTreeMap<_, _> = if response_in_fragment {
        assert!(redir_url.query().is_none());
        let fragment = redir_url.fragment().expect("missing URL fragment");
        query_parse(fragment.as_bytes()).collect()
    } else {
        // response_mode = query is default for response_type = code
        assert!(redir_url.fragment().is_none());
        redir_url.query_pairs().collect()
    };

    // We should have state and code.
    let code = pairs.get("code").expect("code not found!");
    assert_eq!(
        pairs.get("state").map(|s| s.to_string()),
        state.map(|s| s.to_string())
    );

    // Step 3 - the "resource server" then uses this state and code to directly contact
    // the authorisation server to request a token.

    let mut form_req: AccessTokenRequest = GrantTypeReq::AuthorizationCode {
        code: code.to_string(),
        redirect_uri: Url::parse(TEST_INTEGRATION_RS_REDIRECT_URL).expect("Invalid URL"),
        code_verifier: Some(pkce_code_verifier.secret().clone()),
    }
    .into();

    let mut response = client.post(rsclient.make_url(OAUTH2_TOKEN_ENDPOINT));

    match auth_method {
        AuthMethod::ClientSecretPost => {
            form_req.client_post_auth = ClientPostAuth {
                client_id: Some(TEST_INTEGRATION_RS_ID.to_string()),
                client_secret: Some(client_secret.clone()),
            }
        }
        AuthMethod::Basic => {
            response = response.basic_auth(TEST_INTEGRATION_RS_ID, Some(client_secret.clone()));
        }
    }

    let response = response
        .form(&form_req)
        .send()
        .await
        .expect("Failed to send code exchange request.");

    assert_eq!(response.status(), StatusCode::OK);

    let cors_header: &str = response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .expect("missing access-control-allow-origin header")
        .to_str()
        .expect("invalid access-control-allow-origin header");
    assert!(cors_header.eq("*"));

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
    let mut intr_request = AccessTokenIntrospectRequest {
        token: atr.access_token.clone(),
        token_type_hint: None,
        client_post_auth: ClientPostAuth::default(),
    };

    let mut response = client.post(rsclient.make_url(OAUTH2_TOKEN_INTROSPECT_ENDPOINT));

    match auth_method {
        AuthMethod::Basic => {
            response = response.basic_auth(TEST_INTEGRATION_RS_ID, Some(client_secret.clone()));
        }
        AuthMethod::ClientSecretPost => {
            intr_request.client_post_auth = ClientPostAuth {
                client_id: Some(TEST_INTEGRATION_RS_ID.to_string()),
                client_secret: Some(client_secret.clone()),
            };
        }
    }

    let response = response
        .form(&intr_request)
        .send()
        .await
        .expect("Failed to send token introspect request.");

    assert_eq!(response.status(), StatusCode::OK);
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
    assert!(!tir.scope.is_empty());
    assert_eq!(tir.client_id.as_deref(), Some(TEST_INTEGRATION_RS_ID));
    assert_eq!(
        tir.username.as_deref(),
        Some(format!("{NOT_ADMIN_TEST_USERNAME}@localhost").as_str())
    );
    assert_eq!(tir.token_type, Some(AccessTokenType::Bearer));
    assert!(tir.exp.is_some());
    assert!(tir.iat.is_some());
    assert!(tir.nbf.is_some());
    assert!(tir.sub.is_some());
    assert_eq!(tir.aud.as_deref(), Some(TEST_INTEGRATION_RS_ID));
    assert!(tir.iss.is_none());
    assert_ne!(tir.jti.to_string().is_empty());

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
    assert_eq!(
        oidc.iss,
        rsclient.make_url(&format!("/oauth2/openid/{TEST_INTEGRATION_RS_ID}"))
    );
    eprintln!("{:?}", oidc.s_claims.email);
    assert_eq!(oidc.s_claims.email.as_deref(), Some(NOT_ADMIN_TEST_EMAIL));
    assert_eq!(oidc.s_claims.email_verified, Some(true));

    let response = client
        .get(rsclient.make_url(&format!("/oauth2/openid/{TEST_INTEGRATION_RS_ID}/userinfo")))
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

    assert_eq!(userinfo, oidc);

    let response = client
        .post(rsclient.make_url(&format!("/oauth2/openid/{TEST_INTEGRATION_RS_ID}/userinfo")))
        .bearer_auth(atr.access_token.clone())
        .send()
        .await
        .expect("Failed to send userinfo POST request.");

    tracing::trace!("{:?}", response.headers());
    assert!(
        response.headers().get(CONTENT_TYPE) == Some(&HeaderValue::from_static(APPLICATION_JSON))
    );
    let userinfo_post = response
        .json::<OidcToken>()
        .await
        .expect("Unable to decode OidcToken from POST userinfo");

    assert_eq!(userinfo_post, userinfo);

    // Step 6 - Show that our client can perform a client credentials grant

    let form_req: AccessTokenRequest = GrantTypeReq::ClientCredentials {
        scope: Some(BTreeSet::from([
            "email".to_string(),
            "read".to_string(),
            "openid".to_string(),
        ])),
    }
    .into();

    let response = client
        .post(rsclient.make_url(OAUTH2_TOKEN_ENDPOINT))
        .basic_auth(TEST_INTEGRATION_RS_ID, Some(client_secret.clone()))
        .form(&form_req)
        .send()
        .await
        .expect("Failed to send client credentials request.");

    assert_eq!(response.status(), StatusCode::OK);

    let atr = response
        .json::<AccessTokenResponse>()
        .await
        .expect("Unable to decode AccessTokenResponse");

    // Step 7 - inspect the granted client credentials token.
    let mut intr_request = AccessTokenIntrospectRequest {
        token: atr.access_token.clone(),
        token_type_hint: None,
        client_post_auth: ClientPostAuth::default(),
    };
    let mut response = client.post(rsclient.make_url(OAUTH2_TOKEN_INTROSPECT_ENDPOINT));

    match auth_method {
        AuthMethod::Basic => {
            response = response.basic_auth(TEST_INTEGRATION_RS_ID, Some(client_secret.clone()));
        }
        AuthMethod::ClientSecretPost => {
            intr_request.client_post_auth = ClientPostAuth::from((
                TEST_INTEGRATION_RS_ID.to_string(),
                Some(client_secret.clone()),
            ));
        }
    }

    let response = response
        .form(&intr_request)
        .send()
        .await
        .expect("Failed to send token introspect request.");

    assert_eq!(response.status(), StatusCode::OK);

    let tir = response
        .json::<AccessTokenIntrospectResponse>()
        .await
        .expect("Unable to decode AccessTokenIntrospectResponse");

    assert!(tir.active);
    assert!(!tir.scope.is_empty());
    assert_eq!(tir.client_id.as_deref(), Some(TEST_INTEGRATION_RS_ID));
    assert_eq!(tir.username.as_deref(), Some("test_integration@localhost"));
    assert_eq!(tir.token_type, Some(AccessTokenType::Bearer));

    // revoke the token!
    let mut req = TokenRevokeRequest {
        token: atr.access_token,
        token_type_hint: None,
        client_post_auth: ClientPostAuth::default(),
    };
    let mut response = client.post(rsclient.make_url(OAUTH2_TOKEN_REVOKE_ENDPOINT));

    match auth_method {
        AuthMethod::Basic => {
            response = response.basic_auth(TEST_INTEGRATION_RS_ID, Some(client_secret.clone()));
        }
        AuthMethod::ClientSecretPost => {
            req.client_post_auth =
                ClientPostAuth::from((TEST_INTEGRATION_RS_ID.to_string(), Some(client_secret)));
        }
    }

    let response = response
        .form(&req)
        .send()
        .await
        .expect("Failed to send token revocation request.");

    assert!(response.status().is_success());

    // auth back with admin so we can test deleting things
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    rsclient
        .idm_oauth2_rs_delete_sup_scope_map(TEST_INTEGRATION_RS_ID, TEST_INTEGRATION_RS_GROUP_ALL)
        .await
        .expect("Failed to update oauth2 scopes");
}

/// Test an OAuth 2.0/OpenID confidential client Authorisation Code flow, with
/// `response_mode` unset.
///
/// The response should be returned as a query parameter.
#[kanidmd_testkit::test]
async fn test_oauth2_openid_basic_flow_mode_unset_bearer(rsclient: &KanidmClient) {
    test_oauth2_openid_basic_flow_impl(
        rsclient,
        None,
        false,
        Some(TEST_INTEGRATION_STATE_VALUE),
        AuthMethod::Basic,
    )
    .await;
}
#[kanidmd_testkit::test]
async fn test_oauth2_openid_basic_flow_mode_unset_post(rsclient: &KanidmClient) {
    test_oauth2_openid_basic_flow_impl(
        rsclient,
        None,
        false,
        Some(TEST_INTEGRATION_STATE_VALUE),
        AuthMethod::ClientSecretPost,
    )
    .await;
}

/// Test an OAuth 2.0/OpenID confidential client Authorisation Code flow, with
/// `response_mode=query`.
///
/// The response should be returned as a query parameter.
#[kanidmd_testkit::test]
async fn test_oauth2_openid_basic_flow_mode_query_bearer(rsclient: &KanidmClient) {
    test_oauth2_openid_basic_flow_impl(
        rsclient,
        Some("query"),
        false,
        Some(TEST_INTEGRATION_STATE_VALUE),
        AuthMethod::Basic,
    )
    .await;
}
#[kanidmd_testkit::test]
async fn test_oauth2_openid_basic_flow_mode_query_post(rsclient: &KanidmClient) {
    test_oauth2_openid_basic_flow_impl(
        rsclient,
        Some("query"),
        false,
        Some(TEST_INTEGRATION_STATE_VALUE),
        AuthMethod::ClientSecretPost,
    )
    .await;
}

/// Test an OAuth 2.0/OpenID confidential client Authorisation Code flow, with
/// `response_mode=fragment`.
///
/// The response should be returned in the URI's fragment.
#[kanidmd_testkit::test]
async fn test_oauth2_openid_basic_flow_mode_fragment_bearer(rsclient: &KanidmClient) {
    test_oauth2_openid_basic_flow_impl(
        rsclient,
        Some("fragment"),
        true,
        Some(TEST_INTEGRATION_STATE_VALUE),
        AuthMethod::Basic,
    )
    .await;
}
#[kanidmd_testkit::test]
async fn test_oauth2_openid_basic_flow_mode_fragment_post(rsclient: &KanidmClient) {
    test_oauth2_openid_basic_flow_impl(
        rsclient,
        Some("fragment"),
        true,
        Some(TEST_INTEGRATION_STATE_VALUE),
        AuthMethod::ClientSecretPost,
    )
    .await;
}

/// Test an OAuth 2.0/OpenID confidential client Authorisation Code flow, with
/// `response_mode=fragment` and no state in the request..
///
/// The response should be returned in the URI's fragment.
#[kanidmd_testkit::test]
async fn test_oauth2_openid_basic_flow_no_state_bearer(rsclient: &KanidmClient) {
    test_oauth2_openid_basic_flow_impl(rsclient, Some("fragment"), true, None, AuthMethod::Basic)
        .await;
}
/// The response should be returned in the URI's fragment.
#[kanidmd_testkit::test]
async fn test_oauth2_openid_basic_flow_no_state_post(rsclient: &KanidmClient) {
    test_oauth2_openid_basic_flow_impl(
        rsclient,
        Some("fragment"),
        true,
        None,
        AuthMethod::ClientSecretPost,
    )
    .await;
}

/// Tests an OAuth 2.0 / OpenID public client Authorisation Client flow.
///
/// ## Arguments
///
/// * `response_mode`: If `Some`, the `response_mode` parameter to pass in the
///   `/oauth2/authorise` request.
///
/// * `response_in_fragment`: If `false`, use the `code` passed in the
///   callback URI's query parameter, and require the fragment to be empty.
///
///   If `true`, use the `code` passed in the callback URI's fragment, and
///   require the query parameter to be empty.
async fn test_oauth2_openid_public_flow_impl(
    rsclient: &KanidmClient,
    response_mode: Option<&str>,
    response_in_fragment: bool,
    state: Option<&str>,
) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
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

    rsclient
        .idm_oauth2_client_add_origin(
            TEST_INTEGRATION_RS_ID,
            &Url::parse(TEST_INTEGRATION_RS_REDIRECT_URL).expect("Invalid URL"),
        )
        .await
        .expect("Failed to update oauth2 config");

    // Extend the admin account with extended details for openid claims.
    rsclient
        .idm_person_account_create(NOT_ADMIN_TEST_USERNAME, NOT_ADMIN_TEST_USERNAME)
        .await
        .expect("Failed to create account details");

    rsclient
        .idm_person_account_set_attr(
            NOT_ADMIN_TEST_USERNAME,
            Attribute::Mail.as_ref(),
            &[NOT_ADMIN_TEST_EMAIL],
        )
        .await
        .expect("Failed to create account mail");

    rsclient
        .idm_person_account_primary_credential_set_password(
            NOT_ADMIN_TEST_USERNAME,
            ADMIN_TEST_PASSWORD,
        )
        .await
        .expect("Failed to configure account password");

    rsclient
        .idm_oauth2_rs_update(TEST_INTEGRATION_RS_ID, None, None, None, true)
        .await
        .expect("Failed to update oauth2 config");

    rsclient
        .idm_oauth2_rs_update_scope_map(
            TEST_INTEGRATION_RS_ID,
            NAME_IDM_ALL_ACCOUNTS,
            vec![OAUTH2_SCOPE_READ, OAUTH2_SCOPE_EMAIL, OAUTH2_SCOPE_OPENID],
        )
        .await
        .expect("Failed to update oauth2 scopes");

    rsclient
        .idm_oauth2_rs_update_sup_scope_map(
            TEST_INTEGRATION_RS_ID,
            NAME_IDM_ALL_ACCOUNTS,
            vec![ADMIN_TEST_USER],
        )
        .await
        .expect("Failed to update oauth2 scopes");

    // Add a custom claim map.
    rsclient
        .idm_oauth2_rs_update_claim_map(
            TEST_INTEGRATION_RS_ID,
            "test_claim",
            NAME_IDM_ALL_ACCOUNTS,
            &["claim_a".to_string(), "claim_b".to_string()],
        )
        .await
        .expect("Failed to update oauth2 claims");

    // Set an alternate join
    rsclient
        .idm_oauth2_rs_update_claim_map_join(
            TEST_INTEGRATION_RS_ID,
            "test_claim",
            Oauth2ClaimMapJoin::Ssv,
        )
        .await
        .expect("Failed to update oauth2 claims");

    // Get our admin's auth token for our new client.
    // We have to re-auth to update the mail field.
    let res = rsclient
        .auth_simple_password(NOT_ADMIN_TEST_USERNAME, ADMIN_TEST_PASSWORD)
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
        .tls_built_in_native_certs(false)
        .no_proxy()
        .build()
        .expect("Failed to create client.");

    // Step 0 - get the jwks public key.
    let response = client
        .get(rsclient.make_url(&format!(
            "/oauth2/openid/{TEST_INTEGRATION_RS_ID}/public_key.jwk",
        )))
        .send()
        .await
        .expect("Failed to send request.");

    assert_eq!(response.status(), StatusCode::OK);
    assert_no_cache!(response);

    let jwk_set: JwkKeySet = response
        .json()
        .await
        .expect("Failed to access response body");

    let public_jwk = jwk_set.keys.first().expect("No public key in set!");

    let jws_validator = JwsEs256Verifier::try_from(public_jwk).expect("failed to build validator");

    // Step 1 - the Oauth2 Resource Server would send a redirect to the authorisation
    // server, where the url contains a series of authorisation request parameters.
    //
    // Since we are a client, we can just "pretend" we got the redirect, and issue the
    // get call directly. This should be a 200. (?)
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut query = vec![
        ("response_type", "code"),
        ("client_id", TEST_INTEGRATION_RS_ID),
        ("code_challenge", pkce_code_challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("redirect_uri", TEST_INTEGRATION_RS_REDIRECT_URL),
        ("scope", "email read openid"),
    ];

    if let Some(response_mode) = response_mode {
        query.push(("response_mode", response_mode));
    }

    if let Some(state) = state {
        query.push(("state", state));
    }

    let response = client
        .get(rsclient.make_url(OAUTH2_AUTHORISE))
        .bearer_auth(oauth_test_uat.clone())
        .query(&query)
        .send()
        .await
        .expect("Failed to send request.");

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Failed to send initial authorize call"
    );
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
        assert!(
            scopes.contains(ADMIN_TEST_USER),
            "Didn't find user {ADMIN_TEST_USER} in scope"
        );
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
        .expect("Failed to send user consent request.");

    // This should yield a 302 redirect with some query params.
    assert_eq!(
        response.status(),
        StatusCode::FOUND,
        "Didn't get redirected"
    );
    assert_no_cache!(response);

    // And we should have a URL in the location header.
    let redir_str = response
        .headers()
        .get("Location")
        .and_then(|hv| hv.to_str().ok().map(str::to_string))
        .expect("Invalid/missing redirect url in Location header");

    // Now check it's content
    let redir_url = Url::parse(&redir_str).expect("Redirect URL parse failure");

    let pairs: BTreeMap<_, _> = if response_in_fragment {
        assert!(redir_url.query().is_none());
        let fragment = redir_url.fragment().expect("Missing URL fragment");
        query_parse(fragment.as_bytes()).collect()
    } else {
        // response_mode = query is default for response_type = code
        assert!(redir_url.fragment().is_none());
        redir_url.query_pairs().collect()
    };

    // We should have state and code.
    let code = pairs.get("code").expect("code not found in query params!");
    assert_eq!(
        pairs.get("state").map(|s| s.to_string()),
        state.map(|s| s.to_string()),
        "Didn't get state from query pairs {pairs:?}"
    );

    // Step 3 - the "resource server" then uses this state and code to directly contact
    // the authorisation server to request a token.

    let form_req = AccessTokenRequest {
        grant_type: GrantTypeReq::AuthorizationCode {
            code: code.to_string(),
            redirect_uri: Url::parse(TEST_INTEGRATION_RS_REDIRECT_URL).expect("Invalid URL"),
            code_verifier: Some(pkce_code_verifier.secret().clone()),
        },
        client_post_auth: (TEST_INTEGRATION_RS_ID, None).into(),
    };

    let response = client
        .post(rsclient.make_url(OAUTH2_TOKEN_ENDPOINT))
        .form(&form_req)
        .send()
        .await
        .expect("Failed to send code exchange request.");

    assert_eq!(response.status(), StatusCode::OK);
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
    assert_eq!(
        oidc.iss,
        rsclient.make_url(&format!("/oauth2/openid/{TEST_INTEGRATION_RS_ID}"))
    );
    eprintln!("{:?}", oidc.s_claims.email);
    assert_eq!(oidc.s_claims.email.as_deref(), Some(NOT_ADMIN_TEST_EMAIL));
    assert_eq!(oidc.s_claims.email_verified, Some(true));

    eprintln!("{:?}", oidc.claims);
    assert_eq!(
        oidc.claims.get("test_claim").and_then(|v| v.as_str()),
        Some("claim_a claim_b")
    );

    // Check the preflight works.
    let response = client
        .request(
            reqwest::Method::OPTIONS,
            rsclient.make_url(&format!("/oauth2/openid/{TEST_INTEGRATION_RS_ID}/userinfo")),
        )
        .send()
        .await
        .expect("Failed to send userinfo preflight request.");

    assert_eq!(response.status(), StatusCode::OK);
    let cors_header: &str = response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .expect("missing access-control-allow-origin header")
        .to_str()
        .expect("invalid access-control-allow-origin header");
    assert!(cors_header.eq("*"));

    let response = client
        .get(rsclient.make_url(&format!("/oauth2/openid/{TEST_INTEGRATION_RS_ID}/userinfo")))
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

    assert_eq!(userinfo, oidc);

    // auth back with admin so we can test deleting things
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());
    rsclient
        .idm_oauth2_rs_delete_sup_scope_map(TEST_INTEGRATION_RS_ID, TEST_INTEGRATION_RS_GROUP_ALL)
        .await
        .expect("Failed to update oauth2 scopes");
}

/// Test an OAuth 2.0/OpenID public client Authorisation Code flow, with
/// `response_mode` unset.
///
/// The response should be returned as a query parameter.
#[kanidmd_testkit::test]
async fn test_oauth2_openid_public_flow_mode_unset(rsclient: &KanidmClient) {
    test_oauth2_openid_public_flow_impl(rsclient, None, false, Some(TEST_INTEGRATION_STATE_VALUE))
        .await;
}

/// Test an OAuth 2.0/OpenID public client Authorisation Code flow, with
/// `response_mode=query`.
///
/// The response should be returned as a query parameter.
#[kanidmd_testkit::test]
async fn test_oauth2_openid_public_flow_mode_query(rsclient: &KanidmClient) {
    test_oauth2_openid_public_flow_impl(
        rsclient,
        Some("query"),
        false,
        Some(TEST_INTEGRATION_STATE_VALUE),
    )
    .await;
}

/// Test an OAuth 2.0/OpenID public client Authorisation Code flow, with
/// `response_mode=fragment`.
///
/// The response should be returned in the URI's fragment.
#[kanidmd_testkit::test]
async fn test_oauth2_openid_public_flow_mode_fragment(rsclient: &KanidmClient) {
    test_oauth2_openid_public_flow_impl(
        rsclient,
        Some("fragment"),
        true,
        Some(TEST_INTEGRATION_STATE_VALUE),
    )
    .await;
}

/// Test an OAuth 2.0/OpenID public client Authorisation Code flow, with
/// `response_mode=fragment` and no state value in the url
///
/// The response should be returned in the URI's fragment.
#[kanidmd_testkit::test]
async fn test_oauth2_openid_public_flow_no_state(rsclient: &KanidmClient) {
    test_oauth2_openid_public_flow_impl(rsclient, Some("fragment"), true, None).await;
}

#[kanidmd_testkit::test]
async fn test_oauth2_token_post_bad_bodies(rsclient: &KanidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_native_certs(false)
        .no_proxy()
        .build()
        .expect("Failed to create client.");

    // test for a bad-body request on token
    let response = client
        .post(rsclient.make_url(OAUTH2_TOKEN_ENDPOINT))
        .form(&serde_json::json!({}))
        // .bearer_auth(atr.access_token.clone())
        .send()
        .await
        .expect("Failed to send token request.");
    println!("{response:?}");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // test for a bad-auth request
    let response = client
        .post(rsclient.make_url(OAUTH2_TOKEN_INTROSPECT_ENDPOINT))
        .form(&serde_json::json!({ "token": "lol" }))
        .send()
        .await
        .expect("Failed to send token introspection request.");
    println!("{response:?}");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[kanidmd_testkit::test]
async fn test_oauth2_token_revoke_post_bearer(rsclient: &KanidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_native_certs(false)
        .no_proxy()
        .build()
        .expect("Failed to create client.");

    // test for a bad-body request on token
    let response = client
        .post(rsclient.make_url(OAUTH2_TOKEN_REVOKE_ENDPOINT))
        .form(&serde_json::json!({}))
        .bearer_auth("lolol")
        .send()
        .await
        .expect("Failed to send token request.");
    println!("{response:?}");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // test for a invalid format request on token
    let response = client
        .post(rsclient.make_url(OAUTH2_TOKEN_REVOKE_ENDPOINT))
        .json("")
        .bearer_auth("lolol")
        .send()
        .await
        .expect("Failed to send token request.");
    println!("{response:?}");

    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // test for a bad-body request on token
    let response = client
        .post(rsclient.make_url(OAUTH2_TOKEN_REVOKE_ENDPOINT))
        .form(&serde_json::json!({}))
        .bearer_auth("Basic lolol")
        .send()
        .await
        .expect("Failed to send token request.");
    println!("{response:?}");
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // test for a bad-body request on token
    let response = client
        .post(rsclient.make_url(OAUTH2_TOKEN_REVOKE_ENDPOINT))
        .body(serde_json::json!({}).to_string())
        .bearer_auth("Basic lolol")
        .send()
        .await
        .expect("Failed to send token request.");
    println!("{response:?}");
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[kanidmd_testkit::test]
async fn test_oauth2_token_revoke_post_postauth(rsclient: &KanidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_native_certs(false)
        .no_proxy()
        .build()
        .expect("Failed to create client.");

    let form = TokenRevokeRequest {
        token: "lolol".into(),
        token_type_hint: None,
        client_post_auth: ClientPostAuth {
            client_id: Some("invalid".to_string()),
            client_secret: Some("lolol".to_string()),
        },
    };

    // test for bad auth
    let response = client
        .post(rsclient.make_url(OAUTH2_TOKEN_REVOKE_ENDPOINT))
        .form(&form)
        .send()
        .await
        .expect("Failed to send token request.");
    println!("{response:?}");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
