#![allow(unused_imports)]
use std::collections::BTreeMap;
use std::str::FromStr;

use compact_jwt::{JwkKeySet, JwsEs256Verifier, JwsVerifier, OidcToken, OidcUnverified};
use kanidm_client::KanidmClient;

use kanidm_proto::constants::uri::{OAUTH2_AUTHORISE, OAUTH2_AUTHORISE_PERMIT};

use kanidm_proto::internal::Oauth2ClaimMapJoin;
use kanidm_proto::oauth2::{
    AccessTokenRequest, AccessTokenResponse, AuthorisationResponse, GrantTypeReq,
};

use kanidmd_lib::prelude::uri::{OAUTH2_AUTHORISE_DEVICE, OAUTH2_TOKEN_ENDPOINT};
use kanidmd_lib::prelude::{
    Attribute, IDM_ALL_ACCOUNTS, OAUTH2_SCOPE_EMAIL, OAUTH2_SCOPE_OPENID, OAUTH2_SCOPE_READ,
};
use kanidmd_testkit::{
    assert_no_cache, ADMIN_TEST_PASSWORD, ADMIN_TEST_USER, IDM_ADMIN_TEST_PASSWORD,
    IDM_ADMIN_TEST_USER, NOT_ADMIN_TEST_EMAIL, NOT_ADMIN_TEST_PASSWORD, NOT_ADMIN_TEST_USERNAME,
    TEST_INTEGRATION_RS_DISPLAY, TEST_INTEGRATION_RS_GROUP_ALL, TEST_INTEGRATION_RS_ID,
    TEST_INTEGRATION_RS_REDIRECT_URL, TEST_INTEGRATION_RS_URL,
};

use oauth2_ext::basic::BasicClient;
use oauth2_ext::http::StatusCode;
use oauth2_ext::{
    AuthUrl, ClientId, DeviceAuthorizationUrl, HttpRequest, HttpResponse, PkceCodeChallenge,
    RequestTokenError, Scope, StandardDeviceAuthorizationResponse, StandardErrorResponse, TokenUrl,
};
use reqwest::Client;
use tracing::{debug, error, info};
use url::Url;

#[cfg(feature = "dev-oauth2-device-flow")]
async fn http_client(
    request: HttpRequest,
) -> Result<HttpResponse, oauth2_ext::reqwest::Error<reqwest::Error>> {
    // let ca_contents = std::fs::read("/tmp/kanidm/ca.pem")
    //     .map_err(|err| oauth2::reqwest::Error::Other(err.to_string()))?;

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        // reqwest::Certificate::from_der(&ca_contents)
        // .map_err(oauth2::reqwest::Error::Reqwest)?,
        // )
        .build()
        .map_err(oauth2_ext::reqwest::Error::Reqwest)?;

    let method = reqwest::Method::from_str(request.method.as_str())
        .map_err(|err| oauth2_ext::reqwest::Error::Other(err.to_string()))?;

    let mut request_builder = client
        .request(method, request.url.as_str())
        .body(request.body);

    for (name, value) in &request.headers {
        request_builder = request_builder.header(name.as_str(), value.as_bytes());
    }

    let response = client
        .execute(request_builder.build().map_err(|err| {
            error!("Failed to build request... {:?}", err);
            oauth2_ext::reqwest::Error::Reqwest(err)
        })?)
        .await
        .map_err(|err| {
            error!("Failed to query url {} error={:?}", request.url, err);
            oauth2_ext::reqwest::Error::Reqwest(err)
        })?;

    let status_code = StatusCode::from_u16(response.status().as_u16())
        .map_err(|err| oauth2_ext::reqwest::Error::Other(err.to_string()))?;
    let headers = response
        .headers()
        .into_iter()
        .map(|(k, v)| {
            debug!("header key={:?} value={:?}", k, v);
            (
                oauth2_ext::http::HeaderName::from_str(k.as_str()).expect("Failed to parse header"),
                oauth2_ext::http::HeaderValue::from_str(
                    v.to_str().expect("Failed to parse header value"),
                )
                .expect("Failed to parse header value"),
            )
        })
        .collect();

    let body = response.bytes().await.map_err(|err| {
        error!("Failed to parse body...? {:?}", err);
        oauth2_ext::reqwest::Error::Reqwest(err)
    })?;
    info!("Response body: {:?}", String::from_utf8(body.to_vec()));

    Ok(HttpResponse {
        status_code,
        headers,
        body: body.to_vec(),
    })
}

#[cfg(feature = "dev-oauth2-device-flow")]
#[kanidmd_testkit::test]
async fn oauth2_device_flow(rsclient: KanidmClient) {
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
            NOT_ADMIN_TEST_PASSWORD,
        )
        .await
        .expect("Failed to configure account password");

    rsclient
        .idm_oauth2_rs_update(TEST_INTEGRATION_RS_ID, None, None, None, true, true, true)
        .await
        .expect("Failed to update oauth2 config");

    rsclient
        .idm_oauth2_rs_update_scope_map(
            TEST_INTEGRATION_RS_ID,
            IDM_ALL_ACCOUNTS.name,
            vec![OAUTH2_SCOPE_READ, OAUTH2_SCOPE_EMAIL, OAUTH2_SCOPE_OPENID],
        )
        .await
        .expect("Failed to update oauth2 scopes");

    rsclient
        .idm_oauth2_rs_update_sup_scope_map(
            TEST_INTEGRATION_RS_ID,
            IDM_ALL_ACCOUNTS.name,
            vec![ADMIN_TEST_USER],
        )
        .await
        .expect("Failed to update oauth2 scopes");

    // Add a custom claim map.
    rsclient
        .idm_oauth2_rs_update_claim_map(
            TEST_INTEGRATION_RS_ID,
            "test_claim",
            IDM_ALL_ACCOUNTS.name,
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
        .auth_simple_password(IDM_ADMIN_TEST_USER, IDM_ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    // set up the device flow values

    let rsdata = rsclient
        .idm_oauth2_rs_get(TEST_INTEGRATION_RS_ID)
        .await
        .expect("failed to query rs")
        .expect("failed to get rsdata");

    dbg!(&rsdata);

    assert!(
        !rsdata
            .attrs
            .contains_key(Attribute::OAuth2DeviceFlowEnable.as_str()),
        "Found device flow enable attribute, shouldn't be there yet!"
    );

    rsclient
        .idm_oauth2_client_device_flow_update(TEST_INTEGRATION_RS_ID, true)
        .await
        .expect("Failed to update oauth2 config to enable device flow");

    let rsdata = rsclient
        .idm_oauth2_rs_get(TEST_INTEGRATION_RS_ID)
        .await
        .expect("failed to query rs")
        .expect("failed to get rsdata");

    dbg!(&rsdata);

    assert!(
        rsdata
            .attrs
            .contains_key(Attribute::OAuth2DeviceFlowEnable.as_str()),
        "Couldn't find device flow enable attribute"
    );
    assert_eq!(
        rsdata
            .attrs
            .get(Attribute::OAuth2DeviceFlowEnable.as_str())
            .expect("Couldn't find device flow enable attribute"),
        &vec!["true".to_string()],
        "Device flow enable attribute not set to true"
    );

    // ok we've checked that adding the thing works.
    // now we need to test the device flow itself.

    // first we need to get the device code.

    // kanidm system oauth2 create-public device_flow device_flow 'https://deviceauth'
    let client = BasicClient::new(
        ClientId::new(TEST_INTEGRATION_RS_ID.to_string()),
        None,
        AuthUrl::new(rsclient.make_url(OAUTH2_AUTHORISE).to_string())
            .expect("Failed to build authurl"),
        Some(
            TokenUrl::new(rsclient.make_url(OAUTH2_TOKEN_ENDPOINT).to_string())
                .expect("Failed to build token url"),
        ),
    )
    .set_device_authorization_url(
        DeviceAuthorizationUrl::new(rsclient.make_url(OAUTH2_AUTHORISE_DEVICE).to_string())
            .expect("Failed to build DeviceAuthorizationUrl"),
    );

    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()
        .expect("Failed to exchange device code")
        .add_scope(Scope::new("read".to_string()))
        .request_async(http_client)
        .await
        .expect("Failed to get device code!");

    debug!("{:?}", details);
    dbg!(&details.device_code().secret());
    assert!(details.device_code().secret().len() == 24);

    // now take that device code and get the token... glhf!

    let result = client
        .exchange_device_access_token(&details)
        .request_async(
            http_client,
            tokio::time::sleep,
            Some(std::time::Duration::from_secs(1)),
        )
        .await;

    assert!(result.is_err());
    let err = result.err().expect("Failed to get error");
    dbg!(&err.to_string());
    assert!(err.to_string().contains("Server returned error response"));
}
