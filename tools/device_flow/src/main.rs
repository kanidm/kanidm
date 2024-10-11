use std::str::FromStr;

use kanidm_proto::constants::uri::{
    OAUTH2_AUTHORISE, OAUTH2_AUTHORISE_DEVICE, OAUTH2_TOKEN_ENDPOINT,
};
use oauth2::basic::BasicClient;
use oauth2::devicecode::StandardDeviceAuthorizationResponse;
use oauth2::http::StatusCode;
use oauth2::{
    AuthUrl, ClientId, DeviceAuthorizationUrl, HttpRequest, HttpResponse, Scope, TokenUrl,
};
use reqwest::blocking::Client;
use sketching::tracing_subscriber::layer::SubscriberExt;
use sketching::tracing_subscriber::util::SubscriberInitExt;
use sketching::tracing_subscriber::{fmt, EnvFilter};
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info};

fn http_client(
    request: HttpRequest,
) -> Result<HttpResponse, oauth2::reqwest::Error<reqwest::Error>> {
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
        .map_err(oauth2::reqwest::Error::Reqwest)?;

    let method = reqwest::Method::from_str(request.method.as_str())
        .map_err(|err| oauth2::reqwest::Error::Other(err.to_string()))?;

    let mut request_builder = client
        .request(method, request.url.as_str())
        .body(request.body);

    for (name, value) in &request.headers {
        request_builder = request_builder.header(name.as_str(), value.as_bytes());
    }

    let response = client
        .execute(request_builder.build().map_err(|err| {
            error!("Failed to build request... {:?}", err);
            oauth2::reqwest::Error::Reqwest(err)
        })?)
        .map_err(|err| {
            error!("Failed to query url {} error={:?}", request.url, err);
            oauth2::reqwest::Error::Reqwest(err)
        })?;

    let status_code = StatusCode::from_u16(response.status().as_u16())
        .map_err(|err| oauth2::reqwest::Error::Other(err.to_string()))?;
    let headers = response
        .headers()
        .into_iter()
        .map(|(k, v)| {
            debug!("header key={:?} value={:?}", k, v);
            (
                oauth2::http::HeaderName::from_str(k.as_str()).expect("Failed to parse header"),
                oauth2::http::HeaderValue::from_str(
                    v.to_str().expect("Failed to parse header value"),
                )
                .expect("Failed to parse header value"),
            )
        })
        .collect();

    let body = response.bytes().map_err(|err| {
        error!("Failed to parse body...? {:?}", err);
        oauth2::reqwest::Error::Reqwest(err)
    })?;
    info!("Response body: {:?}", String::from_utf8(body.to_vec()));

    Ok(HttpResponse {
        status_code,
        headers,
        body: body.to_vec(),
    })
}

fn main() -> anyhow::Result<()> {
    let fmt_layer = fmt::layer().with_writer(std::io::stderr);

    let filter_layer = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .parse_lossy("info,kanidm_client=warn,kanidm_cli=info");

    sketching::tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    info!("building client...");

    // kanidm system oauth2 create-public device_flow device_flow 'https://deviceauth'
    let client = BasicClient::new(
        ClientId::new("device_code".to_string()),
        None,
        AuthUrl::new(format!("https://localhost:8443{}", OAUTH2_AUTHORISE))?,
        Some(TokenUrl::new(format!(
            "https://localhost:8443{}",
            OAUTH2_TOKEN_ENDPOINT
        ))?),
    )
    .set_device_authorization_url(DeviceAuthorizationUrl::new(format!(
        "https://localhost:8443{}",
        OAUTH2_AUTHORISE_DEVICE
    ))?);

    info!("Getting details...");

    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()
        .inspect_err(|err| error!("configuration error: {:?}", err))?
        .add_scope(Scope::new("read".to_string()))
        .request(http_client)?;

    println!(
        "Open this URL in your browser: {}",
        match details.verification_uri_complete() {
            Some(uri) => uri.secret().as_str(),
            None => details.verification_uri().as_str(),
        }
    );

    println!("the code is {}", details.user_code().secret());

    let token_result = client.exchange_device_access_token(&details).request(
        http_client,
        std::thread::sleep,
        None,
    )?;
    println!("Result: {:?}", token_result);
    Ok(())
}
