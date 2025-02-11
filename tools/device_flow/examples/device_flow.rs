use std::str::FromStr;

use kanidm_proto::constants::uri::{
    OAUTH2_AUTHORISE, OAUTH2_AUTHORISE_DEVICE, OAUTH2_TOKEN_ENDPOINT,
};
use oauth2::basic::BasicClient;

use oauth2::http::StatusCode;
use oauth2::{
    AuthUrl, ClientId, DeviceAuthorizationUrl, HttpRequest, HttpResponse, Scope,
    StandardDeviceAuthorizationResponse, TokenUrl,
};
use reqwest::Client;
use sketching::tracing_subscriber::layer::SubscriberExt;
use sketching::tracing_subscriber::util::SubscriberInitExt;
use sketching::tracing_subscriber::{fmt, EnvFilter};
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info};

async fn http_client(request: HttpRequest) -> Result<HttpResponse, oauth2::reqwest::Error> {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let method = reqwest::Method::from_str(request.method().as_str())
        .expect("this is definitely a bug but OK in an example!");

    let mut request_builder = client
        .request(method, request.uri().to_string())
        .body(request.body().to_vec());

    for (name, value) in request.headers().iter() {
        request_builder = request_builder.header(name.as_str(), value.as_bytes());
    }

    let response = client
        .execute(request_builder.build()?)
        .await
        .inspect_err(|err| {
            error!("Failed to query url {} error={:?}", request.uri(), err);
        })?;

    let status_code =
        StatusCode::from_u16(response.status().as_u16()).expect("This'll work, for an example");
    let headers: Vec<(oauth2::http::HeaderName, oauth2::http::HeaderValue)> = response
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

    let body = response.bytes().await?;
    info!("Response body: {:?}", String::from_utf8(body.to_vec()));

    let mut response = HttpResponse::new(body.to_vec());

    let headers_mut = response.headers_mut();
    headers_mut.extend(headers);

    *response.status_mut() = status_code;

    Ok(response)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
    let client = BasicClient::new(ClientId::new("device_code".to_string()))
        .set_token_uri(TokenUrl::from_url(
            format!("https://localhost:8443{}", OAUTH2_TOKEN_ENDPOINT).parse()?,
        ))
        .set_auth_uri(AuthUrl::from_url(
            format!("https://localhost:8443{}", OAUTH2_AUTHORISE).parse()?,
        ))
        .set_device_authorization_url(DeviceAuthorizationUrl::new(format!(
            "https://localhost:8443{}",
            OAUTH2_AUTHORISE_DEVICE
        ))?);

    info!("Getting details...");

    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()
        // .inspect_err(|err| error!("configuration error: {:?}", err))?
        .add_scope(Scope::new("read".to_string()))
        .request_async(&http_client)
        .await?;

    println!(
        "Open this URL in your browser: {}",
        match details.verification_uri_complete() {
            Some(uri) => uri.secret().as_str(),
            None => details.verification_uri().as_str(),
        }
    );

    println!("the code is {}", details.user_code().secret());

    let token_result = client
        .exchange_device_access_token(&details)
        .request_async(&http_client, tokio::time::sleep, None)
        .await?;
    println!("Result: {:?}", token_result);
    Ok(())
}
