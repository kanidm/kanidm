use anyhow;
use kanidm_proto::constants::uri::{
    OAUTH2_AUTHORISE, OAUTH2_AUTHORISE_DEVICE, OAUTH2_TOKEN_ENDPOINT,
};
use oauth2::basic::BasicClient;
use oauth2::devicecode::StandardDeviceAuthorizationResponse;
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl,
    ClientId,
    // ClientSecret,
    DeviceAuthorizationUrl,
    Scope,
    // TokenResponse,
    TokenUrl,
};

fn main() -> anyhow::Result<()> {
    // kanidm system oauth2 create-public device_flow device_flow 'https://deviceauth'
    let client = BasicClient::new(
        ClientId::new("device_flow".to_string()),
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

    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()?
        .add_scope(Scope::new("read".to_string()))
        .request(http_client)?;

    println!(
        "Open this URL in your browser:\n{}\nand enter the code: {}",
        details.verification_uri().to_string(),
        details.user_code().secret().to_string()
    );

    let token_result = client.exchange_device_access_token(&details).request(
        http_client,
        std::thread::sleep,
        None,
    )?;
    println!("Result: {:?}", token_result);
    Ok(())
}
