use clap::Parser;
use sketching::tracing_subscriber::layer::SubscriberExt;
use sketching::tracing_subscriber::util::SubscriberInitExt;
use sketching::tracing_subscriber::{fmt, EnvFilter};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, error, info};
use axum::middleware;
use axum::response::Html;
use axum::routing::get;
use axum::response::{IntoResponse, Response};
use axum::Router;
use askama::Template;
use askama_web::WebTemplate;
use tower_http::services::{ServeDir, ServeFile};
use tower_sessions::cookie::{Key, SameSite};
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};
use url::Url;
use openidconnect::{
    reqwest,
};

mod auth_oidc;


#[derive(Template, WebTemplate)]
#[template(path = "index.html")]
struct IndexView {
    
}

async fn index_view() -> Response {
    IndexView { }
        .into_response()
}

async fn status_view() -> Html<&'static str> {
    Html(r#"Ok"#)
}

struct AppState {
    oidc: auth_oidc::ConfiguredClient,
    async_http_client: reqwest::Client,
}

#[derive(Debug, clap::Parser)]
#[clap(about = "OAuth2 Testing Tool")]
struct EnvConfig {
    #[arg(env = "CLIENT_SECRET")]
    client_secret: Option<String>,

    #[arg(default_value = "oauth2_test", env = "CLIENT_ID")]
    client_id: String,

    #[arg(default_value = "https://localhost:8443/", env = "KANIDM_URL")]
    kanidm_url: Url,

    #[structopt(
        default_value = "127.0.0.1:8843",
        env = "TLS_BIND_ADDRESS",
        long = "tlsaddr"
    )]
    /// Address to listen to for https
    tls_bind_addr: SocketAddr,

    #[structopt(
        env = "TLS_PEM_KEY",
        long = "tlskey",
        default_value = "/tmp/kanidm/key.pem"
    )]
    /// Path to the TLS Key file in PEM format.
    tls_pem_key: String,
    #[structopt(
        env = "TLS_PEM_CHAIN",
        long = "tlschain",
        default_value = "/tmp/kanidm/chain.pem"
    )]
    /// Path to the TLS Chain file in PEM format.
    tls_pem_chain: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let fmt_layer = fmt::layer().with_writer(std::io::stderr);

    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    sketching::tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    //
    let env_config = EnvConfig::parse();

    debug!(?env_config);

    rustls::crypto::aws_lc_rs::default_provider().install_default()
        .unwrap();

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
        env_config.tls_pem_chain, env_config.tls_pem_key)
        .await
        .expect("Failed to process pem files");

    // TODO: In future the oauth2/openidconnect crates will detach their
    // reqwest versions, but until then we have to use what they bundle.
    //
    // See: https://github.com/ramosbugs/oauth2-rs/tree/main/oauth2-reqwest

    let async_http_client = {
        let builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none());

        builder.build().unwrap()
    };

    let oidc = auth_oidc::configure(
        &env_config.client_id,
        env_config.client_secret.as_deref(),
        &format!("https://{}", env_config.tls_bind_addr),
        &env_config.kanidm_url,
        &async_http_client,
    ).await;

    let app_state = Arc::new(AppState {
        oidc,
        async_http_client,
    });

    let key = Key::generate();

    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(time::Duration::seconds(300)))
        .with_signed(key);

    let with_oidc_auth = Router::new()
        .route("/oidc/whoami", get(auth_oidc::whoami_view))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_oidc::middleware
        ));

    let with_oidc_unauth = Router::new()
        .route("/oidc/start_login", get(auth_oidc::login_view))
        .route("/oidc/response", get(auth_oidc::response_view));

    let with_unauth = Router::new()
        .route("/", get(index_view))
        .route("/_status", get(status_view));

    let app = Router::new()
        .merge(with_oidc_auth)
        .merge(with_oidc_unauth)
        .merge(with_unauth)
        .with_state(app_state.clone())
        .layer(session_layer);

    println!("listening on https://{}", env_config.tls_bind_addr);
    axum_server::bind_rustls(env_config.tls_bind_addr, tls_config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
