use crate::AppState;
use askama::Template;
use askama_web::WebTemplate;
use axum::body::Body;
use axum::{
    extract::{Query, State},
    http::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    Form, Json,
};
use chrono::{DateTime, Utc};
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest, AccessToken, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;
use tower_sessions::Session;
use tracing::{debug, error, info, trace};
use url::Url;

// This is disgusting. Thanks openidconnect.
pub type ConfiguredClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub(crate) async fn middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let session = (&request).extensions().get::<Session>().unwrap();
    let maybe_user_token: Option<User> = { session.get("token").await.unwrap() };

    let uwu_senpai_redir_me_pls = request
        .uri()
        .path_and_query()
        .map(|path| path.as_str().to_string());

    if let Some(uwu_senpai_redir_me_pls) = uwu_senpai_redir_me_pls {
        if let Err(e) = session.insert("uwu_senpai", uwu_senpai_redir_me_pls).await {
            error!(?e, "Failed to setup uri return path");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };
    }

    let current_user = if let Some(current_user) = maybe_user_token {
        current_user
    } else {
        return Redirect::to("/oidc/login").into_response();
    };

    let now = chrono::offset::Utc::now();
    if current_user.exp > now {
        info!(
            "authenticated session found remaining {}",
            current_user.exp - now
        );
        request.extensions_mut().insert(current_user);
        next.run(request).await
    } else if let Some(refresh_token) = current_user.refresh_token.as_ref() {
        info!("expired session, attempting refresh");

        if let Err(err) = session.remove_value("token").await {
            error!(?err, "oauth2 token request failure");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }

        let nonce: Nonce = if let Some(n) = session.get("nonce").await.unwrap() {
            n
        } else {
            error!("nonce");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        };

        let r_token = state
            .oidc
            .exchange_refresh_token(&refresh_token)
            .expect("Unable to proceed with exchange")
            .request_async(&state.async_http_client)
            .await;

        let token = match r_token {
            Ok(tr) => tr,
            Err(e) => {
                error!("oauth2 token request failure - {:?}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        let id_tok = match token.id_token() {
            Some(id_tok) => id_tok,
            None => {
                error!("oidc id_token not provided");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        let claims = match id_tok.claims(&state.oidc.id_token_verifier(), &nonce) {
            Ok(c) => c,
            Err(e) => {
                error!(
                    ?e,
                    "Failed to access id_token claims - token verification failed"
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

        // Do I care about ATH? It's meant to check if an access token was swapped out, but nothing
        // checks if the refresh token was?

        let user = User {
            sub: claims.subject().as_str().to_owned(),
            /*
            // I'm not actually sure it's possible to access this claim .... :(
            displayname: claims.name()
                .unwrap()
                ,
            */
            // email: claims.email().unwrap().as_str().to_owned(),
            username: claims.preferred_username().unwrap().as_str().to_owned(),
            exp: claims.expiration(),
            access_token: token.access_token().to_owned(),
            refresh_token: token.refresh_token().cloned(),
        };

        if let Err(e) = session.insert("token", user).await {
            error!(?e, "Failed to setup request session");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        } else {
            // New token valid, run the request.
            next.run(request).await
        }
    } else {
        info!("no refresh token, reauthenticate pls");
        Redirect::to("/oidc/login").into_response()
    }
}

#[derive(Template, WebTemplate)]
#[template(path = "oidc.html")]
struct LoginView {}

pub async fn login_view(State(state): State<Arc<AppState>>, session: Session) -> Response {
    LoginView {}.into_response()
}

#[derive(Deserialize, Debug)]
pub struct FormLoginOptions {
    scopes: String,
    max_age: String,
}

#[axum::debug_handler]
pub(crate) async fn login_post(
    State(state): State<Arc<AppState>>,
    session: Session,
    Form(form_data): Form<FormLoginOptions>,
) -> Result<Response, StatusCode> {
    let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

    trace!(?session);
    debug!(?form_data);
    debug!("challenge -> {:?}", pkce_code_challenge.as_str());
    debug!("secret -> {:?}", pkce_code_verifier.secret());

    let oidc = state.oidc.authorize_url(
        CoreAuthenticationFlow::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );

    let max_age = u64::from_str(&form_data.max_age).ok();

    let oidc = max_age.into_iter().fold(oidc, |oidc, max_age| {
        oidc.set_max_age(std::time::Duration::from_secs(max_age))
    });

    let oidc = form_data
        .scopes
        .split_ascii_whitespace()
        .fold(oidc, |oidc, scope| {
            oidc.add_scope(Scope::new(scope.to_string()))
        });

    let (auth_url, csrf_token, nonce) = oidc.set_pkce_challenge(pkce_code_challenge).url();

    // We can stash the verifier in the session.
    session
        .insert("pkce_code_verifier", &pkce_code_verifier)
        .await
        .unwrap();
    session.insert("csrf_token", &csrf_token).await.unwrap();
    session.insert("nonce", &nonce).await.unwrap();

    info!("starting oauth");

    Ok(Redirect::to(auth_url.as_str()).into_response())
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct OauthResp {
    state: CsrfToken,
    code: AuthorizationCode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct User {
    sub: String,
    // displayname: String,
    // email: String,
    username: String,
    exp: DateTime<Utc>,
    access_token: AccessToken,
    refresh_token: Option<RefreshToken>,
}

#[axum::debug_handler]
pub(crate) async fn response_view(
    State(state): State<Arc<AppState>>,
    session: Session,
    Query(params): Query<OauthResp>,
) -> Result<Response, StatusCode> {
    trace!(?session);
    debug!("params -> {:?}", params);

    // get the verifier and csrf token
    let pkce_code_verifier: PkceCodeVerifier = session
        .get("pkce_code_verifier")
        .await
        .unwrap()
        .ok_or_else(|| {
            error!("pkce code verifier was not found");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    debug!("secret -> {:?}", pkce_code_verifier.secret());

    let csrf_token: CsrfToken = session.get("csrf_token").await.unwrap().ok_or_else(|| {
        error!("csrf");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let nonce: Nonce = session.get("nonce").await.unwrap().ok_or_else(|| {
        error!("nonce");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Compare state to csrf token.
    if csrf_token.secret() != params.state.secret() {
        error!("csrf validation");
        return Err(StatusCode::CONFLICT);
    }

    let r_token = state
        .oidc
        .exchange_code(params.code)
        .expect("Unable to proceed with exchange")
        .set_pkce_verifier(pkce_code_verifier)
        .request_async(&state.async_http_client)
        .await;

    let token = match r_token {
        Ok(tr) => tr,
        Err(e) => {
            error!("oauth2 token request failure - {:?}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let id_tok = match token.id_token() {
        Some(id_tok) => id_tok,
        None => {
            error!("oidc id_token not provided");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let claims = match id_tok.claims(&state.oidc.id_token_verifier(), &nonce) {
        Ok(c) => c,
        Err(e) => {
            error!(
                ?e,
                "Failed to access id_token claims - token verification failed"
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Do I care about ATH? It's meant to check if an access token was swapped out, but nothing
    // checks if the refresh token was?

    let user = User {
        sub: claims.subject().as_str().to_owned(),
        /*
        // I'm not actually sure it's possible to access this claim .... :(
        displayname: claims.name()
            .unwrap()
            ,
        */
        // email: claims.email().unwrap().as_str().to_owned(),
        username: claims.preferred_username().unwrap().as_str().to_owned(),
        exp: claims.expiration(),
        access_token: token.access_token().to_owned(),
        refresh_token: token.refresh_token().cloned(),
    };

    if let Err(e) = session.insert("token", user).await {
        error!(?e, "Failed to setup request session");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    let maybe_uwu_senpai: Option<String> = { session.get("uwu_senpai").await.unwrap() };

    if let Some(uwu_senpai) = maybe_uwu_senpai {
        Ok(Redirect::to(&uwu_senpai).into_response())
    } else {
        Ok(Redirect::to("/oidc/whoami").into_response())
    }
}

pub(crate) async fn whoami_view(
    session: Session,
    // State(state): State<Arc<AppState>>,
) -> Response {
    let maybe_user_token: Option<User> = session.get("token").await.unwrap();

    let current_user = if let Some(current_user) = maybe_user_token {
        current_user
    } else {
        return Redirect::to("/oidc/login").into_response();
    };

    Json(current_user.username).into_response()
}

pub async fn configure(
    client_id: &str,
    client_secret: Option<&str>,
    client_url: &str,
    kanidm_url: &Url,
    async_http_client: &reqwest::Client,
) -> ConfiguredClient {
    let mut discovery_url = kanidm_url.clone();
    discovery_url
        .path_segments_mut()
        .unwrap()
        .extend(["oauth2", "openid", client_id]);

    let issuer = IssuerUrl::new(discovery_url.to_string()).expect("Unable to parse issuer url");

    let redir_url = RedirectUrl::new(format!("{}/oidc/response", client_url))
        .expect("Unable to parse client url");

    debug!(discover_url = ?issuer);

    let provider_metadata = CoreProviderMetadata::discover_async(issuer, async_http_client)
        .await
        .expect("Unable to discover oidc provider");

    debug!(?provider_metadata);

    CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id.to_string()),
        client_secret.map(|s| ClientSecret::new(s.to_string())),
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(redir_url)
}
