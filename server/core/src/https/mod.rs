pub mod csp_headers;
mod manifest;
pub mod middleware;
pub mod oauth2;
mod tests;
pub mod ui;
pub mod v1;
pub mod v1_scim;

use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_write::QueryServerWriteV1;
use crate::config::ServerRole;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::*;
use axum::{body, Extension};
use axum::{middleware::from_fn_with_state, Router};
use axum_macros::FromRef;
use axum_sessions::{async_session, SameSite, SessionLayer};
use compact_jwt::JwsSigner;
use hyper::Body;
use kanidm_proto::v1::OperationError;
use kanidmd_lib::status::{StatusActor, StatusRequestEvent};
use serde::Serialize;
use std::path::PathBuf;
use std::{net::SocketAddr, str::FromStr};
use tokio::sync::broadcast;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use crate::CoreAction;

use self::middleware::KOpId;

#[derive(Clone, FromRef)]
pub struct ServerState {
    pub status_ref: &'static kanidmd_lib::status::StatusActor,
    pub qe_w_ref: &'static crate::actors::v1_write::QueryServerWriteV1,
    pub qe_r_ref: &'static crate::actors::v1_read::QueryServerReadV1,
    // Store the token management parts.
    pub jws_signer: compact_jwt::JwsSigner,
    pub jws_validator: compact_jwt::JwsValidator,
    // /// The SHA384 hashes of javascript files we're going to serve to users
    pub js_files: Vec<JavaScriptFile>,
    // pub(crate) trust_x_forward_for: bool,
}

impl ServerState {
    // fn get_current_auth_session_id(&self, session_id_header: String) -> Option<Uuid> {
    //     // We see if there is a signed header copy first.
    //     let kref = &self.jws_validator;
    //     self.header("X-KANIDM-AUTH-SESSION-ID")
    //         .and_then(|hv| {
    //             // Get the first header value.
    //             hv.get(0)
    //         })
    //         .and_then(|h| {
    //             // Take the token str and attempt to decrypt
    //             // Attempt to re-inflate a uuid from bytes.
    //             JwsUnverified::from_str(h.as_str()).ok()
    //         })
    //         .and_then(|jwsu| {
    //             jwsu.validate(&self.jws_validator)
    //                 .map(|jws: Jws<SessionId>| jws.into_inner().sessionid)
    //                 .ok()
    //         })
    //         // If not there, get from the cookie instead.
    //         .or_else(|| self.session().get::<Uuid>("auth-session-id"))
    // }
}

pub fn get_js_files(role: ServerRole) -> Vec<JavaScriptFile> {
    let mut js_files: Vec<JavaScriptFile> = Vec::new();

    if !matches!(role, ServerRole::WriteReplicaNoUI) {
        // let's set up the list of js module hashes
        {
            let filepath = "wasmloader.js";
            js_files.push(JavaScriptFile {
                filepath,
                hash: generate_integrity_hash(format!(
                    "{}/{}",
                    env!("KANIDM_WEB_UI_PKG_PATH").to_owned(),
                    filepath,
                ))
                .unwrap(),
                filetype: Some("module".to_string()),
            });
        }
        // let's set up the list of non-module hashes
        {
            let filepath = "external/bootstrap.bundle.min.js";
            js_files.push(JavaScriptFile {
                filepath,
                hash: generate_integrity_hash(format!(
                    "{}/{}",
                    env!("KANIDM_WEB_UI_PKG_PATH").to_owned(),
                    filepath,
                ))
                .unwrap(),
                filetype: None,
            });
        }
    };
    js_files
}

pub async fn create_https_server(
    address: String,
    domain: String,
    tlsconfig: Option<crate::config::TlsConfiguration>,
    role: ServerRole,
    // trust_x_forward_for: bool,
    cookie_key: [u8; 32],
    jws_signer: JwsSigner,
    status_ref: &'static StatusActor,
    qe_w_ref: &'static QueryServerWriteV1,
    qe_r_ref: &'static QueryServerReadV1,
    mut rx: broadcast::Receiver<CoreAction>,
) -> Result<tokio::task::JoinHandle<()>, ()> {
    let jws_validator = jws_signer
        .get_validator()
        .map_err(|e| {
            error!(?e, "Failed to get jws validator");
        })
        .unwrap();

    // TODO this whole session store is kinda cursed and doesn't work the way we need, I think?
    let store = async_session::CookieStore::new();
    // let secret = b"..."; // MUST be at least 64 bytes!
    let secret = format!("{:?}", cookie_key);
    let secret = secret.as_bytes(); // TODO the cookie/session secret needs to be longer?
    let session_layer = SessionLayer::new(store, secret)
        .with_cookie_name("kanidm-session")
        .with_session_ttl(None)
        .with_cookie_domain(domain)
        .with_same_site_policy(SameSite::Strict)
        .with_secure(true);

    let state = ServerState {
        status_ref,
        qe_w_ref,
        qe_r_ref,
        jws_signer,
        jws_validator,
        js_files: get_js_files(role.clone()),
    };

    let app = match role {
        ServerRole::WriteReplica | ServerRole::ReadOnlyReplica => {
            let pkg_path = PathBuf::from(env!("KANIDM_WEB_UI_PKG_PATH"));
            if !pkg_path.exists() {
                eprintln!(
                    "Couldn't find Web UI package path: ({}), quitting.",
                    env!("KANIDM_WEB_UI_PKG_PATH")
                );
                std::process::exit(1);
            }
            Router::new()
                .route("/", get(|| async { Redirect::temporary("/ui/login") }))
                .route("/ui", get(crate::https::ui::ui_handler))
                .route("/ui/", get(crate::https::ui::ui_handler))
                .route("/ui/*ui", get(crate::https::ui::ui_handler))
                .route("/manifest.webmanifest", get(manifest::manifest))
                .route("/robots.txt", get(|| async { todo!() }))
                .nest_service("/pkg", ServeDir::new(pkg_path))
                .layer(middleware::compression::new()) // TODO: this needs to be configured properly
        }
        ServerRole::WriteReplicaNoUI => Router::new(),
    };

    //  // == oauth endpoints.
    // TODO: turn this from a nest into a merge because state things are bad in nested routes
    let app = app.nest("/oauth2", oauth2::oauth2_route_setup(state.clone()));
    //  // == scim endpoints.
    let app = app
        .merge(v1_scim::scim_route_setup())
        .route("/v1/raw/create", post(v1::create))
        .route("/v1/raw/modify", post(v1::modify))
        .route("/v1/raw/delete", post(v1::delete))
        .route("/v1/raw/search", post(v1::search))
        .route("/v1/schema/", get(v1::schema_get))
        .route(
            "/v1/schema/attributetype",
            get(v1::schema_attributetype_get),
        )
        // .route("/v1/schema/attributetype", post(do_nothing))
        .route(
            "/v1/schema/attributetype/:id",
            get(v1::schema_attributetype_get_id),
        )
        // .route("/v1/schema/attributetype/:id", put(do_nothing).patch(do_nothing))
        .route(
            "/v1/schema/classtype",
            get(v1::schema_classtype_get), // .post(do_nothing)
        )
        .route(
            "/v1/schema/classtype/:id",
            get(v1::schema_classtype_get_id), // .put(do_nothing).patch(do_nothing)
        )
        .route("/v1/self/", get(v1::whoami))
        .route("/v1/self/_uat", get(v1::whoami_uat))
        .route("/v1/self/_attr/:attr", get(do_nothing))
        .route("/v1/self/_credential", get(do_nothing))
        .route("/v1/self/_credential/:cid/_lock", get(do_nothing))
        .route("/v1/self/_radius", get(do_nothing))
        .route("/v1/self/_radius", delete(do_nothing))
        .route("/v1/self/_radius", post(do_nothing))
        .route("/v1/self/_radius/_config", post(do_nothing))
        .route("/v1/self/_radius/_config/:token", get(do_nothing))
        .route("/v1/self/_radius/_config/:token/apple", get(do_nothing))
        // Applinks are the list of apps this account can access.
        .route("/v1/self/_applinks", get(v1::applinks_get))
        // Person routes
        .route("/v1/person/", get(v1::person_get))
        .route("/v1/person/", post(v1::person_post))
        .route(
            "/v1/person/:id",
            get(v1::person_id_get)
                .patch(v1::account_id_patch)
                .delete(v1::person_account_id_delete),
        )
        .route(
            "/v1/person/:id/_attr/:attr",
            get(v1::account_id_get_attr)
                .put(v1::account_id_put_attr)
                .post(v1::account_id_post_attr)
                .delete(v1::account_id_delete_attr),
        )
        //  .route("/v1/person/:id/_lock", get(do_nothing))
        //  .route("/v1/person/:id/_credential", get(do_nothing))
        .route(
            "/v1/person/:id/_credential/_status",
            get(v1::account_get_id_credential_status),
        )
        //  .route("/v1/person/:id/_credential/:cid/_lock", get(do_nothing))
        .route(
            "/v1/person/:id/_credential/_update",
            get(v1::account_get_id_credential_update),
        )
        .route(
            "/v1/person/:id/_credential/_update_intent",
            get(v1::account_get_id_credential_update_intent),
        )
        .route(
            "/v1/person/:id/_credential/_update_intent/:ttl",
            get(v1::account_get_id_credential_update_intent),
        )
        .route(
            "/v1/person/:id/_ssh_pubkeys",
            get(v1::account_get_id_ssh_pubkeys).post(v1::account_post_id_ssh_pubkey),
        )
        .route(
            "/v1/person/:id/_ssh_pubkeys/:tag",
            get(v1::account_get_id_ssh_pubkey_tag).delete(v1::account_delete_id_ssh_pubkey_tag),
        )
        .route(
            "/v1/person/:id/_radius",
            get(v1::account_get_id_radius)
                .post(v1::account_post_id_radius_regenerate)
                .delete(v1::account_delete_id_radius),
        )
        .route(
            "/v1/person/:id/_radius/_token",
            get(v1::account_get_id_radius_token),
        ) // TODO: make this cacheable
        .route("/v1/person/:id/_unix", post(v1::account_post_id_unix))
        .route(
            "/v1/person/:id/_unix/_credential",
            put(v1::account_put_id_unix_credential).delete(v1::account_delete_id_unix_credential),
        );

    //  // Service accounts
    let service_account_route = Router::new()
        .route(
            "/",
            get(v1::service_account_get).post(v1::service_account_post),
        )
        .route(
            "/:id",
            get(v1::service_account_id_get).delete(v1::service_account_id_delete),
        )
        .route(
            "/:id/_attr/:attr",
            get(v1::account_id_get_attr)
                .put(v1::account_id_put_attr)
                .post(v1::account_id_post_attr)
                .delete(v1::account_id_delete_attr),
        )
        //  // service_account_route.route("/:id/_lock", get(do_nothing));
        .route("/:id/_into_person", post(v1::service_account_into_person))
        .route(
            "/:id/_api_token",
            post(v1::service_account_api_token_post).get(v1::service_account_api_token_get),
        )
        .route(
            "/:id/_api_token/:token_id",
            delete(v1::service_account_api_token_delete),
        )
        .route("/:id/_credential", get(do_nothing))
        .route(
            "/:id/_credential/_generate",
            get(v1::service_account_credential_generate),
        )
        .route(
            "/:id/_credential/_status",
            get(v1::account_get_id_credential_status),
        )
        .route("/:id/_credential/:cid/_lock", get(do_nothing))
        .route(
            "/:id/_ssh_pubkeys",
            get(v1::account_get_id_ssh_pubkeys).post(v1::account_post_id_ssh_pubkey),
        )
        .route(
            "/:id/_ssh_pubkeys/:tag",
            get(v1::account_get_id_ssh_pubkey_tag).delete(v1::account_delete_id_ssh_pubkey_tag),
        )
        .route("/:id/_unix", post(v1::account_post_id_unix))
        .with_state(state.clone());

    let app = app.nest("/v1/service_account", service_account_route);

    // TODO: openapi/routemap returns
    //  routemap.push_self("/v1/routemap".to_string(), http_types::Method::Get);
    //  appserver.route("/v1/routemap").nest({let mut route_api = tide::with_state(routemap);route_api.route("/").get(do_routemap);route_api
    //  });
    //  // routemap_route.route("/", get(do_routemap));

    //  // ===  End routes

    // let app = app.nest("/v1/schema", schema_route);
    // let app = app.nest("/v1/raw", raw_route);
    let app = app
        // Shared account features only - mainly this is for unix-like features.
        .route(
            "/v1/account/:id/_unix/_auth",
            post(v1::account_post_id_unix_auth),
        )
        .route(
            "/v1/account/:id/_unix/_token",
            post(v1::account_get_id_unix_token), // TODO: make this cacheable
        )
        .route(
            "/v1/account/:id/_ssh_pubkeys",
            get(v1::account_get_id_ssh_pubkeys),
        )
        .route(
            "/v1/account/:id/_ssh_pubkeys/:tag",
            get(v1::account_get_id_ssh_pubkey_tag),
        )
        .route(
            "/v1/account/:id/_user_auth_token",
            get(v1::account_get_id_user_auth_token),
        )
        .route(
            "/v1/account/:id/_user_auth_token/:token_id",
            delete(v1::account_user_auth_token_delete),
        )
        .route(
            "/v1/credential/_exchange_intent",
            post(v1::credential_update_exchange_intent),
        )
        .route("/v1/credential/_status", post(v1::credential_update_status))
        .route("/v1/credential/_update", post(v1::credential_update_update))
        .route("/v1/credential/_commit", post(v1::credential_update_commit))
        .route("/v1/credential/_cancel", post(v1::credential_update_cancel))
        // domain-things
        .route("/v1/domain", get(v1::domain_get))
        .route(
            "/v1/domain/_attr/:attr",
            get(v1::domain_get_attr)
                .put(v1::domain_put_attr)
                .delete(v1::domain_delete_attr),
        )
        .route("/v1/group/:id/_unix", post(v1::group_post_id_unix))
        .route(
            "/v1/group/:id/_unix/_token",
            get(v1::group_get_id_unix_token),
        )
        .route("/v1/group/", get(v1::group_get).post(v1::group_post))
        .route(
            "/v1/group/:id",
            get(v1::group_id_get).delete(v1::group_id_delete),
        )
        .route(
            "/v1/group/:id/_attr/:attr",
            delete(v1::group_id_delete_attr)
                .get(v1::group_id_get_attr)
                .put(v1::group_id_put_attr)
                .post(v1::group_id_post_attr),
        )
        .with_state(state.clone())
        .route("/v1/system/", get(v1::system_get))
        .route(
            "/v1/system/_attr/:attr",
            get(v1::system_get_attr)
                .post(v1::system_post_attr)
                .delete(v1::system_delete_attr),
        )
        .route("/v1/recycle_bin/", get(v1::recycle_bin_get))
        .route("/v1/recycle_bin/:id", get(v1::recycle_bin_id_get))
        .route(
            "/v1/recycle_bin/:id/_revive",
            post(v1::recycle_bin_revive_id_post),
        )
        .route("/v1/access_profile/", get(do_nothing))
        .route("/v1/access_profile/:id", get(do_nothing))
        .route("/v1/access_profile/:id/_attr/:attr", get(do_nothing))
        .route("/v1/auth/valid", get(v1::auth_valid))
        .route("/v1/auth", post(v1::auth))
        .route("/v1/logout", get(v1::logout))
        .route("/v1/reauth", post(v1::reauth))
        .route("/status", get(status))
        .route_layer(from_fn_with_state(
            state.clone(),
            crate::https::csp_headers::cspheaders_layer,
        ))
        .layer(session_layer)
        .layer(axum::middleware::from_fn(middleware::version_middleware))
        .layer(axum::middleware::from_fn(middleware::kopid_end))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::kopid_start,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from_str(&address).unwrap();
    info!("Starting the web server...");

    Ok(tokio::spawn(async move {
        tokio::select! {
            Ok(action) = rx.recv() => {
                match action {
                    CoreAction::Shutdown => {},
                }
            }
            res = match tlsconfig {
                Some(tls_param) => {
                    let config = axum_server::tls_openssl::OpenSSLConfig::from_pem_file(
                        tls_param.chain.clone(),
                        tls_param.key.clone(),
                    )
                    .map_err(|e| {
                        error!("Failed to build TLS Listener for web server: {:?}", e);
                    }).unwrap();

                    tokio::spawn(
                        axum_server::bind_openssl(addr, config)
                        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                    )
                },
                None => {
                    tokio::spawn(axum_server::bind(addr).serve(app.into_make_service_with_connect_info::<SocketAddr>()))
                }
            } => {
                if let Err(err) = res {
                    error!("Web server exited with {:?}", err);
                }
            }
        };
        #[cfg(feature = "otel")]
        opentelemetry::global::shutdown_tracer_provider();
        info!("Stopped WebAcceptorActor");
    }))
}

/// Status endpoint used for healthchecks
pub async fn status(
    State(state): State<ServerState>,
    Extension(kopid): Extension<KOpId>,
) -> impl IntoResponse {
    let r = state
        .status_ref
        .handle_request(StatusRequestEvent {
            eventid: kopid.eventid,
        })
        .await;
    Response::new(format!("{}", r))
}

/// Generates the integrity hash for a file based on a filename
pub fn generate_integrity_hash(filename: String) -> Result<String, String> {
    let wasm_filepath = PathBuf::from(filename);
    match wasm_filepath.exists() {
        false => Err(format!(
            "Can't find {:?} to generate file hash",
            &wasm_filepath
        )),
        true => {
            let filecontents = match std::fs::read(&wasm_filepath) {
                Ok(value) => value,
                Err(error) => {
                    return Err(format!(
                        "Failed to read {:?}, skipping: {:?}",
                        wasm_filepath, error
                    ));
                }
            };
            let shasum =
                openssl::hash::hash(openssl::hash::MessageDigest::sha384(), &filecontents).unwrap();
            Ok(format!("sha384-{}", openssl::base64::encode_block(&shasum)))
        }
    }
}

#[derive(Clone)]
pub struct JavaScriptFile {
    // Relative to the pkg/ dir
    pub filepath: &'static str,
    // SHA384 hash of the file
    pub hash: String,
    // if it's a module add the "type"
    pub filetype: Option<String>,
}

impl JavaScriptFile {
    /// return the hash for use in CSP headers
    // pub fn as_csp_hash(self) -> String {
    //     self.hash
    // }

    /// returns a `<script>` HTML tag
    pub fn as_tag(self) -> String {
        let typeattr = match self.filetype {
            Some(val) => {
                format!(" type=\"{}\"", val.as_str())
            }
            _ => String::from(""),
        };
        format!(
            r#"<script src="/pkg/{}" integrity="{}"{}></script>"#,
            self.filepath, &self.hash, &typeattr,
        )
    }
}

/// Silly placeholder response for unimplemented routes
pub async fn do_nothing() -> impl IntoResponse {
    "Not implemented"
}

/// Convert any kind of Result<T, OperationError> into an axum response with a stable type
/// by JSON-encoding the body.
pub fn to_axum_response<T: Serialize>(v: Result<T, OperationError>) -> Response<Body> {
    match v {
        Ok(iv) => {
            let body = serde_json::to_string(&iv).unwrap();
            Response::builder().body(Body::from(body)).unwrap()
        }
        Err(e) => {
            (match &e {
                OperationError::NotAuthenticated | OperationError::SessionExpired => {
                    // https://datatracker.ietf.org/doc/html/rfc7235#section-4.1
                    Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .header("WWW-Authenticate", "Bearer")
                }
                OperationError::SystemProtectedObject | OperationError::AccessDenied => {
                    Response::builder().status(http::StatusCode::FORBIDDEN)
                }
                OperationError::NoMatchingEntries => {
                    Response::builder().status(http::StatusCode::NOT_FOUND)
                }
                OperationError::PasswordQuality(_)
                | OperationError::EmptyRequest
                | OperationError::SchemaViolation(_) => {
                    Response::builder().status(http::StatusCode::BAD_REQUEST)
                }
                _ => Response::builder().status(http::StatusCode::INTERNAL_SERVER_ERROR),
            })
            .body(body::Body::empty())
            .unwrap()
        }
    }
}
