pub mod csp_headers;
mod manifest;
pub mod middleware;
pub mod oauth2;
mod tests;
pub mod ui;
pub mod v1;
// pub mod v1_scim;

use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_write::QueryServerWriteV1;
use crate::config::ServerRole;
use axum::body;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{middleware::from_fn_with_state, Router};
use axum_macros::FromRef;
use axum_sessions::{async_session, SameSite, SessionLayer};
use compact_jwt::JwsSigner;
use http::{HeaderMap, HeaderValue};
use hyper::Body;
use kanidm_proto::v1::OperationError;
use kanidmd_lib::status::{StatusActor, StatusRequestEvent};
use serde::Serialize;
use std::path::PathBuf;
use std::{net::SocketAddr, str::FromStr};
use tokio::sync::broadcast;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::CoreAction;

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
    pub fn new_eventid(&self) -> (Uuid, String) {
        let eventid = sketching::tracing_forest::id();
        let hv = eventid.as_hyphenated().to_string();
        (eventid, hv)
    }

    pub fn header_kopid(&self, headers: &mut HeaderMap, hv: String) {
        headers.insert("X-KANIDM-OPID", HeaderValue::from_str(&hv).unwrap());
    }

    fn get_current_uat(&self, headers: HeaderMap) -> Option<String> {
        // Contact the QS to get it to validate wtf is up.
        // let kref = &self.state().bundy_handle;
        // self.session().get::<UserAuthToken>("uat")
        headers
            .get("Authorization")
            .and_then(|hv| {
                // Get the first header value.
                hv.to_str().ok()
            })
            .and_then(|h| {
                // Turn it to a &str, and then check the prefix
                h.strip_prefix("Bearer ")
            })
            .map(|s| s.to_string())
        // TODO: session thingies
        // .or_else(|| self.session().get::<String>("bearer"))
    }

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

    let store = async_session::CookieStore::new();
    // let secret = b"..."; // MUST be at least 64 bytes!
    let secret = format!("{:?}", cookie_key);
    let secret = secret.as_bytes(); // TODO lol the cookie/session secret needs to be longer?
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

    let app = Router::new().route("/status", get(status));
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
            app.route("/", get(|| async { Redirect::temporary("/ui/login") }))
                .route("/ui", get(crate::https::ui::ui_handler))
                .route("/ui/", get(crate::https::ui::ui_handler))
                .route("/ui/*ui", get(crate::https::ui::ui_handler))
                .route("/manifest.webmanifest", get(manifest::manifest))
                .route("/robots.txt", get(|| async { todo!() }))
                .nest_service("/pkg", ServeDir::new(pkg_path))
                .layer(middleware::compression::new()) // TODO: this needs to be configured properly
        }
        ServerRole::WriteReplicaNoUI => app,
    };

    // TODO: version middleware

    //  // == oauth endpoints.
    let app = app.nest("/oauth2", oauth2::oauth2_route_setup(state.clone()));

    //  // == scim endpoints.
    //  scim_route_setup(&mut appserver, &mut routemap);

    let raw_route = Router::new()
        .route("/create", post(v1::create))
        .route("/modify", post(v1::modify))
        .route("/delete", post(v1::delete))
        .route("/search", post(v1::search))
        // .route("/v1/auth", post(v1::auth))
        .route("/v1/auth/valid", get(v1::auth_valid))
        .route("/v1/logout", get(v1::logout))
        .route("/v1/reauth", post(v1::reauth))
        .with_state(state.clone());

    let app = app.nest("/v1/raw", raw_route);

    let schema_route = Router::new()
        .route("/", get(v1::schema_get))
        //  .route("/attributetype", get(schema_attributetype_get))
        .route("/attributetype", post(do_nothing))
        //  .route("/attributetype/:id", get(schema_attributetype_get_id))
        .route("/attributetype/:id", put(do_nothing))
        .route("/attributetype/:id", patch(do_nothing))
        //  .route("/classtype", get(schema_classtype_get))
        .route("/classtype", post(do_nothing))
        //  .route("/classtype/:id", get(schema_classtype_get_id))
        .route("/classtype/:id", put(do_nothing))
        .route("/classtype/:id", patch(do_nothing));
    let app = app.nest("/v1/schema", schema_route);

    let oauth2_route = Router::new()
        .route("/", get(oauth2::oauth2_get))
        .route("/:rs_name", get(oauth2::oauth2_id_get))
        .route("/:rs_name", patch(oauth2::oauth2_id_patch))
        // TODO: #1787 work out what this comment means: It's not really possible to replace this wholesale.// ..put(xxxx&mut routemap, oauth2_id_put, patch(oauth2_id_patch), delete(oauth2_id_delete));
        .route(
            "/:rs_name/_basic_secret",
            get(oauth2::oauth2_id_get_basic_secret),
        )
        .route("/_basic", post(oauth2::oauth2_basic_post))
        .with_state(state.clone());

    //  oauth2_route.route("/:id/_scopemap/:group", post(oauth2_id_scopemap_post), delete(oauth2_id_scopemap_delete));

    //  oauth2_route.route("/:id/_sup_scopemap/:group", post(oauth2_id_sup_scopemap_post), delete(oauth2_id_sup_scopemap_delete));
    let app = app.nest("/v1/oauth2", oauth2_route);

    let self_route = Router::new()
        .route("/", get(v1::whoami))
        .route("/_uat", get(v1::whoami_uat))
        .route("/_attr/:attr", get(do_nothing))
        .route("/_credential", get(do_nothing))
        .route("/_credential/:cid/_lock", get(do_nothing))
        .route("/_radius", get(do_nothing))
        .route("/_radius", delete(do_nothing))
        .route("/_radius", post(do_nothing))
        .route("/_radius/_config", post(do_nothing))
        .route("/_radius/_config/:token", get(do_nothing))
        .route("/_radius/_config/:token/apple", get(do_nothing))
        //  // Applinks are the list of apps this account can access.
        .route("/_applinks", get(v1::applinks_get))
        .with_state(state.clone());
    let app = app.nest("/v1/self", self_route);

    let person_route = Router::new()
        .route("/", get(v1::person_get))
        .route("/", post(v1::person_post))
        // .route("/:id", get(v1::person_id_get))
        // .route("/:id",  patch(v1::account_id_patch))
        // .route("/:id", delete(v1::person_account_id_delete))
        // .route("/:id/_attr/:attr", get(v1::account_id_get_attr))
        // .route("/:id/_attr/:attr", put(v1::account_id_put_attr))
        // .route("/:id/_attr/:attr", post(v1::account_id_post_attr))
        // .route("/:id/_attr/:attr", delete(v1::account_id_delete_attr))
        .with_state(state.clone());
    let app = app.nest("/v1/person", person_route);

    //  // person_route.route("/:id/_lock", get(do_nothing));
    //  // person_route.route("/:id/_credential", get(do_nothing));
    //  person_route.route("/:id/_credential/_status", get(account_get_id_credential_status));
    //  // person_route.route("/:id/_credential/:cid/_lock", get(do_nothing));
    //  person_route.route("/:id/_credential/_update", get(account_get_id_credential_update));
    //  person_route.route("/:id/_credential/_update_intent", get(account_get_id_credential_update_intent));
    //  person_route.route("/:id/_credential/_update_intent/:ttl", get(account_get_id_credential_update_intent));

    //  person_route.route("/:id/_ssh_pubkeys", get(account_get_id_ssh_pubkeys), post(account_post_id_ssh_pubkey));
    //  person_route.route("/:id/_ssh_pubkeys/:tag", get(account_get_id_ssh_pubkey_tag), delete(account_delete_id_ssh_pubkey_tag));

    //  person_route.route("/:id/_radius", get(account_get_id_radius), post(account_post_id_radius_regenerate), delete(account_delete_id_radius));

    //  person_route.route("/:id/_unix", post(account_post_id_unix));
    //  person_route.route("/:id/_unix/_credential", put(account_put_id_unix_credential), delete(account_delete_id_unix_credential));

    //  // Service accounts

    let service_account_route = Router::new()
        .route("/", get(v1::service_account_get))
        // , post(service_account_post));
        //  service_account_route.route("/:id", get(service_account_id_get), patch(account_id_patch), delete(service_account_id_delete));
        //  service_account_route.route("/:id/_attr/:attr", get(account_id_get_attr),
        // put(account_id_put_attr),
        // post(account_id_post_attr),
        // delete(account_id_delete_attr));
        //  // service_account_route.route("/:id/_lock", get(do_nothing));
        //  service_account_route.route("/:id/_into_person", post(service_account_into_person));
        //  service_account_route.route("/:id/_api_token", post(service_account_api_token_post),
        // get(service_account_api_token_get));
        //  service_account_route.route("/:id/_api_token/:token_id", delete(service_account_api_token_delete));
        //  // service_account_route.route("/:id/_credential", get(do_nothing));
        //  service_account_route.route("/:id/_credential/_generate", get(service_account_credential_generate));
        //  service_account_route.route("/:id/_credential/_status"
        // , get(account_get_id_credential_status));
        //  // service_account_route.route("/:id/_credential/:cid/_lock", get(do_nothing));
        //  service_account_route.route("/:id/_ssh_pubkeys", get(account_get_id_ssh_pubkeys)
        // , post(account_post_id_ssh_pubkey));
        //  service_account_route.route("/:id/_ssh_pubkeys/:tag", get(account_get_id_ssh_pubkey_tag)
        // , delete(account_delete_id_ssh_pubkey_tag));
        //  service_account_route.route("/:id/_unix", post(account_post_id_unix));
        .with_state(state.clone());
    let app = app.nest("/v1/service_account", service_account_route);

    //  // Shared account features only - mainly this is for unix-like
    //  // features.
    let account_route = Router::new()
        //  .route("/:id/_unix/_auth", post(v1::account_post_id_unix_auth));
        //  .route("/:id/_ssh_pubkeys", get(v1::account_get_id_ssh_pubkeys));
        //  .route("/:id/_ssh_pubkeys/:tag", get(v1::account_get_id_ssh_pubkey_tag));
        //  .route("/:id/_user_auth_token", get(v1::account_get_id_user_auth_token));
        //  .route("/:id/_user_auth_token/:token_id", delete(v1::account_user_auth_token_delete));
        .with_state(state.clone());
    let app = app.nest("/v1/account", account_route);

    //  // Credential updates, don't require the account id.
    let cred_route = Router::new()
        //  .route("/_exchange_intent", post(v1::credential_update_exchange_intent))
        //  .route("/_status", post(v1::credential_update_status))
        //  .route("/_update", post(v1::credential_update_update))
        //  .route("/_cancel", post(v1::credential_update_cancel))
        //  .route("/_commit", post(v1::credential_update_commit))
        .with_state(state.clone());
    let app = app.nest("/v1/credential", cred_route);

    let group_route = Router::new()
        .route("/:id/_unix", post(v1::group_post_id_unix))
        .with_state(state.clone());
    let app = app.nest("/v1/group", group_route);
    //  group_route.route("/", get(group_get), post(group_post));
    //  group_route.route("/:id", get(group_id_get), delete(group_id_delete));
    //  group_route.route("/:id/_attr/:attr", delete(group_id_delete_attr), get(group_id_get_attr), put(group_id_put_attr), post(group_id_post_attr));

    let domain_route = Router::new()
        .route("/", get(v1::domain_get))
        .route("/_attr/:attr", get(v1::domain_get_attr))
        // .route("/_attr/:attr", put(domain_put_attr))
        .route("/_attr/:attr", delete(v1::domain_delete_attr))
        .with_state(state.clone());
    let app = app.nest("/v1/domain", domain_route);

    let system_route = Router::new()
        // .route("/", get(v1::system_get))
        .route("/_attr/:attr", get(v1::system_get_attr))
        .route("/_attr/:attr", post(v1::system_post_attr))
        .route("/_attr/:attr", delete(v1::system_delete_attr))
        .with_state(state.clone());
    let app = app.nest("/v1/system", system_route);

    let recycle_route = Router::new()
        .route("/", get(v1::recycle_bin_get))
        .route("/:id", get(v1::recycle_bin_id_get))
        .route("/:id/_revive", post(v1::recycle_bin_revive_id_post))
        .with_state(state.clone());
    let app = app.nest("/v1/recycle_bin", recycle_route);

    let accessprof_route = Router::new()
        .route("/", get(do_nothing))
        .route("/:id", get(do_nothing))
        .route("/:id/_attr/:attr", get(do_nothing))
        .with_state(state.clone());
    let app = app.nest("/v1/access_profile", accessprof_route);

    //  routemap.push_self("/v1/routemap".to_string(), http_types::Method::Get);
    //  appserver.route("/v1/routemap").nest({let mut route_api = tide::with_state(routemap);route_api.route("/").get(do_routemap);route_api
    //  });
    //  // routemap_route.route("/", get(do_routemap));

    //  // ===  End routes

    let app = app
        .nest("/v1", crate::https::v1::new(state.clone()))
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
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    // let opt_tls_params = Some(tlsconfig.clone());

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
                        axum_server::bind_openssl(addr, config).serve(app.into_make_service())
                    )
                },
                None => {
                    tokio::spawn(axum_server::bind(addr).serve(app.into_make_service()))
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

    // Ok(handle)
}

pub async fn status(State(state): State<ServerState>) -> impl IntoResponse {
    // We ignore the body in this req
    let (eventid, hvalue) = state.new_eventid();
    let r = state
        .status_ref
        .handle_request(StatusRequestEvent { eventid })
        .await;
    let mut res = Response::new(format!("{}", r));
    let headers = res.headers_mut();
    state.header_kopid(headers, hvalue);
    res
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

#[test]
fn test_javscriptfile() {
    // make sure it outputs what we think it does
    use JavaScriptFile;
    let jsf = JavaScriptFile {
        filepath: "wasmloader.js",
        hash: "sha384-1234567890".to_string(),
        filetype: Some("module".to_string()),
    };
    assert_eq!(
        jsf.as_tag(),
        r#"<script src="/pkg/wasmloader.js" integrity="sha384-1234567890" type="module"></script>"#
    );
    let jsf = JavaScriptFile {
        filepath: "wasmloader.js",
        hash: "sha384-1234567890".to_string(),
        filetype: None,
    };
    assert_eq!(
        jsf.as_tag(),
        r#"<script src="/pkg/wasmloader.js" integrity="sha384-1234567890"></script>"#
    );
}

pub async fn do_nothing() -> impl IntoResponse {
    "Not implemented"
}

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
