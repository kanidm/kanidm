pub mod csp_headers;
mod manifest;
pub mod middleware;
pub mod ui;
pub mod v1;
// pub mod oauth2;
// pub mod v1_scim;

use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::post;
use axum::{middleware::from_fn_with_state, routing::get, Router};
use axum_macros::FromRef;
use axum_sessions::{async_session, SessionLayer};
use compact_jwt::JwsSigner;
use http::{HeaderMap, HeaderValue};
use kanidmd_lib::status::{StatusActor, StatusRequestEvent};
use std::path::PathBuf;
use std::{net::SocketAddr, str::FromStr};
use tokio::sync::broadcast;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_write::QueryServerWriteV1;
use crate::config::ServerRole;

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
    tlsconfig: crate::config::TlsConfiguration,
    role: ServerRole,
    // trust_x_forward_for: bool,
    cookie_key: [u8; 32],
    jws_signer: JwsSigner,
    status_ref: &'static StatusActor,
    qe_w_ref: &'static QueryServerWriteV1,
    qe_r_ref: &'static QueryServerReadV1,
    mut rx: broadcast::Receiver<CoreAction>,
) -> Result<tokio::task::JoinHandle<()>, ()> {
    let jws_validator = jws_signer.get_validator().map_err(|e| {
        error!(?e, "Failed to get jws validator");
    })?;

    let store = async_session::MemoryStore::new();
    // let secret = b"..."; // MUST be at least 64 bytes!
    let secret = format!("{:?}", cookie_key);
    let secret = secret.as_bytes(); // TODO lol the cookie/session secret needs to be longer?
    let session_layer = SessionLayer::new(store, secret);

    let state = ServerState {
        status_ref,
        qe_w_ref,
        qe_r_ref,
        jws_signer,
        jws_validator,
        js_files: get_js_files(role.clone()),
    };

    let config = axum_server::tls_openssl::OpenSSLConfig::from_pem_file(
        tlsconfig.chain.clone(),
        tlsconfig.key.clone(),
    )
    .unwrap();

    let app = Router::new();

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
            app.route("/", get(|| async { Redirect::temporary("/ui/") }))
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
    //  oauth2_route_setup(&mut appserver, &mut routemap);

    //  // == scim endpoints.
    //  scim_route_setup(&mut appserver, &mut routemap);

    let raw_route = Router::new()
        .route("/create", post(v1::create))
        .route("/modify", post(v1::modify))
        .route("/delete", post(v1::delete))
        .route("/search", post(v1::search))
        .with_state(state.clone());

    let app = app.nest("/v1/raw", raw_route);
    //  // appserver.route("/v1/auth").mapped_post(&mut routemap, auth);
    //  appserver
    //      .route("/v1/auth/valid")
    //      .mapped_get(&mut routemap, auth_valid);
    //  appserver
    //      .route("/v1/reauth")
    //      .mapped_post(&mut routemap, reauth);

    //  appserver.route("/v1/logout").mapped_get(&mut routemap, logout);

    //  let mut schema_route = appserver.route("/v1/schema");
    //  schema_route.route("/").mapped_get(&mut routemap, schema_get);
    //  schema_route
    //      .route("/attributetype")
    //      .mapped_get(&mut routemap, schema_attributetype_get)
    //      // .mapped_post(&mut routemap, do_nothing)
    //      ;
    //  schema_route
    //      .route("/attributetype/:id")
    //      .mapped_get(&mut routemap, schema_attributetype_get_id)
    //      // .mapped_put(&mut routemap, do_nothing)
    //      // .mapped_patch(&mut routemap, do_nothing)
    //      ;

    //  schema_route
    //      .route("/classtype")
    //      .mapped_get(&mut routemap, schema_classtype_get)
    //      // .mapped_post(&mut routemap, do_nothing)
    //      ;
    //  schema_route
    //      .route("/classtype/:id")
    //      .mapped_get(&mut routemap, schema_classtype_get_id)
    //      // .mapped_put(&mut routemap, do_nothing)
    //      // .mapped_patch(&mut routemap, do_nothing)
    //      ;

    //  let mut oauth2_route = appserver.route("/v1/oauth2");
    //  oauth2_route.route("/").mapped_get(&mut routemap, oauth2_get);

    //  oauth2_route
    //      .route("/_basic")
    //      .mapped_post(&mut routemap, oauth2_basic_post);

    //  oauth2_route
    //      .route("/:rs_name")
    //      .mapped_get(&mut routemap, oauth2_id_get)
    //      // It's not really possible to replace this wholesale.
    //      // .mapped_put(&mut routemap, oauth2_id_put)
    //      .mapped_patch(&mut routemap, oauth2_id_patch)
    //      .mapped_delete(&mut routemap, oauth2_id_delete);

    //  oauth2_route
    //      .route("/:rs_name/_basic_secret")
    //      .mapped_get(&mut routemap, oauth2_id_get_basic_secret);

    //  oauth2_route
    //      .route("/:id/_scopemap/:group")
    //      .mapped_post(&mut routemap, oauth2_id_scopemap_post)
    //      .mapped_delete(&mut routemap, oauth2_id_scopemap_delete);

    //  oauth2_route
    //      .route("/:id/_sup_scopemap/:group")
    //      .mapped_post(&mut routemap, oauth2_id_sup_scopemap_post)
    //      .mapped_delete(&mut routemap, oauth2_id_sup_scopemap_delete);

    let self_route = Router::new()
        .route("/", get(v1::whoami))
        .route("/_uat", get(v1::whoami_uat))
        .with_state(state.clone());
    let app = app.nest("/v1/self", self_route);

    //  // self_route
    //  //     .route("/_attr/:attr")
    //  //     .mapped_get(&mut routemap, do_nothing);
    //  // self_route
    //  //     .route("/_credential")
    //  //     .mapped_get(&mut routemap, do_nothing);

    //  // self_route
    //  //     .route("/_credential/:cid/_lock")
    //  //     .mapped_get(&mut routemap, do_nothing);

    //  // self_route
    //  //     .route("/_radius")
    //  //     .mapped_get(&mut routemap, do_nothing)
    //  //     .mapped_delete(&mut routemap, do_nothing)
    //  //     .mapped_post(&mut routemap, do_nothing);

    //  // self_route
    //  //     .route("/_radius/_config")
    //  //     .mapped_post(&mut routemap, do_nothing);
    //  // self_route
    //  //     .route("/_radius/_config/:token")
    //  //     .mapped_get(&mut routemap, do_nothing);
    //  // self_route
    //  //     .route("/_radius/_config/:token/apple")
    //  //     .mapped_get(&mut routemap, do_nothing);

    //  // Applinks are the list of apps this account can access.
    //  self_route
    //      .route("/_applinks")
    //      .mapped_get(&mut routemap, applinks_get);

    let person_route = Router::new().with_state(state.clone());
    let app = app.nest("/v1/person", person_route);
    //  person_route
    //      .route("/")
    //      .mapped_get(&mut routemap, person_get)
    //      .mapped_post(&mut routemap, person_post);
    //  person_route
    //      .route("/:id")
    //      .mapped_get(&mut routemap, person_id_get)
    //      .mapped_patch(&mut routemap, account_id_patch)
    //      .mapped_delete(&mut routemap, person_account_id_delete);
    //  person_route
    //      .route("/:id/_attr/:attr")
    //      .mapped_get(&mut routemap, account_id_get_attr)
    //      .mapped_put(&mut routemap, account_id_put_attr)
    //      .mapped_post(&mut routemap, account_id_post_attr)
    //      .mapped_delete(&mut routemap, account_id_delete_attr);

    //  // person_route
    //  //     .route("/:id/_lock")
    //  //     .mapped_get(&mut routemap, do_nothing);
    //  // person_route
    //  //     .route("/:id/_credential")
    //  //     .mapped_get(&mut routemap, do_nothing);
    //  person_route
    //      .route("/:id/_credential/_status")
    //      .mapped_get(&mut routemap, account_get_id_credential_status);
    //  // person_route
    //  //     .route("/:id/_credential/:cid/_lock")
    //  //     .mapped_get(&mut routemap, do_nothing);
    //  person_route
    //      .route("/:id/_credential/_update")
    //      .mapped_get(&mut routemap, account_get_id_credential_update);
    //  person_route
    //      .route("/:id/_credential/_update_intent")
    //      .mapped_get(&mut routemap, account_get_id_credential_update_intent);
    //  person_route
    //      .route("/:id/_credential/_update_intent/:ttl")
    //      .mapped_get(&mut routemap, account_get_id_credential_update_intent);

    //  person_route
    //      .route("/:id/_ssh_pubkeys")
    //      .mapped_get(&mut routemap, account_get_id_ssh_pubkeys)
    //      .mapped_post(&mut routemap, account_post_id_ssh_pubkey);
    //  person_route
    //      .route("/:id/_ssh_pubkeys/:tag")
    //      .mapped_get(&mut routemap, account_get_id_ssh_pubkey_tag)
    //      .mapped_delete(&mut routemap, account_delete_id_ssh_pubkey_tag);

    //  person_route
    //      .route("/:id/_radius")
    //      .mapped_get(&mut routemap, account_get_id_radius)
    //      .mapped_post(&mut routemap, account_post_id_radius_regenerate)
    //      .mapped_delete(&mut routemap, account_delete_id_radius);

    //  person_route
    //      .route("/:id/_unix")
    //      .mapped_post(&mut routemap, account_post_id_unix);
    //  person_route
    //      .route("/:id/_unix/_credential")
    //      .mapped_put(&mut routemap, account_put_id_unix_credential)
    //      .mapped_delete(&mut routemap, account_delete_id_unix_credential);

    //  // Service accounts

    let service_account_route = Router::new().with_state(state.clone());
    //  service_account_route
    //      .route("/")
    //      .mapped_get(&mut routemap, service_account_get)
    //      .mapped_post(&mut routemap, service_account_post);
    //  service_account_route
    //      .route("/:id")
    //      .mapped_get(&mut routemap, service_account_id_get)
    //      .mapped_patch(&mut routemap, account_id_patch)
    //      .mapped_delete(&mut routemap, service_account_id_delete);
    //  service_account_route
    //      .route("/:id/_attr/:attr")
    //      .mapped_get(&mut routemap, account_id_get_attr)
    //      .mapped_put(&mut routemap, account_id_put_attr)
    //      .mapped_post(&mut routemap, account_id_post_attr)
    //      .mapped_delete(&mut routemap, account_id_delete_attr);

    //  // service_account_route
    //  //     .route("/:id/_lock")
    //  //     .mapped_get(&mut routemap, do_nothing);

    //  service_account_route
    //      .route("/:id/_into_person")
    //      .mapped_post(&mut routemap, service_account_into_person);

    //  service_account_route
    //      .route("/:id/_api_token")
    //      .mapped_post(&mut routemap, service_account_api_token_post)
    //      .mapped_get(&mut routemap, service_account_api_token_get);
    //  service_account_route
    //      .route("/:id/_api_token/:token_id")
    //      .mapped_delete(&mut routemap, service_account_api_token_delete);

    //  // service_account_route
    //  //     .route("/:id/_credential")
    //  //     .mapped_get(&mut routemap, do_nothing);
    //  service_account_route
    //      .route("/:id/_credential/_generate")
    //      .mapped_get(&mut routemap, service_account_credential_generate);
    //  service_account_route
    //      .route("/:id/_credential/_status")
    //      .mapped_get(&mut routemap, account_get_id_credential_status);
    //  // service_account_route
    //  //     .route("/:id/_credential/:cid/_lock")
    //  //     .mapped_get(&mut routemap, do_nothing);

    //  service_account_route
    //      .route("/:id/_ssh_pubkeys")
    //      .mapped_get(&mut routemap, account_get_id_ssh_pubkeys)
    //      .mapped_post(&mut routemap, account_post_id_ssh_pubkey);
    //  service_account_route
    //      .route("/:id/_ssh_pubkeys/:tag")
    //      .mapped_get(&mut routemap, account_get_id_ssh_pubkey_tag)
    //      .mapped_delete(&mut routemap, account_delete_id_ssh_pubkey_tag);

    //  service_account_route
    //      .route("/:id/_unix")
    //      .mapped_post(&mut routemap, account_post_id_unix);
    let app = app.nest("/v1/service_account", service_account_route);

    //  // Shared account features only - mainly this is for unix-like
    //  // features.
    let account_route = Router::new().with_state(state.clone());
    let app = app.nest("/v1/account", account_route);
    //  account_route
    //      .route("/:id/_unix/_auth")
    //      .mapped_post(&mut routemap, account_post_id_unix_auth);
    //  account_route
    //      .route("/:id/_ssh_pubkeys")
    //      .mapped_get(&mut routemap, account_get_id_ssh_pubkeys);
    //  account_route
    //      .route("/:id/_ssh_pubkeys/:tag")
    //      .mapped_get(&mut routemap, account_get_id_ssh_pubkey_tag);
    //  account_route
    //      .route("/:id/_user_auth_token")
    //      .mapped_get(&mut routemap, account_get_id_user_auth_token);
    //  account_route
    //      .route("/:id/_user_auth_token/:token_id")
    //      .mapped_delete(&mut routemap, account_user_auth_token_delete);

    //  // Credential updates, don't require the account id.
    let cred_route = Router::new().with_state(state.clone());
    let app = app.nest("/v1/credential", cred_route);
    //  cred_route
    //      .route("/_exchange_intent")
    //      .mapped_post(&mut routemap, credential_update_exchange_intent);

    //  cred_route
    //      .route("/_status")
    //      .mapped_post(&mut routemap, credential_update_status);

    //  cred_route
    //      .route("/_update")
    //      .mapped_post(&mut routemap, credential_update_update);

    //  cred_route
    //      .route("/_commit")
    //      .mapped_post(&mut routemap, credential_update_commit);

    //  cred_route
    //      .route("/_cancel")
    //      .mapped_post(&mut routemap, credential_update_cancel);

    let group_route = Router::new().with_state(state.clone());
    let app = app.nest("/v1/group", group_route);
    //  group_route
    //      .route("/")
    //      .mapped_get(&mut routemap, group_get)
    //      .mapped_post(&mut routemap, group_post);
    //  group_route
    //      .route("/:id")
    //      .mapped_get(&mut routemap, group_id_get)
    //      .mapped_delete(&mut routemap, group_id_delete);
    //  group_route
    //      .route("/:id/_attr/:attr")
    //      .mapped_delete(&mut routemap, group_id_delete_attr)
    //      .mapped_get(&mut routemap, group_id_get_attr)
    //      .mapped_put(&mut routemap, group_id_put_attr)
    //      .mapped_post(&mut routemap, group_id_post_attr);
    //  group_route
    //      .route("/:id/_unix")
    //      .mapped_post(&mut routemap, group_post_id_unix);

    let domain_route = Router::new().with_state(state.clone());
    let app = app.nest("/v1/domain", domain_route);
    //  domain_route.route("/").mapped_get(&mut routemap, domain_get);
    //  domain_route
    //      .route("/_attr/:attr")
    //      .mapped_get(&mut routemap, domain_get_attr)
    //      .mapped_put(&mut routemap, domain_put_attr)
    //      .mapped_delete(&mut routemap, domain_delete_attr);

    let system_route = Router::new().with_state(state.clone());
    let app = app.nest("/v1/system", system_route);
    //  system_route.route("/").mapped_get(&mut routemap, system_get);
    //  system_route
    //      .route("/_attr/:attr")
    //      .mapped_get(&mut routemap, system_get_attr)
    //      .mapped_post(&mut routemap, system_post_attr)
    //      .mapped_delete(&mut routemap, system_delete_attr);

    let recycle_route = Router::new().with_state(state.clone());
    let app = app.nest("/v1/recycle_bin", recycle_route);
    //  recycle_route
    //      .route("/")
    //      .mapped_get(&mut routemap, recycle_bin_get);
    //  recycle_route
    //      .route("/:id")
    //      .mapped_get(&mut routemap, recycle_bin_id_get);
    //  recycle_route
    //      .route("/:id/_revive")
    //      .mapped_post(&mut routemap, recycle_bin_revive_id_post);

    let accessprof_route = Router::new().with_state(state.clone());
    let app = app.nest("/v1/access_profile", accessprof_route);
    //  // accessprof_route
    //  //     .route("/")
    //  //     .mapped_get(&mut routemap, do_nothing);
    //  // accessprof_route
    //  //     .route("/:id")
    //  //     .mapped_get(&mut routemap, do_nothing);
    //  // accessprof_route
    //  //     .route("/:id/_attr/:attr")
    //  //     .mapped_get(&mut routemap, do_nothing);

    //  routemap.push_self("/v1/routemap".to_string(), http_types::Method::Get);
    //  appserver.route("/v1/routemap").nest({
    //      let mut route_api = tide::with_state(routemap);
    //      route_api.route("/").get(do_routemap);
    //      route_api
    //  });
    //  // routemap_route.route("/").mapped_get(&mut routemap, do_routemap);
    //  // ===  End routes

    let app = app
        .nest("/v1", crate::https::v1::new(state.clone()))
        .route_layer(from_fn_with_state(
            state.clone(),
            crate::https::csp_headers::cspheaders_layer,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(session_layer)
        .with_state(state);

    let addr = SocketAddr::from_str(&address).unwrap();
    println!("AXUM listening on {}", addr);
    axum_server::bind_openssl(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();

    let opt_tls_params = Some(tlsconfig.clone());

    let handle = match opt_tls_params {
        Some(_tls_param) => {
            // let tlsl = TlsListener::build()
            //     .addrs(&address)
            //     .cert(&tls_param.chain)
            //     .key(&tls_param.key)
            //     .finish()
            //     .map_err(|e| {
            //         error!("Failed to build TLS Listener -> {:?}", e);
            //     })?;

            // let mut listener = tlsl.to_listener().map_err(|e| {
            // error!("Failed to convert to Listener -> {:?}", e);
            // })?;

            // if let Err(e) = listener.bind(tserver).await {
            //     error!(
            //         "Failed to start server listener on address {:?} -> {:?}",
            //         &address, e
            //     );
            //     return Err(());
            // }

            tokio::spawn(async move {
                tokio::select! {
                    Ok(action) = rx.recv() => {
                        match action {
                            CoreAction::Shutdown => {},
                        }
                    }
                    // server_result = listener.accept() => {
                    //     if let Err(e) = server_result {
                    //         error!(
                    //             "Failed to accept via listener on address {:?} -> {:?}",
                    //             &address, e
                    //         );
                    //     }
                    // }
                };
                info!("Stopped HTTPSAcceptorActor");
            })
        }
        None => {
            // Create without https
            // let mut listener = (&address).to_listener().map_err(|e| {
            //     error!("Failed to convert to Listener -> {:?}", e);
            // })?;

            // if let Err(e) = listener.bind(tserver).await {
            //     error!(
            //         "Failed to start server listener on address {:?} -> {:?}",
            //         &address, e
            //     );
            //     return Err(());
            // }

            tokio::spawn(async move {
                tokio::select! {
                    Ok(action) = rx.recv() => {
                        match action {
                            CoreAction::Shutdown => {},
                        }
                    }
                    // server_result = listener.accept() => {
                    //     if let Err(e) = server_result {
                    //         error!(
                    //             "Failed to accept via listener on address {:?} -> {:?}",
                    //             &address, e
                    //         );
                    //     }
                    // }
                }
                info!("Stopped HTTPAcceptorActor");
            })
        }
    };

    Ok(handle)
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
