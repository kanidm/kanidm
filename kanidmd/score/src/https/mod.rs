mod manifest;
pub mod middleware;
mod oauth2;
mod v1;

use self::manifest::manifest;
use self::middleware::*;
use self::oauth2::*;
use self::v1::*;

use compact_jwt::{Jws, JwsSigner, JwsUnverified, JwsValidator};
use kanidm::actors::v1_read::QueryServerReadV1;
use kanidm::actors::v1_write::QueryServerWriteV1;
use kanidm::config::{ServerRole, TlsConfiguration};
use kanidm::prelude::*;
use kanidm::status::StatusActor;
use kanidm::tracing_tree::TreeMiddleware;
use serde::Serialize;
use std::fs::canonicalize;
use std::path::PathBuf;
use std::str::FromStr;
use tide_compress::CompressMiddleware;
use tide_openssl::TlsListener;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Clone)]
pub struct JavaScriptFile {
    // Relative to the pkg/ dir
    filepath: &'static str,
    // SHA384 hash of the file
    hash: String,
    // if it's a module add the "type"
    filetype: Option<String>,
}

impl std::fmt::Display for JavaScriptFile {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> ::std::result::Result<(), ::std::fmt::Error> {
        // TODO YOLO this
        let typestr = match &self.filetype {
            Some(value) => format!("type=\"{}\"", value),
            _ => "".to_string(),
        };
        f.write_str(format!(r#"<script src=\"/pkg/{}\" {}"#, &self.filepath, typestr,).as_str())
    }
}

impl JavaScriptFile {
    /// grab the hash for use in CSP headers
    pub fn as_csp_hash(self) -> String {
        self.hash
    }

    /// returns a <script tag
    fn as_tag(self) -> String {
        let typeattr = match self.filetype {
            Some(val) => format!("type=\"{}\" ", val),
            _ => String::from(""),
        };
        format!(
            r#"<script src="/pkg/{}" integrity="{}" {}></script>"#,
            self.filepath, self.hash, typeattr,
        )
    }
}

#[derive(Clone)]
pub struct AppState {
    pub status_ref: &'static StatusActor,
    pub qe_w_ref: &'static QueryServerWriteV1,
    pub qe_r_ref: &'static QueryServerReadV1,
    // Store the token management parts.
    pub jws_signer: std::sync::Arc<JwsSigner>,
    pub jws_validator: std::sync::Arc<JwsValidator>,
    /// The SHA384 hashes of javascript files we're going to serve to users
    pub js_files: Vec<JavaScriptFile>,
}

pub trait RequestExtensions {
    fn get_current_uat(&self) -> Option<String>;

    fn get_current_auth_session_id(&self) -> Option<Uuid>;

    fn get_url_param(&self, param: &str) -> Result<String, tide::Error>;

    fn new_eventid(&self) -> (Uuid, String);
}

impl RequestExtensions for tide::Request<AppState> {
    fn get_current_uat(&self) -> Option<String> {
        // Contact the QS to get it to validate wtf is up.
        // let kref = &self.state().bundy_handle;
        // self.session().get::<UserAuthToken>("uat")
        self.header(tide::http::headers::AUTHORIZATION)
            .and_then(|hv| {
                // Get the first header value.
                hv.get(0)
            })
            .and_then(|h| {
                // Turn it to a &str, and then check the prefix
                h.as_str().strip_prefix("Bearer ")
            })
            .map(|s| s.to_string())
            .or_else(|| self.session().get::<String>("bearer"))
        /*
        .and_then(|ts| {
            // Take the token str and attempt to decrypt
            // Attempt to re-inflate a UAT from bytes.
            //
            // NOTE: UAT expiry validation is performed in event.rs!
            let uat: Option<UserAuthToken> = kref.verify(ts).ok();
            uat
        })
        */
    }

    fn get_current_auth_session_id(&self) -> Option<Uuid> {
        // We see if there is a signed header copy first.
        let kref = &self.state().jws_validator;
        self.header("X-KANIDM-AUTH-SESSION-ID")
            .and_then(|hv| {
                // Get the first header value.
                hv.get(0)
            })
            .and_then(|h| {
                // Take the token str and attempt to decrypt
                // Attempt to re-inflate a uuid from bytes.
                JwsUnverified::from_str(h.as_str()).ok()
            })
            .and_then(|jwsu| {
                jwsu.validate(kref)
                    .map(|jws: Jws<SessionId>| jws.inner.sessionid)
                    .ok()
            })
            // If not there, get from the cookie instead.
            .or_else(|| self.session().get::<Uuid>("auth-session-id"))
    }

    fn get_url_param(&self, param: &str) -> Result<String, tide::Error> {
        self.param(param).map(str::to_string).map_err(|e| {
            error!(?e);
            tide::Error::from_str(tide::StatusCode::ImATeapot, "teapot")
        })
    }

    fn new_eventid(&self) -> (Uuid, String) {
        let eventid = kanidm::tracing_tree::operation_id().unwrap();
        let hv = eventid.as_hyphenated().to_string();
        (eventid, hv)
    }
}

pub fn to_tide_response<T: Serialize>(
    v: Result<T, OperationError>,
    hvalue: String,
) -> tide::Result {
    match v {
        Ok(iv) => {
            let mut res = tide::Response::new(200);
            tide::Body::from_json(&iv).map(|b| {
                res.set_body(b);
                res
            })
        }
        Err(e) => {
            let mut res = match &e {
                OperationError::NotAuthenticated | OperationError::SessionExpired => {
                    // https://datatracker.ietf.org/doc/html/rfc7235#section-4.1
                    let mut res = tide::Response::new(tide::StatusCode::Unauthorized);
                    res.insert_header("WWW-Authenticate", "Bearer");
                    res
                }
                OperationError::SystemProtectedObject | OperationError::AccessDenied => {
                    tide::Response::new(tide::StatusCode::Forbidden)
                }
                OperationError::NoMatchingEntries => {
                    tide::Response::new(tide::StatusCode::NotFound)
                }
                OperationError::PasswordQuality(_)
                | OperationError::EmptyRequest
                | OperationError::SchemaViolation(_) => {
                    tide::Response::new(tide::StatusCode::BadRequest)
                }
                _ => tide::Response::new(tide::StatusCode::InternalServerError),
            };
            tide::Body::from_json(&e).map(|b| {
                res.set_body(b);
                res
            })
        }
    }
    .map(|mut res| {
        res.insert_header("X-KANIDM-OPID", hvalue);
        res
    })
}

/// Returns a generic robots.txt blocking all bots
async fn robots_txt(_req: tide::Request<AppState>) -> tide::Result {
    let mut res = tide::Response::new(200);

    res.set_content_type("text/plain");
    res.set_body(
        r#"
User-agent: *
Disallow: /
"#,
    );
    Ok(res)
}

/// The web UI at / for Kanidm
async fn index_view(req: tide::Request<AppState>) -> tide::Result {
    let mut res = tide::Response::new(200);
    let (eventid, hvalue) = req.new_eventid();

    let domain_display_name = req.state().qe_r_ref.get_domain_display_name(eventid).await;
    res.insert_header("X-KANIDM-OPID", hvalue);

    res.set_content_type("text/html;charset=utf-8");
    let jsfiles: Vec<String> = req
        .state()
        .to_owned()
        .js_files
        .into_iter()
        .map(|j| j.as_tag())
        .collect();
    let jstags = jsfiles.join(" ");
    res.set_body(format!(r#"
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8"/>
        <meta name="theme-color" content="white" />
        <meta name="viewport" content="width=device-width" />
        <title>{}</title>

        <link rel="icon" href="/pkg/img/favicon.png" />
        <link rel="manifest" href="/manifest.webmanifest" />
        <link rel="apple-touch-icon" href="/pkg/img/logo-256.png" />
        <link rel="apple-touch-icon" sizes="180x180" href="/pkg/img/logo-180.png" />
        <link rel="apple-touch-icon" sizes="192x192" href="/pkg/img/logo-192.png" />
        <link rel="apple-touch-icon" sizes="512x512" href="/pkg/img/logo-square.svg" />
        <link rel="stylesheet" href="/pkg/external/bootstrap.min.css" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC"/>
        <link rel="stylesheet" href="/pkg/style.css"/>

        {}

    </head>
    <body class="flex-column d-flex h-100">
        <main class="flex-shrink-0 form-signin">
        <center>
            <img src="/pkg/img/logo-square.svg" alt="Kanidm" class="kanidm_logo"/>
            <h3>Kanidm is loading, please wait... </h3>
        </center>
        </main>
        <footer class="footer mt-auto py-3 bg-light text-end">
            <div class="container">
                <span class="text-muted">Powered by <a href="https://kanidm.com">Kanidm</a></span>
            </div>
        </footer>
    </body>
</html>"#,
    domain_display_name.as_str(),
    jstags,
    )
    );

    Ok(res)
}

/// Generates the integrity hash for a file based on a filename
pub fn generate_integrity_hash(filename: String) -> Result<String, String> {
    let wasm_filepath = PathBuf::from(filename);
    match wasm_filepath.exists() {
        false => {
            return Err(format!(
                "Can't find {:?} to generate file hash",
                &wasm_filepath
            ));
        }
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

// TODO: Add request limits.
pub fn create_https_server(
    address: String,
    // opt_tls_params: Option<SslAcceptorBuilder>,
    opt_tls_params: Option<&TlsConfiguration>,
    role: ServerRole,
    cookie_key: &[u8; 32],
    jws_signer: JwsSigner,
    status_ref: &'static StatusActor,
    qe_w_ref: &'static QueryServerWriteV1,
    qe_r_ref: &'static QueryServerReadV1,
) -> Result<(), ()> {
    let jws_validator = jws_signer.get_validator().map_err(|e| {
        error!(?e, "Failed to get jws validator");
    })?;

    let jws_validator = std::sync::Arc::new(jws_validator);
    let jws_signer = std::sync::Arc::new(jws_signer);

    let mut js_files: Vec<JavaScriptFile> = Vec::new();

    if !matches!(role, ServerRole::WriteReplicaNoUI) {
        // let's set up the list of js module hashes
        for filepath in ["wasmloader.js"] {
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
        for filepath in ["external/bootstrap.bundle.min.js"] {
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
    };

    let mut tserver = tide::Server::with_state(AppState {
        status_ref,
        qe_w_ref,
        qe_r_ref,
        jws_signer,
        jws_validator,
        js_files: js_files.to_owned(),
    });

    // tide::log::with_level(tide::log::LevelFilter::Debug);

    // Add middleware?
    tserver.with(TreeMiddleware::with_stdout());
    // tserver.with(tide::log::LogMiddleware::new());
    // We do not force a session ttl, because we validate this elsewhere in usage.
    tserver.with(
        // We do not force a session ttl, because we validate this elsewhere in usage.
        tide::sessions::SessionMiddleware::new(tide::sessions::MemoryStore::new(), cookie_key)
            .with_cookie_name("kanidm-session")
            .with_same_site_policy(tide::http::cookies::SameSite::Strict),
    );
    tserver.with(StrictResponseMiddleware::default());

    // Add routes
    // ==== static content routes that have a longer cache policy.

    // If we are no-ui, we remove this.
    if !matches!(role, ServerRole::WriteReplicaNoUI) {
        let pkg_path = PathBuf::from(env!("KANIDM_WEB_UI_PKG_PATH"));
        if !pkg_path.exists() {
            eprintln!(
                "Couldn't find Web UI package path: ({}), quitting.",
                env!("KANIDM_WEB_UI_PKG_PATH")
            );
            std::process::exit(1);
        }
        info!("Web UI package path: {:?}", canonicalize(pkg_path).unwrap());

        /*
        Let's build a compression middleware!

        The threat of the TLS BREACH attack [1] was considered as part of adding
        the CompressMiddleware configuration.

        The attack targets secrets compressed and encrypted in flight with the intent
        to infer their content.

        This is not a concern for the paths covered by this configuration
        ( /, /ui/<and all sub-paths>, /pkg/<and all sub-paths> ),
        as they're all static content with no secrets in transit - all that data should
        come from Kanidm's REST API, which is on a different path and not covered by
        the compression middleware.


        [1] - https://resources.infosecinstitute.com/topic/the-breach-attack/
        */

        let compress_middleware = CompressMiddleware::builder()
            .threshold(1024)
            .content_type_check(Some(compression_content_type_checker()))
            .build();

        let mut static_tserver = tserver.at("");
        static_tserver.with(StaticContentMiddleware::default());

        static_tserver.with(UIContentSecurityPolicyResponseMiddleware::new(js_files));

        // The compression middleware needs to be the last one added before routes
        static_tserver.with(compress_middleware.clone());

        static_tserver.at("/").get(index_view);
        static_tserver.at("/robots.txt").get(robots_txt);
        static_tserver.at("/manifest.webmanifest").get(manifest);
        static_tserver.at("/ui/").get(index_view);
        static_tserver.at("/ui/*").get(index_view);

        let mut static_dir_tserver = tserver.at("");
        static_dir_tserver.with(StaticContentMiddleware::default());
        // The compression middleware needs to be the last one added before routes
        static_dir_tserver.with(compress_middleware);
        static_dir_tserver
            .at("/pkg")
            .serve_dir(env!("KANIDM_WEB_UI_PKG_PATH"))
            .map_err(|e| {
                error!(
                    "Failed to serve pkg dir {} -> {:?}",
                    env!("KANIDM_WEB_UI_PKG_PATH"),
                    e
                );
            })?;
    };

    // ==== Some routes can be cached - these are here:
    let mut tserver_cacheable = tserver.at("");
    tserver_cacheable.with(CacheableMiddleware::default());

    let mut account_route_cacheable = tserver_cacheable.at("/v1/account");

    // We allow caching of the radius token.
    account_route_cacheable
        .at("/:id/_radius/_token")
        .get(account_get_id_radius_token);
    // We allow clients to cache the unix token.
    account_route_cacheable
        .at("/:id/_unix/_token")
        .get(account_get_id_unix_token);

    // ==== These routes can not be cached
    let mut appserver = tserver.at("");
    appserver.with(NoCacheMiddleware::default());

    // let mut well_known = appserver.at("/.well-known");

    appserver.at("/status").get(self::status);
    // == oauth endpoints.

    let mut oauth2_process = appserver.at("/oauth2");
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    oauth2_process
        .at("/authorise")
        .post(oauth2_authorise_post)
        .get(oauth2_authorise_get);
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    oauth2_process
        .at("/authorise/permit")
        .post(oauth2_authorise_permit_post)
        .get(oauth2_authorise_permit_get);
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    oauth2_process
        .at("/authorise/reject")
        .post(oauth2_authorise_reject_post)
        .get(oauth2_authorise_reject_get);
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    oauth2_process.at("/token").post(oauth2_token_post);
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    oauth2_process
        .at("/token/introspect")
        .post(oauth2_token_introspect_post);

    let mut openid_process = appserver.at("/oauth2/openid");
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    openid_process
        .at("/:client_id/.well-known/openid-configuration")
        .get(oauth2_openid_discovery_get);
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    openid_process
        .at("/:client_id/userinfo")
        .get(oauth2_openid_userinfo_get);
    // ⚠️  ⚠️   WARNING  ⚠️  ⚠️
    // IF YOU CHANGE THESE VALUES YOU MUST UPDATE OIDC DISCOVERY URLS
    openid_process
        .at("/:client_id/public_key.jwk")
        .get(oauth2_openid_publickey_get);

    let mut raw_route = appserver.at("/v1/raw");
    raw_route.at("/create").post(create);
    raw_route.at("/modify").post(modify);
    raw_route.at("/delete").post(delete);
    raw_route.at("/search").post(search);

    appserver.at("/v1/auth").post(auth);
    appserver.at("/v1/auth/valid").get(auth_valid);

    let mut schema_route = appserver.at("/v1/schema");
    schema_route.at("/").get(schema_get);
    schema_route
        .at("/attributetype")
        .get(schema_attributetype_get)
        .post(do_nothing);
    schema_route
        .at("/attributetype/:id")
        .get(schema_attributetype_get_id)
        .put(do_nothing)
        .patch(do_nothing);

    schema_route
        .at("/classtype")
        .get(schema_classtype_get)
        .post(do_nothing);
    schema_route
        .at("/classtype/:id")
        .get(schema_classtype_get_id)
        .put(do_nothing)
        .patch(do_nothing);

    let mut oauth2_route = appserver.at("/v1/oauth2");
    oauth2_route.at("/").get(oauth2_get);

    oauth2_route.at("/_basic").post(oauth2_basic_post);

    oauth2_route
        .at("/:id")
        .get(oauth2_id_get)
        // It's not really possible to replace this wholesale.
        // .put(oauth2_id_put)
        .patch(oauth2_id_patch)
        .delete(oauth2_id_delete);

    oauth2_route
        .at("/:id/_scopemap/:group")
        .post(oauth2_id_scopemap_post)
        .delete(oauth2_id_scopemap_delete);

    let mut self_route = appserver.at("/v1/self");
    self_route.at("/").get(whoami);

    self_route.at("/_attr/:attr").get(do_nothing);
    self_route.at("/_credential").get(do_nothing);

    self_route
        .at("/_credential/primary/set_password")
        .post(idm_account_set_password);
    self_route.at("/_credential/:cid/_lock").get(do_nothing);

    self_route
        .at("/_radius")
        .get(do_nothing)
        .delete(do_nothing)
        .post(do_nothing);

    self_route.at("/_radius/_config").post(do_nothing);
    self_route.at("/_radius/_config/:token").get(do_nothing);
    self_route
        .at("/_radius/_config/:token/apple")
        .get(do_nothing);

    let mut person_route = appserver.at("/v1/person");
    person_route.at("/").get(person_get).post(person_post);
    person_route.at("/:id").get(person_id_get);

    let mut account_route = appserver.at("/v1/account");
    account_route.at("/").get(account_get).post(account_post);
    account_route
        .at("/:id")
        .get(account_id_get)
        .delete(account_id_delete);
    account_route
        .at("/:id/_attr/:attr")
        .get(account_id_get_attr)
        .put(account_id_put_attr)
        .post(account_id_post_attr)
        .delete(account_id_delete_attr);
    account_route
        .at("/:id/_person/_extend")
        .post(account_post_id_person_extend);
    account_route
        .at("/:id/_person/_set")
        .post(account_post_id_person_set);
    account_route.at("/:id/_lock").get(do_nothing);

    account_route.at("/:id/_credential").get(do_nothing);
    account_route
        .at("/:id/_credential/_status")
        .get(account_get_id_credential_status);
    account_route
        .at("/:id/_credential/primary")
        .put(account_put_id_credential_primary);
    account_route
        .at("/:id/_credential/:cid/_lock")
        .get(do_nothing);
    account_route
        .at("/:id/_credential/:cid/backup_code")
        .get(account_get_backup_code);
    // .post(account_post_backup_code_regenerate) // use "/:id/_credential/primary" instead
    // .delete(account_delete_backup_code); // same as above
    account_route
        .at("/:id/_credential/_update")
        .get(account_get_id_credential_update);
    account_route
        .at("/:id/_credential/_update_intent")
        .get(account_get_id_credential_update_intent);
    account_route
        .at("/:id/_credential/_update_intent/:ttl")
        .get(account_get_id_credential_update_intent);

    account_route
        .at("/:id/_ssh_pubkeys")
        .get(account_get_id_ssh_pubkeys)
        .post(account_post_id_ssh_pubkey);

    account_route
        .at("/:id/_ssh_pubkeys/:tag")
        .get(account_get_id_ssh_pubkey_tag)
        .delete(account_delete_id_ssh_pubkey_tag);

    account_route
        .at("/:id/_radius")
        .get(account_get_id_radius)
        .post(account_post_id_radius_regenerate)
        .delete(account_delete_id_radius);

    account_route.at("/:id/_unix").post(account_post_id_unix);
    account_route
        .at("/:id/_unix/_auth")
        .post(account_post_id_unix_auth);
    account_route
        .at("/:id/_unix/_credential")
        .put(account_put_id_unix_credential)
        .delete(account_delete_id_unix_credential);

    let mut cred_route = appserver.at("/v1/credential");
    cred_route
        .at("/_exchange_intent")
        .post(credential_update_exchange_intent);

    cred_route.at("/_status").post(credential_update_status);

    cred_route.at("/_update").post(credential_update_update);

    cred_route.at("/_commit").post(credential_update_commit);

    let mut group_route = appserver.at("/v1/group");
    group_route.at("/").get(group_get).post(group_post);
    group_route
        .at("/:id")
        .get(group_id_get)
        .delete(group_id_delete);
    group_route
        .at("/:id/_attr/:attr")
        .delete(group_id_delete_attr)
        .get(group_id_get_attr)
        .put(group_id_put_attr)
        .post(group_id_post_attr);
    group_route.at("/:id/_unix").post(group_post_id_unix);
    group_route
        .at("/:id/_unix/_token")
        .get(group_get_id_unix_token);

    let mut domain_route = appserver.at("/v1/domain");
    domain_route.at("/").get(domain_get);
    domain_route
        .at("/_attr/:attr")
        .get(domain_get_attr)
        .put(domain_put_attr)
        .delete(domain_delete_attr);

    let mut recycle_route = appserver.at("/v1/recycle_bin");
    recycle_route.at("/").get(recycle_bin_get);
    recycle_route.at("/:id").get(recycle_bin_id_get);
    recycle_route
        .at("/:id/_revive")
        .post(recycle_bin_revive_id_post);

    let mut accessprof_route = appserver.at("/v1/access_profile");
    accessprof_route.at("/").get(do_nothing);
    accessprof_route.at("/:id").get(do_nothing);
    accessprof_route.at("/:id/_attr/:attr").get(do_nothing);

    // ===  End routes

    // Create listener?
    match opt_tls_params {
        Some(tls_param) => {
            let tlsl = TlsListener::build()
                .addrs(&address)
                .cert(&tls_param.chain)
                .key(&tls_param.key)
                .finish()
                .map_err(|e| {
                    error!("Failed to build TLS Listener -> {:?}", e);
                })?;
            /*
            let x = Box::new(tls_param.build());
            let x_ref = Box::leak(x);
            let tlsl = TlsListener::new(address, x_ref);
            */

            tokio::spawn(async move {
                if let Err(e) = tserver.listen(tlsl).await {
                    error!(
                        "Failed to start server listener on address {:?} -> {:?}",
                        &address, e
                    );
                }
            });
        }
        None => {
            // Create without https
            tokio::spawn(async move {
                if let Err(e) = tserver.listen(&address).await {
                    error!(
                        "Failed to start server listener on address {:?} -> {:?}",
                        &address, e,
                    );
                }
            });
        }
    };
    Ok(())
}
