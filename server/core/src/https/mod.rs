mod manifest;
pub mod middleware;
mod oauth2;
mod routemaps;
mod v1;
mod v1_scim;

use std::fs::canonicalize;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use compact_jwt::{Jws, JwsSigner, JwsUnverified, JwsValidator};
use kanidmd_lib::prelude::*;
use kanidmd_lib::status::StatusActor;
use serde::Serialize;
use tide::listener::{Listener, ToListener};
use tide_compress::CompressMiddleware;
use tide_openssl::TlsListener;
use tracing::{error, info};
use uuid::Uuid;

use self::manifest::manifest;
use self::middleware::*;
use self::oauth2::*;
use self::routemaps::{RouteMap, RouteMaps};
use self::v1::*;
use self::v1_scim::*;
use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_write::QueryServerWriteV1;
use crate::config::{ServerRole, TlsConfiguration};

use crate::CoreAction;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct JavaScriptFile {
    // Relative to the pkg/ dir
    filepath: &'static str,
    // SHA384 hash of the file
    hash: String,
    // if it's a module add the "type"
    filetype: Option<String>,
}

impl JavaScriptFile {
    /// return the hash for use in CSP headers
    // pub fn as_csp_hash(self) -> String {
    //     self.hash
    // }

    /// returns a `<script>` HTML tag
    fn as_tag(self) -> String {
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
    pub(crate) trust_x_forward_for: bool,
}

pub trait RequestExtensions {
    fn get_current_uat(&self) -> Option<String>;

    fn get_auth_bearer(&self) -> Option<String>;

    fn get_current_auth_session_id(&self) -> Option<Uuid>;

    fn get_url_param(&self, param: &str) -> Result<String, tide::Error>;

    fn get_url_param_uuid(&self, param: &str) -> Result<Uuid, tide::Error>;

    fn new_eventid(&self) -> (Uuid, String);

    fn get_remote_addr(&self) -> Option<IpAddr>;
}

impl RequestExtensions for tide::Request<AppState> {
    fn get_auth_bearer(&self) -> Option<String> {
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
            .map(str::to_string)
    }

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
                    .map(|jws: Jws<SessionId>| jws.into_inner().sessionid)
                    .ok()
            })
            // If not there, get from the cookie instead.
            .or_else(|| self.session().get::<Uuid>("auth-session-id"))
    }

    fn get_url_param(&self, param: &str) -> Result<String, tide::Error> {
        self.param(param)
            .map_err(|e| {
                error!(?e);
                tide::Error::from_str(tide::StatusCode::ImATeapot, "teapot")
            })
            .and_then(|data| {
                urlencoding::decode(data)
                    .map(|s| s.into_owned())
                    .map_err(|e| {
                        error!(?e);
                        tide::Error::from_str(tide::StatusCode::ImATeapot, "teapot")
                    })
            })
    }

    fn get_url_param_uuid(&self, param: &str) -> Result<Uuid, tide::Error> {
        self.param(param)
            .map_err(|e| {
                error!(?e);
                tide::Error::from_str(tide::StatusCode::ImATeapot, "teapot")
            })
            .and_then(|s| {
                Uuid::try_parse(s).map_err(|e| {
                    error!(?e);
                    tide::Error::from_str(tide::StatusCode::ImATeapot, "teapot")
                })
            })
    }

    fn new_eventid(&self) -> (Uuid, String) {
        let eventid = sketching::tracing_forest::id();
        let hv = eventid.as_hyphenated().to_string();
        (eventid, hv)
    }

    /// Returns the remote address of the client, based on if you've got trust_x_forward_for set in config.
    fn get_remote_addr(&self) -> Option<IpAddr> {
        if self.state().trust_x_forward_for {
            // xff headers don't have a port, but if we're going direct you might get one
            let res = self.remote().and_then(|ip| {
                ip.parse::<IpAddr>()
                    .ok()
                    .or_else(|| ip.parse::<SocketAddr>().map(|s_ad| s_ad.ip()).ok())
            });
            debug!("Trusting XFF, using remote src_ip={:?}", res);
            res
        } else {
            let res = self
                .peer_addr()
                .map(|addr| addr.parse::<SocketAddr>().unwrap())
                .map(|s_ad: SocketAddr| s_ad.ip());
            debug!("Not trusting XFF, using peer_addr src_ip={:?}", res);
            res
        }
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

    res.set_content_type("text/plain;charset=utf-8");
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
    // this feels icky but I felt that adding a trait on Vec<JavaScriptFile> which generated the string was going a bit far
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

pub async fn create_https_server(
    address: String,
    domain: &String,
    opt_tls_params: Option<&TlsConfiguration>,
    role: ServerRole,
    trust_x_forward_for: bool,
    cookie_key: &[u8; 32],
    jws_signer: JwsSigner,
    status_ref: &'static StatusActor,
    qe_w_ref: &'static QueryServerWriteV1,
    qe_r_ref: &'static QueryServerReadV1,
    mut rx: broadcast::Receiver<CoreAction>,
) -> Result<tokio::task::JoinHandle<()>, ()> {
    let jws_validator = jws_signer.get_validator().map_err(|e| {
        error!(?e, "Failed to get jws validator");
    })?;

    let jws_validator = std::sync::Arc::new(jws_validator);
    let jws_signer = std::sync::Arc::new(jws_signer);
    let mut routemap = RouteMap::default();

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

    let mut tserver = tide::Server::with_state(AppState {
        status_ref,
        qe_w_ref,
        qe_r_ref,
        jws_signer,
        jws_validator,
        js_files: js_files.to_owned(),
        trust_x_forward_for,
    });

    // Add the logging subsystem.
    tserver.with(sketching::middleware::TreeMiddleware::new(
        trust_x_forward_for,
    ));

    // Add cookie handling.
    tserver.with(
        // We do not force a session ttl, because we validate this elsewhere in usage.
        tide::sessions::SessionMiddleware::new(tide::sessions::CookieStore::new(), cookie_key)
            .with_session_ttl(None)
            .with_cookie_name("kanidm-session")
            // Without this, the cookies won't be used on subdomains of origin.
            .with_cookie_domain(domain)
            // Im not sure if we need Lax here, I don't think we do because on the first get
            // we don't need the cookie since wasm drives the fetches.
            .with_same_site_policy(tide::http::cookies::SameSite::Strict),
    );

    // Strict responses.
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

        static_tserver.at("/").mapped_get(&mut routemap, index_view);
        static_tserver
            .at("/robots.txt")
            .mapped_get(&mut routemap, robots_txt);
        static_tserver
            .at("/manifest.webmanifest")
            .mapped_get(&mut routemap, manifest);
        static_tserver
            .at("/ui/")
            .mapped_get(&mut routemap, index_view);
        static_tserver
            .at("/ui/*")
            .mapped_get(&mut routemap, index_view);

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
    // Add our version injector, we only add this to apis.
    tserver_cacheable.with(VersionHeaderMiddleware::default());
    tserver_cacheable.with(CacheableMiddleware::default());

    // We allow clients to cache the unix token for accounts and groups.
    let mut account_route_cacheable = tserver_cacheable.at("/v1/account");
    account_route_cacheable
        .at("/:id/_unix/_token")
        .mapped_get(&mut routemap, account_get_id_unix_token);
    // We allow caching of the radius token.
    account_route_cacheable
        .at("/:id/_radius/_token")
        .mapped_get(&mut routemap, account_get_id_radius_token);

    let mut group_route_cacheable = tserver_cacheable.at("/v1/group");
    group_route_cacheable
        .at("/:id/_unix/_token")
        .mapped_get(&mut routemap, group_get_id_unix_token);

    // We allow caching oauth2 RP icons.
    let mut oauth2_route_cacheable = tserver_cacheable.at("/v1/oauth2");
    oauth2_route_cacheable
        .at("/:rs_name/_icon")
        .mapped_get(&mut routemap, do_nothing);

    // ==== These routes can not be cached
    let mut appserver = tserver.at("");
    // Add our version injector, we only add this to apis.
    appserver.with(VersionHeaderMiddleware::default());
    appserver.with(NoCacheMiddleware::default());

    // let mut well_known = appserver.at("/.well-known");

    appserver
        .at("/status")
        .mapped_get(&mut routemap, self::status);

    // == oauth endpoints.
    oauth2_route_setup(&mut appserver, &mut routemap);

    // == scim endpoints.
    scim_route_setup(&mut appserver, &mut routemap);

    let mut raw_route = appserver.at("/v1/raw");
    raw_route.at("/create").mapped_post(&mut routemap, create);
    raw_route.at("/modify").mapped_post(&mut routemap, modify);
    raw_route.at("/delete").mapped_post(&mut routemap, delete);
    raw_route.at("/search").mapped_post(&mut routemap, search);

    appserver.at("/v1/auth").mapped_post(&mut routemap, auth);
    appserver
        .at("/v1/auth/valid")
        .mapped_get(&mut routemap, auth_valid);
    appserver
        .at("/v1/reauth")
        .mapped_post(&mut routemap, reauth);

    appserver.at("/v1/logout").mapped_get(&mut routemap, logout);

    let mut schema_route = appserver.at("/v1/schema");
    schema_route.at("/").mapped_get(&mut routemap, schema_get);
    schema_route
        .at("/attributetype")
        .mapped_get(&mut routemap, schema_attributetype_get)
        .mapped_post(&mut routemap, do_nothing);
    schema_route
        .at("/attributetype/:id")
        .mapped_get(&mut routemap, schema_attributetype_get_id)
        .mapped_put(&mut routemap, do_nothing)
        .mapped_patch(&mut routemap, do_nothing);

    schema_route
        .at("/classtype")
        .mapped_get(&mut routemap, schema_classtype_get)
        .mapped_post(&mut routemap, do_nothing);
    schema_route
        .at("/classtype/:id")
        .mapped_get(&mut routemap, schema_classtype_get_id)
        .mapped_put(&mut routemap, do_nothing)
        .mapped_patch(&mut routemap, do_nothing);

    let mut oauth2_route = appserver.at("/v1/oauth2");
    oauth2_route.at("/").mapped_get(&mut routemap, oauth2_get);

    oauth2_route
        .at("/_basic")
        .mapped_post(&mut routemap, oauth2_basic_post);

    oauth2_route
        .at("/:rs_name")
        .mapped_get(&mut routemap, oauth2_id_get)
        // It's not really possible to replace this wholesale.
        // .mapped_put(&mut routemap, oauth2_id_put)
        .mapped_patch(&mut routemap, oauth2_id_patch)
        .mapped_delete(&mut routemap, oauth2_id_delete);

    oauth2_route
        .at("/:rs_name/_basic_secret")
        .mapped_get(&mut routemap, oauth2_id_get_basic_secret);

    oauth2_route
        .at("/:id/_scopemap/:group")
        .mapped_post(&mut routemap, oauth2_id_scopemap_post)
        .mapped_delete(&mut routemap, oauth2_id_scopemap_delete);

    oauth2_route
        .at("/:id/_sup_scopemap/:group")
        .mapped_post(&mut routemap, oauth2_id_sup_scopemap_post)
        .mapped_delete(&mut routemap, oauth2_id_sup_scopemap_delete);

    let mut self_route = appserver.at("/v1/self");
    self_route.at("/").mapped_get(&mut routemap, whoami);
    self_route.at("/_uat").mapped_get(&mut routemap, whoami_uat);

    self_route
        .at("/_attr/:attr")
        .mapped_get(&mut routemap, do_nothing);
    self_route
        .at("/_credential")
        .mapped_get(&mut routemap, do_nothing);

    self_route
        .at("/_credential/:cid/_lock")
        .mapped_get(&mut routemap, do_nothing);

    self_route
        .at("/_radius")
        .mapped_get(&mut routemap, do_nothing)
        .mapped_delete(&mut routemap, do_nothing)
        .mapped_post(&mut routemap, do_nothing);

    self_route
        .at("/_radius/_config")
        .mapped_post(&mut routemap, do_nothing);
    self_route
        .at("/_radius/_config/:token")
        .mapped_get(&mut routemap, do_nothing);
    self_route
        .at("/_radius/_config/:token/apple")
        .mapped_get(&mut routemap, do_nothing);

    // Applinks are the list of apps this account can access.
    self_route
        .at("/_applinks")
        .mapped_get(&mut routemap, applinks_get);

    let mut person_route = appserver.at("/v1/person");
    person_route
        .at("/")
        .mapped_get(&mut routemap, person_get)
        .mapped_post(&mut routemap, person_post);
    person_route
        .at("/:id")
        .mapped_get(&mut routemap, person_id_get)
        .mapped_patch(&mut routemap, account_id_patch)
        .mapped_delete(&mut routemap, person_account_id_delete);
    person_route
        .at("/:id/_attr/:attr")
        .mapped_get(&mut routemap, account_id_get_attr)
        .mapped_put(&mut routemap, account_id_put_attr)
        .mapped_post(&mut routemap, account_id_post_attr)
        .mapped_delete(&mut routemap, account_id_delete_attr);

    person_route
        .at("/:id/_lock")
        .mapped_get(&mut routemap, do_nothing);
    person_route
        .at("/:id/_credential")
        .mapped_get(&mut routemap, do_nothing);
    person_route
        .at("/:id/_credential/_status")
        .mapped_get(&mut routemap, account_get_id_credential_status);
    person_route
        .at("/:id/_credential/:cid/_lock")
        .mapped_get(&mut routemap, do_nothing);
    person_route
        .at("/:id/_credential/_update")
        .mapped_get(&mut routemap, account_get_id_credential_update);
    person_route
        .at("/:id/_credential/_update_intent")
        .mapped_get(&mut routemap, account_get_id_credential_update_intent);
    person_route
        .at("/:id/_credential/_update_intent/:ttl")
        .mapped_get(&mut routemap, account_get_id_credential_update_intent);

    person_route
        .at("/:id/_ssh_pubkeys")
        .mapped_get(&mut routemap, account_get_id_ssh_pubkeys)
        .mapped_post(&mut routemap, account_post_id_ssh_pubkey);
    person_route
        .at("/:id/_ssh_pubkeys/:tag")
        .mapped_get(&mut routemap, account_get_id_ssh_pubkey_tag)
        .mapped_delete(&mut routemap, account_delete_id_ssh_pubkey_tag);

    person_route
        .at("/:id/_radius")
        .mapped_get(&mut routemap, account_get_id_radius)
        .mapped_post(&mut routemap, account_post_id_radius_regenerate)
        .mapped_delete(&mut routemap, account_delete_id_radius);

    person_route
        .at("/:id/_unix")
        .mapped_post(&mut routemap, account_post_id_unix);
    person_route
        .at("/:id/_unix/_credential")
        .mapped_put(&mut routemap, account_put_id_unix_credential)
        .mapped_delete(&mut routemap, account_delete_id_unix_credential);

    // Service accounts

    let mut service_account_route = appserver.at("/v1/service_account");
    service_account_route
        .at("/")
        .mapped_get(&mut routemap, service_account_get)
        .mapped_post(&mut routemap, service_account_post);
    service_account_route
        .at("/:id")
        .mapped_get(&mut routemap, service_account_id_get)
        .mapped_patch(&mut routemap, account_id_patch)
        .mapped_delete(&mut routemap, service_account_id_delete);
    service_account_route
        .at("/:id/_attr/:attr")
        .mapped_get(&mut routemap, account_id_get_attr)
        .mapped_put(&mut routemap, account_id_put_attr)
        .mapped_post(&mut routemap, account_id_post_attr)
        .mapped_delete(&mut routemap, account_id_delete_attr);

    service_account_route
        .at("/:id/_lock")
        .mapped_get(&mut routemap, do_nothing);

    service_account_route
        .at("/:id/_into_person")
        .mapped_post(&mut routemap, service_account_into_person);

    service_account_route
        .at("/:id/_api_token")
        .mapped_post(&mut routemap, service_account_api_token_post)
        .mapped_get(&mut routemap, service_account_api_token_get);
    service_account_route
        .at("/:id/_api_token/:token_id")
        .mapped_delete(&mut routemap, service_account_api_token_delete);

    service_account_route
        .at("/:id/_credential")
        .mapped_get(&mut routemap, do_nothing);
    service_account_route
        .at("/:id/_credential/_generate")
        .mapped_get(&mut routemap, service_account_credential_generate);
    service_account_route
        .at("/:id/_credential/_status")
        .mapped_get(&mut routemap, account_get_id_credential_status);
    service_account_route
        .at("/:id/_credential/:cid/_lock")
        .mapped_get(&mut routemap, do_nothing);

    service_account_route
        .at("/:id/_ssh_pubkeys")
        .mapped_get(&mut routemap, account_get_id_ssh_pubkeys)
        .mapped_post(&mut routemap, account_post_id_ssh_pubkey);
    service_account_route
        .at("/:id/_ssh_pubkeys/:tag")
        .mapped_get(&mut routemap, account_get_id_ssh_pubkey_tag)
        .mapped_delete(&mut routemap, account_delete_id_ssh_pubkey_tag);

    service_account_route
        .at("/:id/_unix")
        .mapped_post(&mut routemap, account_post_id_unix);

    // Shared account features only - mainly this is for unix-like
    // features.
    let mut account_route = appserver.at("/v1/account");
    account_route
        .at("/:id/_unix/_auth")
        .mapped_post(&mut routemap, account_post_id_unix_auth);
    account_route
        .at("/:id/_ssh_pubkeys")
        .mapped_get(&mut routemap, account_get_id_ssh_pubkeys);
    account_route
        .at("/:id/_ssh_pubkeys/:tag")
        .mapped_get(&mut routemap, account_get_id_ssh_pubkey_tag);
    account_route
        .at("/:id/_user_auth_token")
        .mapped_get(&mut routemap, account_get_id_user_auth_token);
    account_route
        .at("/:id/_user_auth_token/:token_id")
        .mapped_delete(&mut routemap, account_user_auth_token_delete);

    // Credential updates, don't require the account id.
    let mut cred_route = appserver.at("/v1/credential");
    cred_route
        .at("/_exchange_intent")
        .mapped_post(&mut routemap, credential_update_exchange_intent);

    cred_route
        .at("/_status")
        .mapped_post(&mut routemap, credential_update_status);

    cred_route
        .at("/_update")
        .mapped_post(&mut routemap, credential_update_update);

    cred_route
        .at("/_commit")
        .mapped_post(&mut routemap, credential_update_commit);

    cred_route
        .at("/_cancel")
        .mapped_post(&mut routemap, credential_update_cancel);

    let mut group_route = appserver.at("/v1/group");
    group_route
        .at("/")
        .mapped_get(&mut routemap, group_get)
        .mapped_post(&mut routemap, group_post);
    group_route
        .at("/:id")
        .mapped_get(&mut routemap, group_id_get)
        .mapped_delete(&mut routemap, group_id_delete);
    group_route
        .at("/:id/_attr/:attr")
        .mapped_delete(&mut routemap, group_id_delete_attr)
        .mapped_get(&mut routemap, group_id_get_attr)
        .mapped_put(&mut routemap, group_id_put_attr)
        .mapped_post(&mut routemap, group_id_post_attr);
    group_route
        .at("/:id/_unix")
        .mapped_post(&mut routemap, group_post_id_unix);

    let mut domain_route = appserver.at("/v1/domain");
    domain_route.at("/").mapped_get(&mut routemap, domain_get);
    domain_route
        .at("/_attr/:attr")
        .mapped_get(&mut routemap, domain_get_attr)
        .mapped_put(&mut routemap, domain_put_attr)
        .mapped_delete(&mut routemap, domain_delete_attr);

    let mut system_route = appserver.at("/v1/system");
    system_route.at("/").mapped_get(&mut routemap, system_get);
    system_route
        .at("/_attr/:attr")
        .mapped_get(&mut routemap, system_get_attr)
        .mapped_post(&mut routemap, system_post_attr)
        .mapped_delete(&mut routemap, system_delete_attr);

    let mut recycle_route = appserver.at("/v1/recycle_bin");
    recycle_route
        .at("/")
        .mapped_get(&mut routemap, recycle_bin_get);
    recycle_route
        .at("/:id")
        .mapped_get(&mut routemap, recycle_bin_id_get);
    recycle_route
        .at("/:id/_revive")
        .mapped_post(&mut routemap, recycle_bin_revive_id_post);

    let mut accessprof_route = appserver.at("/v1/access_profile");
    accessprof_route
        .at("/")
        .mapped_get(&mut routemap, do_nothing);
    accessprof_route
        .at("/:id")
        .mapped_get(&mut routemap, do_nothing);
    accessprof_route
        .at("/:id/_attr/:attr")
        .mapped_get(&mut routemap, do_nothing);

    routemap.push_self("/v1/routemap".to_string(), http_types::Method::Get);
    appserver.at("/v1/routemap").nest({
        let mut route_api = tide::with_state(routemap);
        route_api.at("/").get(do_routemap);
        route_api
    });
    // routemap_route.at("/").mapped_get(&mut routemap, do_routemap);
    // ===  End routes

    let handle = match opt_tls_params {
        Some(tls_param) => {
            let tlsl = TlsListener::build()
                .addrs(&address)
                .cert(&tls_param.chain)
                .key(&tls_param.key)
                .finish()
                .map_err(|e| {
                    error!("Failed to build TLS Listener -> {:?}", e);
                })?;

            let mut listener = tlsl.to_listener().map_err(|e| {
                error!("Failed to convert to Listener -> {:?}", e);
            })?;

            if let Err(e) = listener.bind(tserver).await {
                error!(
                    "Failed to start server listener on address {:?} -> {:?}",
                    &address, e
                );
                return Err(());
            }

            tokio::spawn(async move {
                tokio::select! {
                    Ok(action) = rx.recv() => {
                        match action {
                            CoreAction::Shutdown => {},
                        }
                    }
                    server_result = listener.accept() => {
                        if let Err(e) = server_result {
                            error!(
                                "Failed to accept via listener on address {:?} -> {:?}",
                                &address, e
                            );
                        }
                    }
                };
                info!("Stopped HTTPSAcceptorActor");
            })
        }
        None => {
            // Create without https
            let mut listener = (&address).to_listener().map_err(|e| {
                error!("Failed to convert to Listener -> {:?}", e);
            })?;

            if let Err(e) = listener.bind(tserver).await {
                error!(
                    "Failed to start server listener on address {:?} -> {:?}",
                    &address, e
                );
                return Err(());
            }

            tokio::spawn(async move {
                tokio::select! {
                    Ok(action) = rx.recv() => {
                        match action {
                            CoreAction::Shutdown => {},
                        }
                    }
                    server_result = listener.accept() => {
                        if let Err(e) = server_result {
                            error!(
                                "Failed to accept via listener on address {:?} -> {:?}",
                                &address, e
                            );
                        }
                    }
                }
                info!("Stopped HTTPAcceptorActor");
            })
        }
    };
    Ok(handle)
}
