// use actix::SystemRunner;
use actix::Actor;
use actix_web::middleware::session::{self, RequestSession};
use actix_web::{
    error, http, middleware, App, Error, HttpMessage, HttpRequest, HttpResponse, Result, State,
};

use bytes::BytesMut;
use futures::{future, Future, Stream};

use crate::config::Configuration;

// SearchResult
use crate::interval::IntervalActor;
use crate::log;
use crate::proto_v1::{AuthRequest, CreateRequest, DeleteRequest, ModifyRequest, SearchRequest};
use crate::proto_v1_actors::QueryServerV1;

struct AppState {
    qe: actix::Addr<QueryServerV1>,
    max_size: usize,
}

macro_rules! json_event_decode {
    ($req:expr, $state:expr, $event_type:ty, $message_type:ty) => {{
        // This is copied every request. Is there a better way?
        // The issue is the fold move takes ownership of state if
        // we don't copy this here
        let max_size = $state.max_size;

        // HttpRequest::payload() is stream of Bytes objects
        $req.payload()
            // `Future::from_err` acts like `?` in that it coerces the error type from
            // the future into the final error type
            .from_err()
            // `fold` will asynchronously read each chunk of the request body and
            // call supplied closure, then it resolves to result of closure
            .fold(BytesMut::new(), move |mut body, chunk| {
                // limit max size of in-memory payload
                if (body.len() + chunk.len()) > max_size {
                    Err(error::ErrorBadRequest("overflow"))
                } else {
                    body.extend_from_slice(&chunk);
                    Ok(body)
                }
            })
            // `Future::and_then` can be used to merge an asynchronous workflow with a
            // synchronous workflow
            .and_then(
                move |body| -> Box<Future<Item = HttpResponse, Error = Error>> {
                    // body is loaded, now we can deserialize serde-json
                    // let r_obj = serde_json::from_slice::<SearchRequest>(&body);
                    let r_obj = serde_json::from_slice::<$message_type>(&body);

                    // Send to the db for create
                    match r_obj {
                        Ok(obj) => {
                            let res = $state
                                .qe
                                .send(
                                    // Could make this a .into_inner() and move?
                                    // event::SearchEvent::new(obj.filter),
                                    // <($event_type)>::from_request(obj),
                                    obj,
                                )
                                .from_err()
                                .and_then(|res| match res {
                                    Ok(event_result) => Ok(HttpResponse::Ok().json(event_result)),
                                    Err(e) => Ok(HttpResponse::InternalServerError().json(e)),
                                });

                            Box::new(res)
                        }
                        Err(e) => Box::new(future::err(error::ErrorBadRequest(format!(
                            "Json Decode Failed: {:?}",
                            e
                        )))),
                    }
                },
            )
    }};
}

// Handle the various end points we need to expose

fn create(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_event_decode!(req, state, CreateEvent, CreateRequest)
}

fn modify(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_event_decode!(req, state, ModifyEvent, ModifyRequest)
}

fn delete(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_event_decode!(req, state, DeleteEvent, DeleteRequest)
}

fn search(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_event_decode!(req, state, SearchEvent, SearchRequest)
}

// delete, modify

fn auth(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    let max_size = state.max_size;

    req.payload()
        .from_err()
        .fold(BytesMut::new(), move |mut body, chunk| {
            // limit max size of in-memory payload
            if (body.len() + chunk.len()) > max_size {
                Err(error::ErrorBadRequest("overflow"))
            } else {
                body.extend_from_slice(&chunk);
                Ok(body)
            }
        })
        .and_then(
            move |body| -> Box<Future<Item = HttpResponse, Error = Error>> {
                let r_obj = serde_json::from_slice::<AuthRequest>(&body);

                // Send to the db for action
                match r_obj {
                    Ok(obj) => {
                        // First, deal with some state management.
                        // Do anything here first that's needed like getting the session details
                        // out of the req cookie.
                        // let mut counter = 1;

                        // From the actix source errors here
                        // seems to be related to the serde_json deserialise of the cookie
                        // content, and because we control it's get/set it SHOULD be fine
                        // provided we use secure cookies. But we can't always trust that ...
                        let maybe_count = match req.session().get::<i32>("counter") {
                            Ok(c) => c,
                            Err(e) => {
                                return Box::new(future::err(e));
                            }
                        };

                        let c = match maybe_count {
                            Some(count) => {
                                println!("SESSION value: {}", count);
                                count + 1
                            }
                            None => {
                                println!("INIT value: 1");
                                1
                            }
                        };

                        match req.session().set("counter", c) {
                            Ok(_) => {}
                            Err(e) => {
                                return Box::new(future::err(e));
                            }
                        };

                        // We probably need to know if we allocate the cookie, that this is a
                        // new session, and in that case, anything *except* authrequest init is
                        // invalid.

                        let res = state.qe.send(obj).from_err().and_then(|res| match res {
                            Ok(event_result) => Ok(HttpResponse::Ok().json(event_result)),
                            Err(e) => Ok(HttpResponse::InternalServerError().json(e)),
                        });

                        Box::new(res)
                    }
                    Err(e) => Box::new(future::err(error::ErrorBadRequest(format!(
                        "Json Decode Failed: {:?}",
                        e
                    )))),
                }
            },
        )
}

fn whoami(req: &HttpRequest<AppState>) -> Result<&'static str> {
    println!("{:?}", req);

    // RequestSession trait is used for session access
    let mut counter = 1;
    if let Some(count) = req.session().get::<i32>("counter")? {
        println!("SESSION value: {}", count);
        counter = count + 1;
        req.session().set("counter", counter)?;
    } else {
        req.session().set("counter", counter)?;
    }

    Ok("welcome!")
}

pub fn create_server_core(config: Configuration) {
    // Configure the middleware logger
    ::std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    // Until this point, we probably want to write to stderr
    // Start up the logging system: for now it just maps to stderr

    // The log server is started on it's own thread
    let log_addr = log::start();
    log_event!(log_addr, "Starting rsidm with configuration: {:?}", config);

    // Similar, create a stats thread which aggregates statistics from the
    // server as they come in.

    // Start the query server with the given be path: future config
    let server_addr =
        match QueryServerV1::start(log_addr.clone(), config.db_path.as_str(), config.threads) {
            Ok(addr) => addr,
            Err(e) => {
                println!(
                    "An unknown failure in startup has occured - exiting -> {:?}",
                    e
                );
                return;
            }
        };

    // Setup timed events
    let _int_addr = IntervalActor::new(server_addr.clone()).start();

    // Copy the max size
    let max_size = config.maximum_request;
    let secure_cookies = config.secure_cookies;

    // start the web server
    actix_web::server::new(move || {
        App::with_state(AppState {
            qe: server_addr.clone(),
            max_size: max_size,
        })
        // Connect all our end points here.
        .middleware(middleware::Logger::default())
        .middleware(session::SessionStorage::new(
            // Signed prevents tampering. this 32 byte key MUST
            // be generated (probably stored in DB for cross-host access)
            session::CookieSessionBackend::signed(&[0; 32])
                .path("/")
                //.max_age() duration of the token life TODO make this proper!
                .domain("localhost")
                .same_site(cookie::SameSite::Strict) // constrain to the domain
                // Disallow from js
                .http_only(true)
                .name("rsidm-session")
                // This forces https only
                .secure(secure_cookies),
        ))
        // .resource("/", |r| r.f(index))
        // curl --header ...?
        .resource("/v1/whoami", |r| r.f(whoami))
        // .resource("/v1/login", ...)
        // .resource("/v1/logout", ...)
        // .resource("/v1/token", ...) generate a token for id servers to use
        //    on clients, IE linux machines. Workflow being login -> token
        //    containing group uuids and information needed, as well as a
        //    set of data for user stuff
        // curl --header "Content-Type: application/json" --request POST --data '{ "entries": [ {"attrs": {"class": ["group"], "name": ["testgroup"], "description": ["testperson"]}}]}'  http://127.0.0.1:8080/v1/create
        .resource("/v1/create", |r| {
            r.method(http::Method::POST).with_async(create)
        })
        // Should these actually be different method types?
        .resource("/v1/modify", |r| {
            r.method(http::Method::POST).with_async(modify)
        })
        .resource("/v1/delete", |r| {
            r.method(http::Method::POST).with_async(delete)
        })
        // curl --header "Content-Type: application/json" --request POST --data '{ "filter" : { "Eq": ["class", "user"] }}'  http://127.0.0.1:8080/v1/search
        .resource("/v1/search", |r| {
            r.method(http::Method::POST).with_async(search)
        })
        // This is one of the times we need cookies :)
        // curl -b /tmp/cookie.jar -c /tmp/cookie.jar --header "Content-Type: application/json" --request POST --data '{ "state" : { "Init": ["Anonymous", []] }}'  http://127.0.0.1:8080/v1/auth
        .resource("/v1/auth", |r| {
            r.method(http::Method::POST).with_async(auth)
        })
        // Add an ldap compat search function type?
        /*
        .resource("/v1/list/{class_list}", |r| {
            r.method(http::Method::GET).with(class_list)
        })
        */
    })
    .bind(config.address)
    .expect("Failed to initialise server!")
    .start();
}
