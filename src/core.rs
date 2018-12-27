use actix::SystemRunner;
use actix_web::{
    error, http, middleware, App, AsyncResponder, Error, FutureResponse, HttpMessage, HttpRequest,
    HttpResponse, Path, State,
};

use bytes::BytesMut;
use futures::{future, Future, Stream};

use super::config::Configuration;
use super::event::{CreateEvent, SearchEvent, SearchResult};
use super::filter::Filter;
use super::log;
use super::proto_v1::{CreateRequest, Response, SearchRequest, SearchResponse};
use super::server;

struct AppState {
    qe: actix::Addr<server::QueryServer>,
    max_size: usize,
}

macro_rules! json_event_decode {
    ($req:expr, $state:expr, $event_type:ty, $response_type:ty, $message_type:ty) => {{
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
                                    <($event_type)>::from_request(obj),
                                )
                                .from_err()
                                .and_then(|res| match res {
                                    Ok(event_result) => {
                                        Ok(HttpResponse::Ok().json(event_result.response()))
                                    }
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

/// simple handle
fn index(req: &HttpRequest<AppState>) -> HttpResponse {
    println!("{:?}", req);

    HttpResponse::Ok().body("Hello\n")
}

fn class_list((_name, state): (Path<String>, State<AppState>)) -> FutureResponse<HttpResponse> {
    // println!("request to class_list");
    let filt = Filter::Pres(String::from("objectclass"));

    state
        .qe
        .send(
            // This is where we need to parse the request into an event
            // LONG TERM
            // Make a search REQUEST, and create the audit struct here, then
            // pass it to the server
            //
            // FIXME: Don't use SEARCHEVENT here!!!!
            //
            SearchEvent::from_request(SearchRequest::new(filt)),
        )
        // TODO: How to time this part of the code?
        // What does this do?
        .from_err()
        .and_then(|res| match res {
            // What type is entry?
            Ok(search_result) => Ok(HttpResponse::Ok().json(search_result.response())),
            // Ok(_) => Ok(HttpResponse::Ok().into()),
            // Can we properly report this?
            Err(_) => Ok(HttpResponse::InternalServerError().into()),
        })
        // What does this do?
        .responder()
}

fn create(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_event_decode!(req, state, CreateEvent, Response, CreateRequest)
}

fn search(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_event_decode!(req, state, SearchEvent, SearchResponse, SearchRequest)
}

pub fn create_server_core(config: Configuration) {
    // Configure the middleware logger
    ::std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    // Until this point, we probably want to write to stderr
    // Start up the logging system: for now it just maps to stderr
    let log_addr = log::start();
    log_event!(log_addr, "Starting rsidm with configuration: {:?}", config);

    // Start the query server with the given be path: future config
    let server_addr = server::start(log_addr.clone(), config.db_path.as_str(), config.threads);
    // Copy the max size
    let max_size = config.maximum_request;

    // start the web server
    actix_web::server::new(move || {
        App::with_state(AppState {
            qe: server_addr.clone(),
            max_size: max_size,
        })
        // Connect all our end points here.
        .middleware(middleware::Logger::default())
        .resource("/", |r| r.f(index))
        // curl --header "Content-Type: application/json" --request POST --data '{ "entries": [ {"attrs": {"class": ["group"], "name": ["testgroup"], "description": ["testperson"]}}]}'  http://127.0.0.1:8080/v1/create
        .resource("/v1/create", |r| {
            r.method(http::Method::POST).with_async(create)
        })
        // curl --header "Content-Type: application/json" --request POST --data '{ "filter" : { "Eq": ["class", "user"] }}'  http://127.0.0.1:8080/v1/search
        .resource("/v1/search", |r| {
            r.method(http::Method::POST).with_async(search)
        })
        // Add an ldap compat search function type?
        .resource("/v1/list/{class_list}", |r| {
            r.method(http::Method::GET).with(class_list)
        })
    })
    .bind(config.address)
    .unwrap()
    .start();
}
