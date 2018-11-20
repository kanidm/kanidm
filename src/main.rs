extern crate actix;
extern crate actix_web;
extern crate bytes;
extern crate env_logger;
extern crate futures;
extern crate serde;
extern crate serde_derive;
extern crate serde_json;
extern crate uuid;

// use actix::prelude::*;
use actix_web::{
    error, http, middleware, App, AsyncResponder, Error, FutureResponse, HttpMessage, HttpRequest,
    HttpResponse, Path, State,
};

use bytes::BytesMut;
use futures::{future, Future, Stream};

#[macro_use]
extern crate rsidm;
use rsidm::event::{CreateEvent, EventResult, SearchEvent};
use rsidm::filter::Filter;
use rsidm::log;
use rsidm::proto::{CreateRequest, SearchRequest};
use rsidm::server;

const MAX_SIZE: usize = 262_144; //256k - this is the upper bound on create/search etc.

struct AppState {
    qe: actix::Addr<server::QueryServer>,
}

macro_rules! json_event_decode {
    ($req:expr, $state:expr, $event_type:ty, $message_type:ty) => {{
        // HttpRequest::payload() is stream of Bytes objects
        $req.payload()
            // `Future::from_err` acts like `?` in that it coerces the error type from
            // the future into the final error type
            .from_err()
            // `fold` will asynchronously read each chunk of the request body and
            // call supplied closure, then it resolves to result of closure
            .fold(BytesMut::new(), move |mut body, chunk| {
                // limit max size of in-memory payload
                if (body.len() + chunk.len()) > MAX_SIZE {
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
                                    <($event_type)>::new(obj),
                                )
                                .from_err()
                                .and_then(|res| match res {
                                    Ok(entries) => Ok(HttpResponse::Ok().json(entries)),
                                    Err(_) => Ok(HttpResponse::InternalServerError().into()),
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
            SearchEvent::new(SearchRequest::new(filt)),
        )
        // TODO: How to time this part of the code?
        // What does this do?
        .from_err()
        .and_then(|res| match res {
            // What type is entry?
            Ok(EventResult::Search { entries }) => Ok(HttpResponse::Ok().json(entries)),
            Ok(_) => Ok(HttpResponse::Ok().into()),
            // Can we properly report this?
            Err(_) => Ok(HttpResponse::InternalServerError().into()),
        })
        // What does this do?
        .responder()
}

fn create(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_event_decode!(req, state, CreateEvent, CreateRequest)
}

fn search(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_event_decode!(req, state, SearchEvent, SearchRequest)
}

fn main() {
    // Configure the middleware logger
    ::std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();

    let sys = actix::System::new("rsidm-server");

    // read the config (if any?)
    // How do we make the config accesible to all threads/workers? clone it?
    // Make it an Arc<Config>?

    // Until this point, we probably want to write to stderr
    // Start up the logging system: for now it just maps to stderr
    let log_addr = log::start();

    // Start the query server with the given be path: future config
    let server_addr = server::start(log_addr.clone(), "test.db", 8);

    // start the web server
    actix_web::server::new(move || {
        App::with_state(AppState {
            qe: server_addr.clone(),
        })
        // Connect all our end points here.
        .middleware(middleware::Logger::default())
        .resource("/", |r| r.f(index))
        // curl --header "Content-Type: application/json" --request POST --data '{ "entries": [ {"attrs": {"class": ["group"], "name": ["testgroup"], "description": ["testperson"]}}]}'  http://127.0.0.1:8080/create
        .resource("/create", |r| {
            r.method(http::Method::POST).with_async(create)
        })
        // curl --header "Content-Type: application/json" --request POST --data '{ "filter" : { "Eq": ["class", "user"] }}'  http://127.0.0.1:8080/search
        .resource("/search", |r| {
            r.method(http::Method::POST).with_async(search)
        })
        // Add an ldap compat search function type?
        .resource("/list/{class_list}", |r| {
            r.method(http::Method::GET).with(class_list)
        })
        .resource("/list/{class_list}/", |r| {
            r.method(http::Method::GET).with(class_list)
        })
    })
    .bind("127.0.0.1:8080")
    .unwrap()
    .start();

    log_event!(log_addr, "Starting rsidm on http://127.0.0.1:8080");
    // curl --header "Content-Type: application/json" --request POST --data '{"name":"xyz","number":3}'  http://127.0.0.1:8080/manual

    // all the needed routes / views

    let _ = sys.run();
}
