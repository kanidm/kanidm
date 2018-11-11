extern crate serde;
extern crate serde_json;
// #[macro_use]
extern crate actix;
extern crate actix_web;
extern crate bytes;
extern crate env_logger;
extern crate futures;
extern crate serde_derive;
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
use rsidm::event;
use rsidm::filter::Filter;
use rsidm::log;
use rsidm::proto::SearchRequest;
use rsidm::server;

const MAX_SIZE: usize = 262_144; //256k

struct AppState {
    qe: actix::Addr<server::QueryServer>,
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
            event::SearchEvent::new(filt),
        )
        // TODO: How to time this part of the code?
        // What does this do?
        .from_err()
        .and_then(|res| match res {
            // What type is entry?
            Ok(event::EventResult::Search { entries }) => Ok(HttpResponse::Ok().json(entries)),
            Ok(_) => Ok(HttpResponse::Ok().into()),
            // Can we properly report this?
            Err(_) => Ok(HttpResponse::InternalServerError().into()),
        })
        // What does this do?
        .responder()
}

// Based on actix web example json
fn search(req: &HttpRequest<AppState>) -> Box<Future<Item = HttpResponse, Error = Error>> {
    println!("{:?}", req);
    // HttpRequest::payload() is stream of Bytes objects
    req.payload()
        .from_err()
        // `fold` will asynchronously read each chunk of the request body and
        // call supplied closure, then it resolves to result of closure
        .fold(BytesMut::new(), move |mut body, chunk| {
            // limit max size of in-memory payload
            if (body.len() + chunk.len()) > MAX_SIZE {
                Err(error::ErrorBadRequest("Request size too large."))
            } else {
                body.extend_from_slice(&chunk);
                Ok(body)
            }
        })
        .and_then(|body| {
            // body is loaded, now we can deserialize serde-json
            // FIXME: THIS IS FUCKING AWFUL
            let obj = serde_json::from_slice::<SearchRequest>(&body).unwrap();
            // Dispatch a search
            println!("{:?}", obj);
            // We have to resolve this NOW else we break everything :(
            /*
            req.state().qe.send(
                event::SearchEvent::new(obj.filter)
            )
            .from_err()
            .and_then(|res| future::result(match res {
                // What type is entry?
                Ok(event::EventResult::Search { entries }) => Ok(HttpResponse::Ok().json(entries)),
                Ok(_) => Ok(HttpResponse::Ok().into()),
                // Can we properly report this?
                Err(_) => Ok(HttpResponse::InternalServerError().into()),
            }))
            */
            Ok(HttpResponse::InternalServerError().into())
        })
        .responder()
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
        .resource("/search", |r| r.method(http::Method::POST).a(search))
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
