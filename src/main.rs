extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate actix;
extern crate actix_web;
extern crate futures;
extern crate uuid;

use actix::prelude::*;
use actix_web::{
    http, middleware, App, AsyncResponder, FutureResponse, HttpRequest, HttpResponse, Path, State,
};

use futures::Future;

#[macro_use]
extern crate rsidm;
use rsidm::be;
use rsidm::event;
use rsidm::log::{self, EventLog};
use rsidm::server;

struct AppState {
    qe: actix::Addr<server::QueryServer>,
}

// Handle the various end points we need to expose

/// simple handle
fn index(req: &HttpRequest<AppState>) -> HttpResponse {
    println!("{:?}", req);

    HttpResponse::Ok().body("Hello\n")
}

fn class_list((name, state): (Path<String>, State<AppState>)) -> FutureResponse<HttpResponse> {
    // println!("request to class_list");
    state
        .qe
        .send(
            // This is where we need to parse the request into an event
            // LONG TERM
            // Make a search REQUEST, and create the audit struct here, then
            // pass it to the server
            event::SearchEvent::new()
        )
        // TODO: How to time this part of the code?
        // What does this do?
        .from_err()
        .and_then(|res| match res {
            // What type is entry?
            Ok(event::EventResult::Search{ entries }) => Ok(HttpResponse::Ok().json(entries)),
            Ok(_) => Ok(HttpResponse::Ok().into()),
            // Can we properly report this?
            Err(_) => Ok(HttpResponse::InternalServerError().into()),
        })
        // What does this do?
        .responder()
}

fn main() {
    let sys = actix::System::new("rsidm-server");

    // read the config (if any?)
    // How do we make the config accesible to all threads/workers? clone it?
    // Make it an Arc<Config>?

    // Until this point, we probably want to write to stderr
    // Start up the logging system: for now it just maps to stderr
    let log_addr = log::start();

    // Starting the BE chooses the path.
    // let be_addr = be::start(log_addr.clone(), be::BackendType::SQLite, "test.db", 8);

    // Start the query server with the given be
    let server_addr = server::start(log_addr.clone(), "test.db", 8);

    // start the web server
    actix_web::server::new(move || {
        App::with_state(AppState {
            qe: server_addr.clone(),
        })
        // Connect all our end points here.
        // .middleware(middleware::Logger::default())
        .resource("/", |r| r.f(index))
        .resource("/{class_list}", |r| r.method(http::Method::GET).with(class_list))
        .resource("/{class_list}/", |r| r.method(http::Method::GET).with(class_list))
    }).bind("127.0.0.1:8080")
    .unwrap()
    .start();

    log_event!(log_addr, "Starting rsidm on http://127.0.0.1:8080");

    // all the needed routes / views

    let _ = sys.run();
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_simple_create() {
        println!("It works!");
    }
}
