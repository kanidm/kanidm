extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate diesel;
extern crate actix;
extern crate actix_web;
extern crate r2d2;
extern crate uuid;
extern crate futures;

use actix::prelude::*;
use actix_web::{
    http, middleware, App, AsyncResponder, FutureResponse, HttpResponse, Path, HttpRequest,
    State,
};

use diesel::prelude::*;
use diesel::r2d2::ConnectionManager;
use futures::Future;

mod be;
mod entry;
mod server;
mod log;
mod event;

// Helper for internal logging.
macro_rules! log_event {
    ($log_addr:expr, $($arg:tt)*) => ({
        use log::LogEvent;
        $log_addr.do_send(
            LogEvent {
                msg: std::fmt::format(
                    format_args!($($arg)*)
                )
            }
        )
    })
}

struct AppState {
    qe: actix::Addr<server::QueryServer>,
}

// Handle the various end points we need to expose

/// simple handle
fn index(req: &HttpRequest<AppState>) -> HttpResponse {
    println!("{:?}", req);

    HttpResponse::Ok().body("Hello\n")
}

fn class_list(
    (name, state): (Path<String>, State<AppState>),
) -> FutureResponse<HttpResponse>
{
    // println!("request to class_list");
    state
        .qe
        .send(
            server::ListClass {
                class_name: name.into_inner(),
            }
        )
        // What does this do?
        .from_err()
        .and_then(|res| match res {
            // What type is entry?
            Ok(entry) => Ok(HttpResponse::Ok().json(entry)),
            // Can we properly report this?
            Err(_) => Ok(HttpResponse::InternalServerError().into()),
        })
        // What does this do?
        .responder()
}

fn main() {
    let sys = actix::System::new("rsidm-server");

    // read the config (if any?)

    // Until this point, we probably want to write to stderr
    // Start up the logging system: for now it just maps to stderr
    let log_addr = log::start();

    // Starting the BE chooses the path.
    let be_addr = be::start(log_addr.clone(), be::BackendType::SQLite, "test.db");

    // Start the query server with the given be
    let server_addr = server::start(log_addr.clone(), be_addr);

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

    })
        .bind("127.0.0.1:8080")
        .unwrap()
        .start();

    log_event!(log_addr, "Starting rsidm on 127.0.0.1:8080");

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


