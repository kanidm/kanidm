use actix::prelude::*;

use be::Backend;
use entry::Entry;
use event::{CreateEvent, EventResult, SearchEvent};
use log::EventLog;

pub fn start(
    log: actix::Addr<EventLog>,
    // be: actix::Addr<BackendActor>,
    path: &str,
    threads: usize,
) -> actix::Addr<QueryServer> {
    // Create the BE connection
    // probably need a config type soon ....
    let be = Backend::new(log.clone(), path);
    // now we clone it out in the startup I think
    // Should the be need a log clone ref? or pass it around?
    // it probably needs it ...
    SyncArbiter::start(threads, move || QueryServer::new(log.clone(), be.clone()))
}

// This is the core of the server. It implements all
// the search and modify actions, applies access controls
// and get's everything ready to push back to the fe code

// This is it's own actor, so we can have a write addr and a read addr,
// and it allows serialisation that way rather than relying on
// the backend

pub struct QueryServer {
    log: actix::Addr<EventLog>,
    // be: actix::Addr<BackendActor>,
    // This probably needs to be Arc, or a ref. How do we want to manage this?
    // I think the BE is build, configured and cloned? Maybe Backend
    // is a wrapper type to Arc<BackendInner> or something.
    be: Backend,
}

impl QueryServer {
    pub fn new(log: actix::Addr<EventLog>, be: Backend) -> Self {
        log_event!(log, "Starting query worker ...");
        QueryServer { log: log, be: be }
    }

    // Actually conduct a search request
    // This is the core of the server, as it processes the entire event
    // applies all parts required in order and more.
    pub fn search(&mut self) -> Result<Vec<Entry>, ()> {
        Ok(Vec::new())
    }

    // What should this take?
    pub fn create(&mut self) -> Result<(), ()> {
        Ok(())
    }
}

impl Actor for QueryServer {
    type Context = SyncContext<Self>;
}

// The server only recieves "Event" structures, which
// are whole self contained DB operations with all parsing
// required complete. We still need to do certain validation steps, but
// at this point our just is just to route to do_<action>

impl Handler<SearchEvent> for QueryServer {
    type Result = Result<EventResult, ()>;

    fn handle(&mut self, msg: SearchEvent, _: &mut Self::Context) -> Self::Result {
        log_event!(self.log, "Begin event {:?}", msg);
        // Parse what we need from the event?
        // What kind of event is it?

        // was this ok?
        let res = match self.search() {
            Ok(entries) => Ok(EventResult::Search { entries: entries }),
            Err(e) => Err(e),
        };

        log_event!(self.log, "End event {:?}", msg);
        // At the end of the event we send it for logging.
        res
    }
}

impl Handler<CreateEvent> for QueryServer {
    type Result = Result<EventResult, ()>;

    fn handle(&mut self, msg: CreateEvent, _: &mut Self::Context) -> Self::Result {
        log_event!(self.log, "Begin event {:?}", msg);
        Err(())
    }
}

// Auth requests? How do we structure these ...

#[cfg(test)]
mod tests {
    extern crate actix;
    use actix::prelude::*;

    extern crate futures;
    use futures::future;
    use futures::future::lazy;
    use futures::future::Future;

    extern crate tokio;

    use super::super::be::Backend;
    use super::super::log::{self, EventLog, LogEvent};
    use super::super::server::QueryServer;

    macro_rules! run_test {
        ($test_fn:expr) => {{
            System::run(|| {
                let test_log = log::start();

                let mut be = Backend::new(test_log.clone(), "");
                let mut test_server = QueryServer::new(test_log.clone(), be);

                // Could wrap another future here for the future::ok bit...
                let fut = $test_fn(test_log, test_server);
                let comp_fut = fut.map_err(|()| ()).and_then(|r| {
                    println!("Stopping actix ...");
                    actix::System::current().stop();
                    future::result(Ok(()))
                });

                tokio::spawn(comp_fut);
            });
        }};
    }

    #[test]
    fn test_be_create_user() {
        run_test!(|log, mut server: QueryServer| {
            let r1 = server.search().unwrap();
            assert!(r1.len() == 0);

            let cr = server.create();
            assert!(cr.is_ok());

            let r2 = server.search().unwrap();
            assert!(r2.len() == 1);

            future::ok(())
        });
    }
}
