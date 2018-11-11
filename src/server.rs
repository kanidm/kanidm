use actix::prelude::*;

use audit::AuditEvent;
use be::Backend;
use entry::Entry;
use event::{CreateEvent, EventResult, SearchEvent};
use log::EventLog;

pub fn start(log: actix::Addr<EventLog>, path: &str, threads: usize) -> actix::Addr<QueryServer> {
    let mut audit = AuditEvent::new();
    audit.start_event("server_new");
    // Create the BE connection
    // probably need a config type soon ....
    let be = Backend::new(&mut audit, path);
    // now we clone it out in the startup I think
    // Should the be need a log clone ref? or pass it around?
    // it probably needs it ...
    audit.end_event("server_new");
    log.do_send(audit);
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
    pub fn search(&mut self, au: &mut AuditEvent, se: &SearchEvent) -> Result<Vec<Entry>, ()> {
        match self.be.search(au, &se.filter) {
            Ok(r) => Ok(r),
            Err(_) => Err(()),
        }
    }

    // What should this take?
    // This should probably take raw encoded entries? Or sohuld they
    // be handled by fe?
    pub fn create(&mut self, au: &mut AuditEvent, ce: &CreateEvent) -> Result<(), ()> {
        // Start a txn
        // Run any pre checks
        // We may change from ce.entries later to something else?
        match self.be.create(au, &ce.entries) {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
        // Run and post checks
        // Commit/Abort the txn
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
        let mut audit = AuditEvent::new();
        audit.start_event("search");
        audit_log!(audit, "Begin event {:?}", msg);

        // Parse what we need from the event?
        // What kind of event is it?

        // In the future we'll likely change search event ...

        // was this ok?
        let res = match self.search(&mut audit, &msg) {
            Ok(entries) => Ok(EventResult::Search { entries: entries }),
            Err(e) => Err(e),
        };

        audit_log!(audit, "End event {:?}", msg);
        audit.end_event("search");
        // At the end of the event we send it for logging.
        self.log.do_send(audit);
        res
    }
}

impl Handler<CreateEvent> for QueryServer {
    type Result = Result<EventResult, ()>;

    fn handle(&mut self, msg: CreateEvent, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditEvent::new();
        audit.start_event("create");
        audit_log!(audit, "Begin create event {:?}", msg);

        let res = match self.create(&mut audit, &msg) {
            Ok(()) => Ok(EventResult::Create),
            Err(e) => Err(e),
        };

        audit_log!(audit, "End create event {:?}", msg);
        audit.end_event("create");
        // At the end of the event we send it for logging.
        self.log.do_send(audit);
        // At the end of the event we send it for logging.
        res
    }
}

// Auth requests? How do we structure these ...

#[cfg(test)]
mod tests {
    extern crate actix;
    use actix::prelude::*;

    extern crate futures;
    use futures::future;
    use futures::future::Future;

    extern crate tokio;

    use super::super::audit::AuditEvent;
    use super::super::be::Backend;
    use super::super::entry::Entry;
    use super::super::event::{CreateEvent, SearchEvent};
    use super::super::filter::Filter;
    use super::super::log;
    use super::super::server::QueryServer;

    macro_rules! run_test {
        ($test_fn:expr) => {{
            System::run(|| {
                let mut audit = AuditEvent::new();
                let test_log = log::start();

                let be = Backend::new(&mut audit, "");
                let test_server = QueryServer::new(test_log.clone(), be);

                // Could wrap another future here for the future::ok bit...
                let fut = $test_fn(test_log.clone(), test_server, &mut audit);
                let comp_fut = fut.map_err(|()| ()).and_then(move |_r| {
                    test_log.do_send(audit);
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
        run_test!(|_log, mut server: QueryServer, audit: &mut AuditEvent| {
            let filt = Filter::Pres(String::from("userid"));

            let se1 = SearchEvent::new(filt.clone());
            let se2 = SearchEvent::new(filt);

            let mut e: Entry = Entry::new();
            e.add_ava(String::from("userid"), String::from("william"))
                .unwrap();

            let expected = vec![e];

            let ce = CreateEvent::new(expected.clone());

            let r1 = server.search(audit, &se1).unwrap();
            assert!(r1.len() == 0);

            let cr = server.create(audit, &ce);
            assert!(cr.is_ok());

            let r2 = server.search(audit, &se2).unwrap();
            assert!(r2.len() == 1);

            assert_eq!(r2, expected);

            future::ok(())
        });
    }
}
