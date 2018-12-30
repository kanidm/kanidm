use actix::prelude::*;

use audit::AuditScope;
use be::{Backend, BackendError};

use entry::Entry;
use error::OperationError;
use event::{CreateEvent, OpResult, SearchEvent, SearchResult};
use log::EventLog;
use plugins::Plugins;
use schema::Schema;

pub fn start(log: actix::Addr<EventLog>, path: &str, threads: usize) -> actix::Addr<QueryServer> {
    let mut audit = AuditScope::new("server_start");
    let log_inner = log.clone();

    let qs_addr = audit_segment!(audit, || {
        // Create the BE connection
        // probably need a config type soon ....

        // Create a new backend audit scope
        let mut audit_be = AuditScope::new("backend_new");
        let be = Backend::new(&mut audit_be, path);
        audit.append_scope(audit_be);

        let mut schema = Schema::new();
        schema.bootstrap_core();
        // now we clone it out in the startup I think
        // Should the be need a log clone ref? or pass it around?
        // it probably needs it ...
        // audit.end_event("server_new");
        SyncArbiter::start(threads, move || {
            QueryServer::new(log_inner.clone(), be.clone(), schema.clone())
        })
    });
    log.do_send(audit);
    qs_addr
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
    schema: Schema,
}

impl QueryServer {
    pub fn new(log: actix::Addr<EventLog>, be: Backend, schema: Schema) -> Self {
        log_event!(log, "Starting query worker ...");
        QueryServer {
            log: log,
            be: be,
            schema: schema,
        }
    }

    // Actually conduct a search request
    // This is the core of the server, as it processes the entire event
    // applies all parts required in order and more.
    pub fn search(
        &mut self,
        au: &mut AuditScope,
        se: &SearchEvent,
    ) -> Result<Vec<Entry>, OperationError> {
        // TODO: Validate the filter
        // This is an important security step because it prevents us from
        // performing un-indexed searches on attr's that don't exist in the
        // server. This is why ExtensibleObject can only take schema that
        // exists in the server, not arbitrary attr names.

        // TODO: Normalise the filter

        // TODO: Pre-search plugins

        let mut audit_be = AuditScope::new("backend_search");
        let res = self
            .be
            .search(&mut audit_be, &se.filter)
            .map(|r| r)
            .map_err(|_| OperationError::Backend);
        au.append_scope(audit_be);

        // TODO: Post-search plugins

        // TODO: We'll add ACI here. I think ACI should transform from
        // internal -> proto entries since we have to anyway ...
        // alternately, we can just clone again ...
        res
    }

    pub fn create(&mut self, au: &mut AuditScope, ce: &CreateEvent) -> Result<(), OperationError> {
        // The create event is a raw, read only representation of the request
        // that was made to us, including information about the identity
        // performing the request.

        // Log the request

        // TODO: Do we need limits on number of creates, or do we constraint
        // based on request size in the frontend?

        // Copy the entries to a writeable form.
        let mut candidates: Vec<Entry> = ce.entries.iter().map(|er| er.clone()).collect();

        // Start a txn

        // run any pre plugins, giving them the list of mutable candidates.
        // pre-plugins are defined here in their correct order of calling!
        // I have no intent to make these dynamic or configurable.

        let mut audit_plugin_pre = AuditScope::new("plugin_pre_create");
        let plug_pre_res = Plugins::run_pre_create(
            &mut self.be,
            &mut audit_plugin_pre,
            &mut candidates,
            ce,
            &self.schema,
        );
        au.append_scope(audit_plugin_pre);

        if plug_pre_res.is_err() {
            audit_log!(au, "Create operation failed (plugin), {:?}", plug_pre_res);
            return plug_pre_res;
        }

        let r = candidates.iter().fold(Ok(()), |acc, e| {
            if acc.is_ok() {
                self.schema
                    .validate_entry(e)
                    .map_err(|_| OperationError::SchemaViolation)
            } else {
                acc
            }
        });
        if r.is_err() {
            audit_log!(au, "Create operation failed (schema), {:?}", r);
            return r;
        }

        // FIXME: Normalise all entries now.

        let mut audit_be = AuditScope::new("backend_create");
        // We may change from ce.entries later to something else?
        let res = self
            .be
            .create(&mut audit_be, &candidates)
            .map(|_| ())
            .map_err(|e| match e {
                BackendError::EmptyRequest => OperationError::EmptyRequest,
                _ => OperationError::Backend,
            });
        au.append_scope(audit_be);

        if res.is_err() {
            audit_log!(au, "Create operation failed (backend), {:?}", r);
            return res;
        }
        // Run any post plugins

        // Commit the txn

        // We are complete, finalise logging and return

        audit_log!(au, "Create operation success");
        res
    }
}

impl Actor for QueryServer {
    type Context = SyncContext<Self>;

    /*
    fn started(&mut self, ctx: &mut Self::Context) {
        ctx.set_mailbox_capacity(1 << 31);
    }
    */
}

// The server only recieves "Event" structures, which
// are whole self contained DB operations with all parsing
// required complete. We still need to do certain validation steps, but
// at this point our just is just to route to do_<action>

impl Handler<SearchEvent> for QueryServer {
    type Result = Result<SearchResult, OperationError>;

    fn handle(&mut self, msg: SearchEvent, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("search");
        let res = audit_segment!(&mut audit, || {
            audit_log!(audit, "Begin event {:?}", msg);

            // Parse what we need from the event?
            // What kind of event is it?

            // In the future we'll likely change search event ...

            // was this ok?
            match self.search(&mut audit, &msg) {
                Ok(entries) => Ok(SearchResult::new(entries)),
                Err(e) => Err(e),
            }

            // audit_log!(audit, "End event {:?}", msg);
            // audit.end_event("search");
        });
        // At the end of the event we send it for logging.
        self.log.do_send(audit);
        res
    }
}

impl Handler<CreateEvent> for QueryServer {
    type Result = Result<OpResult, OperationError>;

    fn handle(&mut self, msg: CreateEvent, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("create");
        let res = audit_segment!(&mut audit, || {
            audit_log!(audit, "Begin create event {:?}", msg);

            match self.create(&mut audit, &msg) {
                Ok(()) => Ok(OpResult {}),
                Err(e) => Err(e),
            }
        });
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

    use super::super::audit::AuditScope;
    use super::super::be::Backend;
    use super::super::entry::Entry;
    use super::super::event::{CreateEvent, SearchEvent};
    use super::super::filter::Filter;
    use super::super::log;
    use super::super::proto_v1::Entry as ProtoEntry;
    use super::super::proto_v1::{CreateRequest, SearchRequest};
    use super::super::schema::Schema;
    use super::super::server::QueryServer;

    macro_rules! run_test {
        ($test_fn:expr) => {{
            System::run(|| {
                let mut audit = AuditScope::new("run_test");
                let test_log = log::start();

                let be = Backend::new(&mut audit, "");
                let mut schema = Schema::new();
                schema.bootstrap_core();
                let test_server = QueryServer::new(test_log.clone(), be, schema);

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
        run_test!(|_log, mut server: QueryServer, audit: &mut AuditScope| {
            let filt = Filter::Pres(String::from("name"));

            let se1 = SearchEvent::from_request(SearchRequest::new(filt.clone()));
            let se2 = SearchEvent::from_request(SearchRequest::new(filt));

            let e: Entry = serde_json::from_str(
                r#"{
                "attrs": {
                    "class": ["object", "person"],
                    "name": ["testperson"],
                    "uuid": ["cc8e95b4-c24f-4d68-ba54-8bed76f63930"],
                    "description": ["testperson"],
                    "displayname": ["testperson"]
                }
            }"#,
            )
            .unwrap();

            let expected = vec![e];

            let ce = CreateEvent::from_vec(expected.clone());

            let r1 = server.search(audit, &se1).unwrap();
            assert!(r1.len() == 0);

            let cr = server.create(audit, &ce);
            assert!(cr.is_ok());

            let r2 = server.search(audit, &se2).unwrap();
            println!("--> {:?}", r2);
            assert!(r2.len() == 1);

            assert_eq!(r2, expected);

            future::ok(())
        });
    }

    // Test Create Empty

    //
}
