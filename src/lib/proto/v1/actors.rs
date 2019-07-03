use actix::prelude::*;
use std::sync::Arc;

use crate::audit::AuditScope;
use crate::be::Backend;

use crate::error::OperationError;
use crate::event::{
    AuthEvent, AuthResult, CreateEvent, DeleteEvent, ModifyEvent, PurgeRecycledEvent,
    PurgeTombstoneEvent, SearchEvent, SearchResult, WhoamiResult,
};
use crate::log::EventLog;
use crate::schema::{Schema, SchemaTransaction};

use crate::constants::UUID_ANONYMOUS;
use crate::idm::server::IdmServer;
use crate::server::{QueryServer, QueryServerTransaction};

use crate::proto::v1::{
    AuthRequest, AuthResponse, AuthState, CreateRequest, DeleteRequest, ModifyRequest,
    OperationResponse, SearchRequest, SearchResponse, UserAuthToken, WhoamiRequest, WhoamiResponse,
};

use crate::proto::v1::messages::{AuthMessage, WhoamiMessage};

pub struct QueryServerV1 {
    log: actix::Addr<EventLog>,
    qs: QueryServer,
    idms: IdmServer,
}

impl Actor for QueryServerV1 {
    type Context = SyncContext<Self>;

    fn started(&mut self, _ctx: &mut Self::Context) {
        // ctx.set_mailbox_capacity(1 << 31);
    }
}

impl QueryServerV1 {
    pub fn new(log: actix::Addr<EventLog>, qs: QueryServer) -> Self {
        log_event!(log, "Starting query server v1 worker ...");
        QueryServerV1 {
            log: log,
            qs: qs.clone(),
            idms: IdmServer::new(qs),
        }
    }

    // TODO: We could move most of the be/schema/qs setup and startup
    // outside of this call, then pass in "what we need" in a cloneable
    // form, this way we could have seperate Idm vs Qs threads, and dedicated
    // threads for write vs read
    pub fn start(
        log: actix::Addr<EventLog>,
        path: &str,
        threads: usize,
    ) -> Result<actix::Addr<QueryServerV1>, OperationError> {
        let mut audit = AuditScope::new("server_start");
        let log_inner = log.clone();

        let qs_addr: Result<actix::Addr<QueryServerV1>, _> = audit_segment!(audit, || {
            // Create "just enough" schema for us to be able to load from
            // disk ... Schema loading is one time where we validate the
            // entries as we read them, so we need this here.
            let schema = match Schema::new(&mut audit) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };

            // Create a new backend audit scope
            let mut audit_be = AuditScope::new("backend_new");
            let be = match Backend::new(&mut audit_be, path) {
                Ok(be) => be,
                Err(e) => return Err(e),
            };
            audit.append_scope(audit_be);

            {
                let be_txn = be.write();
                let mut schema_write = schema.write();

                // Now, we have the initial schema in memory. Use this to trigger
                // an index of the be for the core schema.

                // Now search for the schema itself, and validate that the system
                // in memory matches the BE on disk, and that it's syntactically correct.
                // Write it out if changes are needed.

                // Now load the remaining backend schema into memory.
                // TODO: Schema elements should be versioned individually.
                match schema_write
                    .bootstrap_core(&mut audit)
                    // TODO: Backend setup indexes as needed from schema, for the core
                    // system schema.
                    // TODO: Trigger an index? This could be costly ...
                    //   Perhaps a config option to say if we index on startup or not.
                    // TODO: Check the results!
                    .and_then(|_| {
                        let r = schema_write.validate(&mut audit);
                        if r.len() == 0 {
                            Ok(())
                        } else {
                            Err(OperationError::ConsistencyError(r))
                        }
                    })
                    .and_then(|_| be_txn.commit())
                    .and_then(|_| schema_write.commit())
                {
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
            }

            // Create a query_server implementation
            let query_server = QueryServer::new(be, schema);

            let mut audit_qsc = AuditScope::new("query_server_init");
            // This may need to be two parts, one for schema, one for everything else
            // that way we can reload schema in between.
            let query_server_write = query_server.write();
            match query_server_write.initialise(&mut audit_qsc).and_then(|_| {
                audit_segment!(audit_qsc, || query_server_write.commit(&mut audit_qsc))
            }) {
                // We are good to go! Finally commit and consume the txn.
                Ok(_) => {}
                Err(e) => return Err(e),
            };
            // What's important about this initial setup here is that it also triggers
            // the schema and acp reload, so they are now configured correctly!

            audit.append_scope(audit_qsc);

            let x = SyncArbiter::start(threads, move || {
                QueryServerV1::new(log_inner.clone(), query_server.clone())
            });
            Ok(x)
        });
        log.do_send(audit);
        qs_addr
    }
}

// The server only recieves "Event" structures, which
// are whole self contained DB operations with all parsing
// required complete. We still need to do certain validation steps, but
// at this point our just is just to route to do_<action>

impl Handler<SearchRequest> for QueryServerV1 {
    type Result = Result<SearchResponse, OperationError>;

    fn handle(&mut self, msg: SearchRequest, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("search");
        let res = audit_segment!(&mut audit, || {
            // Begin a read
            let qs_read = self.qs.read();

            // Make an event from the request
            let srch = match SearchEvent::from_request(&mut audit, msg, &qs_read) {
                Ok(s) => s,
                Err(e) => {
                    audit_log!(audit, "Failed to begin search: {:?}", e);
                    return Err(e);
                }
            };

            audit_log!(audit, "Begin event {:?}", srch);

            match qs_read.search_ext(&mut audit, &srch) {
                Ok(entries) => {
                    let sr = SearchResult::new(entries);
                    // Now convert to a response, and return
                    Ok(sr.response())
                }
                Err(e) => Err(e),
            }
        });
        // At the end of the event we send it for logging.
        self.log.do_send(audit);
        res
    }
}

impl Handler<CreateRequest> for QueryServerV1 {
    type Result = Result<OperationResponse, OperationError>;

    fn handle(&mut self, msg: CreateRequest, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("create");
        let res = audit_segment!(&mut audit, || {
            let qs_write = self.qs.write();

            let crt = match CreateEvent::from_request(&mut audit, msg, &qs_write) {
                Ok(c) => c,
                Err(e) => {
                    audit_log!(audit, "Failed to begin create: {:?}", e);
                    return Err(e);
                }
            };

            audit_log!(audit, "Begin create event {:?}", crt);

            qs_write
                .create(&mut audit, &crt)
                .and_then(|_| qs_write.commit(&mut audit).map(|_| OperationResponse {}))
        });
        // At the end of the event we send it for logging.
        self.log.do_send(audit);
        res
    }
}

impl Handler<ModifyRequest> for QueryServerV1 {
    type Result = Result<OperationResponse, OperationError>;

    fn handle(&mut self, msg: ModifyRequest, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("modify");
        let res = audit_segment!(&mut audit, || {
            let qs_write = self.qs.write();
            let mdf = match ModifyEvent::from_request(&mut audit, msg, &qs_write) {
                Ok(m) => m,
                Err(e) => {
                    audit_log!(audit, "Failed to begin modify: {:?}", e);
                    return Err(e);
                }
            };

            audit_log!(audit, "Begin modify event {:?}", mdf);

            qs_write
                .modify(&mut audit, &mdf)
                .and_then(|_| qs_write.commit(&mut audit).map(|_| OperationResponse {}))
        });
        self.log.do_send(audit);
        res
    }
}

impl Handler<DeleteRequest> for QueryServerV1 {
    type Result = Result<OperationResponse, OperationError>;

    fn handle(&mut self, msg: DeleteRequest, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("delete");
        let res = audit_segment!(&mut audit, || {
            let qs_write = self.qs.write();

            let del = match DeleteEvent::from_request(&mut audit, msg, &qs_write) {
                Ok(d) => d,
                Err(e) => {
                    audit_log!(audit, "Failed to begin delete: {:?}", e);
                    return Err(e);
                }
            };

            audit_log!(audit, "Begin delete event {:?}", del);

            qs_write
                .delete(&mut audit, &del)
                .and_then(|_| qs_write.commit(&mut audit).map(|_| OperationResponse {}))
        });
        self.log.do_send(audit);
        res
    }
}

// Need an auth session storage. LRU?
// requires a lock ...
// needs session id, entry, etc.

impl Handler<AuthMessage> for QueryServerV1 {
    type Result = Result<AuthResponse, OperationError>;

    fn handle(&mut self, msg: AuthMessage, _: &mut Self::Context) -> Self::Result {
        // This is probably the first function that really implements logic
        // "on top" of the db server concept. In this case we check if
        // the credentials provided is sufficient to say if someone is
        // "authenticated" or not.
        let mut audit = AuditScope::new("auth");
        let res = audit_segment!(&mut audit, || {
            audit_log!(audit, "Begin auth event {:?}", msg);

            // Destructure it.
            // Convert the AuthRequest to an AuthEvent that the idm server
            // can use.

            let mut idm_write = self.idms.write();

            let ae = AuthEvent::from_message(msg);

            // Generally things like auth denied are in Ok() msgs
            // so true errors should always trigger a rollback.
            let r = idm_write
                .auth(&mut audit, &ae)
                .and_then(|r| idm_write.commit().map(|_| r));

            audit_log!(audit, "Sending result -> {:?}", r);
            // Build the result.
            r.map(|r| r.response())
        });
        // At the end of the event we send it for logging.
        self.log.do_send(audit);
        res
    }
}

impl Handler<WhoamiMessage> for QueryServerV1 {
    type Result = Result<WhoamiResponse, OperationError>;

    fn handle(&mut self, msg: WhoamiMessage, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("whoami");
        let res = audit_segment!(&mut audit, || {
            // TODO: Move this to IdmServer!!!
            // Begin a read
            let qs_read = self.qs.read();

            // Make an event from the whoami request. This will process the event and
            // generate a selfuuid search.
            // FIXME: This current handles the unauthenticated check, and will
            // trigger the failure, but if we can manage to work out async
            // then move this to core.rs, and don't allow Option<UAT> to get
            // this far.
            let srch = match SearchEvent::from_whoami_request(&mut audit, msg.uat, &qs_read) {
                Ok(s) => s,
                Err(e) => {
                    audit_log!(audit, "Failed to begin whoami: {:?}", e);
                    return Err(e);
                }
            };

            audit_log!(audit, "Begin event {:?}", srch);

            match qs_read.search_ext(&mut audit, &srch) {
                Ok(mut entries) => {
                    // assert there is only one ...
                    match entries.len() {
                        0 => Err(OperationError::NoMatchingEntries),
                        1 => {
                            let e = entries.pop().expect("Entry length mismatch!!!");
                            // Now convert to a response, and return
                            let wr = WhoamiResult::new(e);
                            Ok(wr.response())
                        }
                        // Somehow we matched multiple, which should be impossible.
                        _ => Err(OperationError::InvalidState),
                    }
                }
                // Something else went wrong ...
                Err(e) => Err(e),
            }
        });
        // Should we log the final result?
        // At the end of the event we send it for logging.
        self.log.do_send(audit);
        res
    }
}

// These below are internal only types.

impl Handler<PurgeTombstoneEvent> for QueryServerV1 {
    type Result = ();

    fn handle(&mut self, msg: PurgeTombstoneEvent, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("purge tombstones");
        let res = audit_segment!(&mut audit, || {
            audit_log!(audit, "Begin purge tombstone event {:?}", msg);
            let qs_write = self.qs.write();

            let res = qs_write
                .purge_tombstones(&mut audit)
                .and_then(|_| qs_write.commit(&mut audit));
            audit_log!(audit, "Purge tombstones result: {:?}", res);
            res.expect("Invalid Server State");
        });
        // At the end of the event we send it for logging.
        self.log.do_send(audit);
        res
    }
}

impl Handler<PurgeRecycledEvent> for QueryServerV1 {
    type Result = ();

    fn handle(&mut self, msg: PurgeRecycledEvent, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("purge recycled");
        let res = audit_segment!(&mut audit, || {
            audit_log!(audit, "Begin purge recycled event {:?}", msg);
            let qs_write = self.qs.write();

            let res = qs_write
                .purge_recycled(&mut audit)
                .and_then(|_| qs_write.commit(&mut audit));
            audit_log!(audit, "Purge recycled result: {:?}", res);
            res.expect("Invalid Server State");
        });
        // At the end of the event we send it for logging.
        self.log.do_send(audit);
        res
    }
}
