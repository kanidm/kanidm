use std::sync::Arc;

use crate::audit::AuditScope;

use crate::async_log::EventLog;
use crate::event::{
    AuthEvent, CreateEvent, DeleteEvent, ModifyEvent, PurgeRecycledEvent, PurgeTombstoneEvent,
    SearchEvent, SearchResult, WhoamiResult,
};
use crate::idm::event::PasswordChangeEvent;
use kanidm_proto::v1::OperationError;

use crate::idm::server::IdmServer;
use crate::server::{QueryServer, QueryServerTransaction};

use kanidm_proto::v1::{
    AuthRequest, AuthResponse, CreateRequest, DeleteRequest, ModifyRequest, OperationResponse,
    SearchRequest, SearchResponse, SingleStringRequest, UserAuthToken, WhoamiResponse,
};

use actix::prelude::*;
use std::time::SystemTime;
use uuid::Uuid;

// These are used when the request (IE Get) has no intrising request
// type. Additionally, they are used in some requests where we need
// to supplement extra server state (IE userauthtokens) to a request.
//
// Generally we don't need to have the responses here because they are
// part of the protocol.

pub struct WhoamiMessage {
    pub uat: Option<UserAuthToken>,
}

impl WhoamiMessage {
    pub fn new(uat: Option<UserAuthToken>) -> Self {
        WhoamiMessage { uat: uat }
    }
}

impl Message for WhoamiMessage {
    type Result = Result<WhoamiResponse, OperationError>;
}

#[derive(Debug)]
pub struct AuthMessage {
    pub sessionid: Option<Uuid>,
    pub req: AuthRequest,
}

impl AuthMessage {
    pub fn new(req: AuthRequest, sessionid: Option<Uuid>) -> Self {
        AuthMessage {
            sessionid: sessionid,
            req: req,
        }
    }
}

impl Message for AuthMessage {
    type Result = Result<AuthResponse, OperationError>;
}

pub struct CreateMessage {
    pub uat: Option<UserAuthToken>,
    pub req: CreateRequest,
}

impl CreateMessage {
    pub fn new(uat: Option<UserAuthToken>, req: CreateRequest) -> Self {
        CreateMessage { uat: uat, req: req }
    }
}

impl Message for CreateMessage {
    type Result = Result<OperationResponse, OperationError>;
}

pub struct DeleteMessage {
    pub uat: Option<UserAuthToken>,
    pub req: DeleteRequest,
}

impl DeleteMessage {
    pub fn new(uat: Option<UserAuthToken>, req: DeleteRequest) -> Self {
        DeleteMessage { uat: uat, req: req }
    }
}

impl Message for DeleteMessage {
    type Result = Result<OperationResponse, OperationError>;
}

pub struct ModifyMessage {
    pub uat: Option<UserAuthToken>,
    pub req: ModifyRequest,
}

impl ModifyMessage {
    pub fn new(uat: Option<UserAuthToken>, req: ModifyRequest) -> Self {
        ModifyMessage { uat: uat, req: req }
    }
}

impl Message for ModifyMessage {
    type Result = Result<OperationResponse, OperationError>;
}

pub struct SearchMessage {
    pub uat: Option<UserAuthToken>,
    pub req: SearchRequest,
}

impl SearchMessage {
    pub fn new(uat: Option<UserAuthToken>, req: SearchRequest) -> Self {
        SearchMessage { uat: uat, req: req }
    }
}

impl Message for SearchMessage {
    type Result = Result<SearchResponse, OperationError>;
}

pub struct IdmAccountSetPasswordMessage {
    pub uat: Option<UserAuthToken>,
    pub cleartext: String,
}

impl IdmAccountSetPasswordMessage {
    pub fn new(uat: Option<UserAuthToken>, req: SingleStringRequest) -> Self {
        IdmAccountSetPasswordMessage {
            uat: uat,
            cleartext: req.value,
        }
    }
}

impl Message for IdmAccountSetPasswordMessage {
    type Result = Result<OperationResponse, OperationError>;
}

// ===========================================================

pub struct QueryServerV1 {
    log: actix::Addr<EventLog>,
    qs: QueryServer,
    idms: Arc<IdmServer>,
}

impl Actor for QueryServerV1 {
    type Context = SyncContext<Self>;

    fn started(&mut self, _ctx: &mut Self::Context) {
        // ctx.set_mailbox_capacity(1 << 31);
    }
}

impl QueryServerV1 {
    pub fn new(log: actix::Addr<EventLog>, qs: QueryServer, idms: Arc<IdmServer>) -> Self {
        log_event!(log, "Starting query server v1 worker ...");
        QueryServerV1 {
            log: log,
            qs: qs,
            idms: idms,
        }
    }

    pub fn start(
        log: actix::Addr<EventLog>,
        query_server: QueryServer,
        idms: IdmServer,
        threads: usize,
    ) -> actix::Addr<QueryServerV1> {
        let idms_arc = Arc::new(idms);
        SyncArbiter::start(threads, move || {
            QueryServerV1::new(log.clone(), query_server.clone(), idms_arc.clone())
        })
    }
}

// The server only recieves "Message" structures, which
// are whole self contained DB operations with all parsing
// required complete. We still need to do certain validation steps, but
// at this point our just is just to route to do_<action>

impl Handler<SearchMessage> for QueryServerV1 {
    type Result = Result<SearchResponse, OperationError>;

    fn handle(&mut self, msg: SearchMessage, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("search");
        let res = audit_segment!(&mut audit, || {
            // Begin a read
            let qs_read = self.qs.read();

            // Make an event from the request
            let srch = match SearchEvent::from_message(&mut audit, msg, &qs_read) {
                Ok(s) => s,
                Err(e) => {
                    audit_log!(audit, "Failed to begin search: {:?}", e);
                    return Err(e);
                }
            };

            audit_log!(audit, "Begin event {:?}", srch);

            match qs_read.search_ext(&mut audit, &srch) {
                Ok(entries) => {
                    SearchResult::new(&mut audit, &qs_read, entries).map(|ok_sr| ok_sr.response())
                }
                Err(e) => Err(e),
            }
        });
        // At the end of the event we send it for logging.
        self.log.do_send(audit);
        res
    }
}

impl Handler<CreateMessage> for QueryServerV1 {
    type Result = Result<OperationResponse, OperationError>;

    fn handle(&mut self, msg: CreateMessage, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("create");
        let res = audit_segment!(&mut audit, || {
            let mut qs_write = self.qs.write();

            let crt = match CreateEvent::from_message(&mut audit, msg, &qs_write) {
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

impl Handler<ModifyMessage> for QueryServerV1 {
    type Result = Result<OperationResponse, OperationError>;

    fn handle(&mut self, msg: ModifyMessage, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("modify");
        let res = audit_segment!(&mut audit, || {
            let mut qs_write = self.qs.write();
            let mdf = match ModifyEvent::from_message(&mut audit, msg, &qs_write) {
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

impl Handler<DeleteMessage> for QueryServerV1 {
    type Result = Result<OperationResponse, OperationError>;

    fn handle(&mut self, msg: DeleteMessage, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("delete");
        let res = audit_segment!(&mut audit, || {
            let mut qs_write = self.qs.write();

            let del = match DeleteEvent::from_message(&mut audit, msg, &qs_write) {
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

            let ae = try_audit!(audit, AuthEvent::from_message(msg));

            let ct = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Clock failure!");

            // Trigger a session clean *before* we take any auth steps.
            // It's important to do this before to ensure that timeouts on
            // the session are enforced.
            idm_write.expire_auth_sessions(ct);

            // Generally things like auth denied are in Ok() msgs
            // so true errors should always trigger a rollback.
            let r = idm_write
                .auth(&mut audit, &ae, ct)
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
            // TODO #62: Move this to IdmServer!!!
            // Begin a read
            let qs_read = self.qs.read();

            // Make an event from the whoami request. This will process the event and
            // generate a selfuuid search.
            //
            // This current handles the unauthenticated check, and will
            // trigger the failure, but if we can manage to work out async
            // then move this to core.rs, and don't allow Option<UAT> to get
            // this far.
            let uat = msg.uat.clone().ok_or(OperationError::NotAuthenticated)?;

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
                            WhoamiResult::new(&mut audit, &qs_read, e, uat)
                                .map(|ok_wr| ok_wr.response())
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

impl Handler<IdmAccountSetPasswordMessage> for QueryServerV1 {
    type Result = Result<OperationResponse, OperationError>;

    fn handle(&mut self, msg: IdmAccountSetPasswordMessage, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("idm_account_set_password");
        let res = audit_segment!(&mut audit, || {
            let mut idms_prox_write = self.idms.proxy_write();

            let pce = PasswordChangeEvent::from_idm_account_set_password(
                &mut audit,
                &idms_prox_write.qs_write,
                msg,
            )
            .map_err(|e| {
                audit_log!(audit, "Failed to begin idm_account_set_password: {:?}", e);
                e
            })?;

            idms_prox_write
                .set_account_password(&mut audit, &pce)
                .and_then(|_| idms_prox_write.commit(&mut audit))
                .map(|_| OperationResponse::new(()))
        });
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
