use std::sync::Arc;

use crate::audit::AuditScope;

use crate::async_log::EventLog;
use crate::event::{AuthEvent, SearchEvent, SearchResult, WhoamiResult};
use crate::idm::event::{RadiusAuthTokenEvent};
use kanidm_proto::v1::{OperationError, RadiusAuthToken};

use crate::filter::{Filter, FilterInvalid};
use crate::idm::server::IdmServer;
use crate::server::{QueryServer, QueryServerTransaction};

use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::{
    AuthRequest, AuthResponse, SearchRequest, SearchResponse, UserAuthToken, WhoamiResponse,
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

pub struct InternalSearchMessage {
    pub uat: Option<UserAuthToken>,
    pub filter: Filter<FilterInvalid>,
    pub attrs: Option<Vec<String>>,
}

impl Message for InternalSearchMessage {
    type Result = Result<Vec<ProtoEntry>, OperationError>;
}

pub struct InternalRadiusReadMessage {
    pub uat: Option<UserAuthToken>,
    pub uuid_or_name: String,
}

impl Message for InternalRadiusReadMessage {
    type Result = Result<Option<String>, OperationError>;
}

pub struct InternalRadiusTokenReadMessage {
    pub uat: Option<UserAuthToken>,
    pub uuid_or_name: String,
}

impl Message for InternalRadiusTokenReadMessage {
    type Result = Result<RadiusAuthToken, OperationError>;
}

// ===========================================================

pub struct QueryServerReadV1 {
    log: actix::Addr<EventLog>,
    qs: QueryServer,
    idms: Arc<IdmServer>,
}

impl Actor for QueryServerReadV1 {
    type Context = SyncContext<Self>;

    fn started(&mut self, _ctx: &mut Self::Context) {
        // ctx.set_mailbox_capacity(1 << 31);
    }
}

impl QueryServerReadV1 {
    pub fn new(log: actix::Addr<EventLog>, qs: QueryServer, idms: Arc<IdmServer>) -> Self {
        log_event!(log, "Starting query server v1 worker ...");
        QueryServerReadV1 {
            log: log,
            qs: qs,
            idms: idms,
        }
    }

    pub fn start(
        log: actix::Addr<EventLog>,
        query_server: QueryServer,
        idms: Arc<IdmServer>,
        threads: usize,
    ) -> actix::Addr<QueryServerReadV1> {
        SyncArbiter::start(threads, move || {
            QueryServerReadV1::new(log.clone(), query_server.clone(), idms.clone())
        })
    }
}

// The server only recieves "Message" structures, which
// are whole self contained DB operations with all parsing
// required complete. We still need to do certain validation steps, but
// at this point our just is just to route to do_<action>

impl Handler<SearchMessage> for QueryServerReadV1 {
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

impl Handler<AuthMessage> for QueryServerReadV1 {
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

impl Handler<WhoamiMessage> for QueryServerReadV1 {
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

impl Handler<InternalSearchMessage> for QueryServerReadV1 {
    type Result = Result<Vec<ProtoEntry>, OperationError>;

    fn handle(&mut self, msg: InternalSearchMessage, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("internal_search_message");
        let res = audit_segment!(&mut audit, || {
            let qs_read = self.qs.read();

            // Make an event from the request
            let srch = match SearchEvent::from_internal_message(&mut audit, msg, &qs_read) {
                Ok(s) => s,
                Err(e) => {
                    audit_log!(audit, "Failed to begin search: {:?}", e);
                    return Err(e);
                }
            };

            audit_log!(audit, "Begin event {:?}", srch);

            match qs_read.search_ext(&mut audit, &srch) {
                Ok(entries) => SearchResult::new(&mut audit, &qs_read, entries)
                    .map(|ok_sr| ok_sr.to_proto_array()),
                Err(e) => Err(e),
            }
        });
        self.log.do_send(audit);
        res
    }
}

impl Handler<InternalRadiusReadMessage> for QueryServerReadV1 {
    type Result = Result<Option<String>, OperationError>;

    fn handle(&mut self, msg: InternalRadiusReadMessage, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("internal_radius_read_message");
        let res = audit_segment!(&mut audit, || {
            let qs_read = self.qs.read();

            let target_uuid = match Uuid::parse_str(msg.uuid_or_name.as_str()) {
                Ok(u) => u,
                Err(_) => qs_read
                    .name_to_uuid(&mut audit, msg.uuid_or_name.as_str())
                    .map_err(|e| {
                        audit_log!(&mut audit, "Error resolving id to target");
                        e
                    })?,
            };

            // Make an event from the request
            let srch = match SearchEvent::from_target_uuid_request(
                &mut audit,
                msg.uat,
                target_uuid,
                &qs_read,
            ) {
                Ok(s) => s,
                Err(e) => {
                    audit_log!(audit, "Failed to begin search: {:?}", e);
                    return Err(e);
                }
            };

            audit_log!(audit, "Begin event {:?}", srch);

            // We have to use search_ext to guarantee acs was applied.
            match qs_read.search_ext(&mut audit, &srch) {
                Ok(mut entries) => {
                    let r = entries
                        .pop()
                        // From the entry, turn it into the value
                        .and_then(|e| {
                            e.get_ava_single("radius_secret")
                                .and_then(|v| v.get_radius_secret().map(|s| s.to_string()))
                        });
                    Ok(r)
                }
                Err(e) => Err(e),
            }
        });
        self.log.do_send(audit);
        res
    }
}


impl Handler<InternalRadiusTokenReadMessage> for QueryServerReadV1 {
    type Result = Result<RadiusAuthToken, OperationError>;

    fn handle(&mut self, msg: InternalRadiusTokenReadMessage, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("internal_radius_token_read_message");
        let res = audit_segment!(&mut audit, || {
            let idm_read = self.idms.proxy_read();

            let target_uuid = match Uuid::parse_str(msg.uuid_or_name.as_str()) {
                Ok(u) => u,
                Err(_) => idm_read
                    .qs_read
                    .name_to_uuid(&mut audit, msg.uuid_or_name.as_str())
                    .map_err(|e| {
                        audit_log!(&mut audit, "Error resolving id to target");
                        e
                    })?,
            };

            // Make an event from the request
            let rate = match RadiusAuthTokenEvent::from_parts(
                &mut audit,
                &idm_read.qs_read,
                msg.uat,
                target_uuid
            ) {
                Ok(s) => s,
                Err(e) => {
                    audit_log!(audit, "Failed to begin search: {:?}", e);
                    return Err(e);
                }
            };

            audit_log!(audit, "Begin event {:?}", rate);

            idm_read.get_radiusauthtoken(&mut audit, &rate)
        });
        self.log.do_send(audit);
        res
    }
}

