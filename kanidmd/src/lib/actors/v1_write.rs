use crate::audit::AuditScope;
use std::sync::Arc;

use crate::async_log::EventLog;
use crate::event::{
    CreateEvent, DeleteEvent, ModifyEvent, PurgeRecycledEvent, PurgeTombstoneEvent,
};
use crate::idm::event::{GeneratePasswordEvent, PasswordChangeEvent, RegenerateRadiusSecretEvent};
use kanidm_proto::v1::OperationError;

use crate::idm::server::IdmServer;
use crate::server::{QueryServer, QueryServerTransaction};

use kanidm_proto::v1::{
    CreateRequest, DeleteRequest, ModifyRequest, OperationResponse, SetAuthCredential,
    SingleStringRequest, UserAuthToken,
};

use actix::prelude::*;
use uuid::Uuid;

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

pub struct InternalCredentialSetMessage {
    pub uat: Option<UserAuthToken>,
    pub uuid_or_name: String,
    pub appid: Option<String>,
    pub sac: SetAuthCredential,
}

impl InternalCredentialSetMessage {
    pub fn new(
        uat: Option<UserAuthToken>,
        uuid_or_name: String,
        appid: Option<String>,
        sac: SetAuthCredential,
    ) -> Self {
        InternalCredentialSetMessage {
            uat: uat,
            uuid_or_name: uuid_or_name,
            appid: appid,
            sac: sac,
        }
    }
}

impl Message for InternalCredentialSetMessage {
    type Result = Result<Option<String>, OperationError>;
}

pub struct InternalRegenerateRadiusMessage {
    pub uat: Option<UserAuthToken>,
    pub uuid_or_name: String,
}

impl InternalRegenerateRadiusMessage {
    pub fn new(uat: Option<UserAuthToken>, uuid_or_name: String) -> Self {
        InternalRegenerateRadiusMessage {
            uat: uat,
            uuid_or_name: uuid_or_name,
        }
    }
}

impl Message for InternalRegenerateRadiusMessage {
    type Result = Result<String, OperationError>;
}

/// Indicate that we want to purge an attribute from the entry - this is generally
/// in response to a DELETE http method.
pub struct PurgeAttributeMessage {
    pub uat: Option<UserAuthToken>,
    pub uuid_or_name: String,
    pub attr: String,
}

impl Message for PurgeAttributeMessage {
    type Result = Result<(), OperationError>;
}

pub struct QueryServerWriteV1 {
    log: actix::Addr<EventLog>,
    qs: QueryServer,
    idms: Arc<IdmServer>,
}

impl Actor for QueryServerWriteV1 {
    type Context = SyncContext<Self>;

    fn started(&mut self, _ctx: &mut Self::Context) {
        // How much backlog we want to allow outstanding before we start to throw
        // errors?
        // ctx.set_mailbox_capacity(1 << 31);
    }
}

impl QueryServerWriteV1 {
    pub fn new(log: actix::Addr<EventLog>, qs: QueryServer, idms: Arc<IdmServer>) -> Self {
        log_event!(log, "Starting query server v1 worker ...");
        QueryServerWriteV1 {
            log: log,
            qs: qs,
            idms: idms,
        }
    }

    pub fn start(
        log: actix::Addr<EventLog>,
        query_server: QueryServer,
        idms: Arc<IdmServer>,
    ) -> actix::Addr<QueryServerWriteV1> {
        SyncArbiter::start(1, move || {
            QueryServerWriteV1::new(log.clone(), query_server.clone(), idms.clone())
        })
    }
}

impl Handler<CreateMessage> for QueryServerWriteV1 {
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

impl Handler<ModifyMessage> for QueryServerWriteV1 {
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

impl Handler<DeleteMessage> for QueryServerWriteV1 {
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

// IDM native types for modifications
impl Handler<InternalCredentialSetMessage> for QueryServerWriteV1 {
    type Result = Result<Option<String>, OperationError>;

    fn handle(&mut self, msg: InternalCredentialSetMessage, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("internal_credential_set_message");
        let res = audit_segment!(&mut audit, || {
            let mut idms_prox_write = self.idms.proxy_write();

            // given the uuid_or_name, determine the target uuid.
            // We can either do this by trying to parse the name or by creating a filter
            // to find the entry - there are risks to both TBH ... especially when the uuid
            // is also an entries name, but that they aren't the same entry.
            let target_uuid = match Uuid::parse_str(msg.uuid_or_name.as_str()) {
                Ok(u) => u,
                Err(_) => idms_prox_write
                    .qs_write
                    .name_to_uuid(&mut audit, msg.uuid_or_name.as_str())
                    .map_err(|e| {
                        audit_log!(&mut audit, "Error resolving id to target");
                        e
                    })?,
            };

            // What type of auth set did we recieve?
            match msg.sac {
                SetAuthCredential::Password(cleartext) => {
                    let pce = PasswordChangeEvent::from_parts(
                        &mut audit,
                        &idms_prox_write.qs_write,
                        msg.uat,
                        target_uuid,
                        cleartext,
                        msg.appid,
                    )
                    .map_err(|e| {
                        audit_log!(
                            audit,
                            "Failed to begin internal_credential_set_message: {:?}",
                            e
                        );
                        e
                    })?;
                    idms_prox_write
                        .set_account_password(&mut audit, &pce)
                        .and_then(|_| idms_prox_write.commit(&mut audit))
                        .map(|_| None)
                }
                SetAuthCredential::GeneratePassword => {
                    let gpe = GeneratePasswordEvent::from_parts(
                        &mut audit,
                        &idms_prox_write.qs_write,
                        msg.uat,
                        target_uuid,
                        msg.appid,
                    )
                    .map_err(|e| {
                        audit_log!(
                            audit,
                            "Failed to begin internal_credential_set_message: {:?}",
                            e
                        );
                        e
                    })?;
                    idms_prox_write
                        .generate_account_password(&mut audit, &gpe)
                        .and_then(|r| idms_prox_write.commit(&mut audit).map(|_| r))
                        .map(|v| Some(v))
                }
            }
        });
        self.log.do_send(audit);
        res
    }
}

impl Handler<IdmAccountSetPasswordMessage> for QueryServerWriteV1 {
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

impl Handler<InternalRegenerateRadiusMessage> for QueryServerWriteV1 {
    type Result = Result<String, OperationError>;

    fn handle(
        &mut self,
        msg: InternalRegenerateRadiusMessage,
        _: &mut Self::Context,
    ) -> Self::Result {
        let mut audit = AuditScope::new("idm_account_regenerate_radius");
        let res = audit_segment!(&mut audit, || {
            let mut idms_prox_write = self.idms.proxy_write();

            let target_uuid = match Uuid::parse_str(msg.uuid_or_name.as_str()) {
                Ok(u) => u,
                Err(_) => idms_prox_write
                    .qs_write
                    .name_to_uuid(&mut audit, msg.uuid_or_name.as_str())
                    .map_err(|e| {
                        audit_log!(&mut audit, "Error resolving id to target");
                        e
                    })?,
            };

            let rrse = RegenerateRadiusSecretEvent::from_parts(
                &mut audit,
                &idms_prox_write.qs_write,
                msg.uat,
                target_uuid,
            )
            .map_err(|e| {
                audit_log!(
                    audit,
                    "Failed to begin idm_account_regenerate_radius: {:?}",
                    e
                );
                e
            })?;

            idms_prox_write
                .regenerate_radius_secret(&mut audit, &rrse)
                .and_then(|r| idms_prox_write.commit(&mut audit).map(|_| r))
        });
        self.log.do_send(audit);
        res
    }
}

impl Handler<PurgeAttributeMessage> for QueryServerWriteV1 {
    type Result = Result<(), OperationError>;

    fn handle(&mut self, msg: PurgeAttributeMessage, _: &mut Self::Context) -> Self::Result {
        let mut audit = AuditScope::new("modify");
        let res = audit_segment!(&mut audit, || {
            let mut qs_write = self.qs.write();
            let target_uuid = match Uuid::parse_str(msg.uuid_or_name.as_str()) {
                Ok(u) => u,
                Err(_) => qs_write
                    .name_to_uuid(&mut audit, msg.uuid_or_name.as_str())
                    .map_err(|e| {
                        audit_log!(&mut audit, "Error resolving id to target");
                        e
                    })?,
            };

            let mdf = match ModifyEvent::from_target_uuid_attr_purge(
                &mut audit,
                msg.uat,
                target_uuid,
                msg.attr,
                &qs_write,
            ) {
                Ok(m) => m,
                Err(e) => {
                    audit_log!(audit, "Failed to begin modify: {:?}", e);
                    return Err(e);
                }
            };

            audit_log!(audit, "Begin modify event {:?}", mdf);

            qs_write
                .modify(&mut audit, &mdf)
                .and_then(|_| qs_write.commit(&mut audit).map(|_| ()))
        });
        self.log.do_send(audit);
        res
    }
}

// These below are internal only types.

impl Handler<PurgeTombstoneEvent> for QueryServerWriteV1 {
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

impl Handler<PurgeRecycledEvent> for QueryServerWriteV1 {
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
