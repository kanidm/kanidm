use std::iter;
use std::sync::Arc;
use tokio::sync::mpsc::UnboundedSender as Sender;

use crate::prelude::*;

use crate::event::{
    CreateEvent, DeleteEvent, ModifyEvent, PurgeRecycledEvent, PurgeTombstoneEvent,
    ReviveRecycledEvent,
};
use crate::idm::event::{
    GeneratePasswordEvent, GenerateTotpEvent, PasswordChangeEvent, RegenerateRadiusSecretEvent,
    RemoveTotpEvent, RemoveWebauthnEvent, UnixPasswordChangeEvent, VerifyTotpEvent,
    WebauthnDoRegisterEvent, WebauthnInitRegisterEvent,
};
use crate::modify::{Modify, ModifyInvalid, ModifyList};
use crate::value::{PartialValue, Value};
use kanidm_proto::v1::OperationError;

use crate::filter::{Filter, FilterInvalid};
use crate::idm::delayed::DelayedAction;
use crate::idm::server::IdmServer;
use crate::utils::duration_from_epoch_now;

use kanidm_proto::v1::Modify as ProtoModify;
use kanidm_proto::v1::ModifyList as ProtoModifyList;
use kanidm_proto::v1::{
    AccountUnixExtend, CreateRequest, DeleteRequest, GroupUnixExtend, ModifyRequest,
    OperationResponse, SetCredentialRequest, SetCredentialResponse, UserAuthToken,
};

use uuid::Uuid;

pub struct QueryServerWriteV1 {
    log: Sender<AuditScope>,
    log_level: Option<u32>,
    idms: Arc<IdmServer>,
}

impl QueryServerWriteV1 {
    pub fn new(log: Sender<AuditScope>, log_level: Option<u32>, idms: Arc<IdmServer>) -> Self {
        info!("Starting query server v1 worker ...");
        QueryServerWriteV1 {
            log,
            log_level,
            idms,
        }
    }

    pub fn start_static(
        log: Sender<AuditScope>,
        log_level: Option<u32>,
        idms: Arc<IdmServer>,
    ) -> &'static QueryServerWriteV1 {
        let x = Box::new(QueryServerWriteV1::new(log, log_level, idms));

        let x_ptr = Box::leak(x);
        &(*x_ptr)
    }

    async fn modify_from_parts(
        &self,
        audit: &mut AuditScope,
        audit_tag: &str,
        uat: Option<UserAuthToken>,
        uuid_or_name: &str,
        proto_ml: &ProtoModifyList,
        filter: Filter<FilterInvalid>,
    ) -> Result<(), OperationError> {
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        lperf_op_segment!(audit, audit_tag, || {
            let target_uuid = idms_prox_write
                .qs_write
                .name_to_uuid(audit, uuid_or_name)
                .map_err(|e| {
                    ladmin_error!(audit, "Error resolving id to target");
                    e
                })?;

            let mdf = match ModifyEvent::from_parts(
                audit,
                uat.as_ref(),
                target_uuid,
                proto_ml,
                filter,
                &idms_prox_write.qs_write,
            ) {
                Ok(m) => m,
                Err(e) => {
                    ladmin_error!(audit, "Failed to begin modify: {:?}", e);
                    return Err(e);
                }
            };

            ltrace!(audit, "Begin modify event {:?}", mdf);

            idms_prox_write
                .qs_write
                .modify(audit, &mdf)
                .and_then(|_| idms_prox_write.commit(audit).map(|_| ()))
        })
    }

    async fn modify_from_internal_parts(
        &self,
        audit: &mut AuditScope,
        audit_tag: &str,
        uat: Option<UserAuthToken>,
        uuid_or_name: &str,
        ml: &ModifyList<ModifyInvalid>,
        filter: Filter<FilterInvalid>,
    ) -> Result<(), OperationError> {
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        lperf_op_segment!(audit, audit_tag, || {
            let target_uuid = idms_prox_write
                .qs_write
                .name_to_uuid(audit, uuid_or_name)
                .map_err(|e| {
                    ladmin_error!(audit, "Error resolving id to target");
                    e
                })?;

            let mdf = match ModifyEvent::from_internal_parts(
                audit,
                uat.as_ref(),
                target_uuid,
                ml,
                filter,
                &idms_prox_write.qs_write,
            ) {
                Ok(m) => m,
                Err(e) => {
                    ladmin_error!(audit, "Failed to begin modify: {:?}", e);
                    return Err(e);
                }
            };

            ltrace!(audit, "Begin modify event {:?}", mdf);

            idms_prox_write
                .qs_write
                .modify(audit, &mdf)
                .and_then(|_| idms_prox_write.commit(audit).map(|_| ()))
        })
    }

    pub async fn handle_create(
        &self,
        uat: Option<UserAuthToken>,
        req: CreateRequest,
        eventid: Uuid,
    ) -> Result<OperationResponse, OperationError> {
        let mut audit = AuditScope::new("create", eventid, self.log_level);
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_write::handle<CreateMessage>",
            || {
                let crt = match CreateEvent::from_message(
                    &mut audit,
                    uat.as_ref(),
                    &req,
                    &idms_prox_write.qs_write,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        ladmin_warning!(audit, "Failed to begin create: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin create event {:?}", crt);

                idms_prox_write
                    .qs_write
                    .create(&mut audit, &crt)
                    .and_then(|_| {
                        idms_prox_write
                            .commit(&mut audit)
                            .map(|_| OperationResponse {})
                    })
            }
        );
        // At the end of the event we send it for logging.
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_modify(
        &self,
        uat: Option<UserAuthToken>,
        req: ModifyRequest,
        eventid: Uuid,
    ) -> Result<OperationResponse, OperationError> {
        let mut audit = AuditScope::new("modify", eventid, self.log_level);
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = lperf_segment!(
            &mut audit,
            "actors::v1_write::handle<ModifyMessage>",
            || {
                let mdf = match ModifyEvent::from_message(
                    &mut audit,
                    uat.as_ref(),
                    &req,
                    &idms_prox_write.qs_write,
                ) {
                    Ok(m) => m,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin modify: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin modify event {:?}", mdf);

                idms_prox_write
                    .qs_write
                    .modify(&mut audit, &mdf)
                    .and_then(|_| {
                        idms_prox_write
                            .commit(&mut audit)
                            .map(|_| OperationResponse {})
                    })
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_delete(
        &self,
        uat: Option<UserAuthToken>,
        req: DeleteRequest,
        eventid: Uuid,
    ) -> Result<OperationResponse, OperationError> {
        let mut audit = AuditScope::new("delete", eventid, self.log_level);
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_write::handle<DeleteMessage>",
            || {
                let del = match DeleteEvent::from_message(
                    &mut audit,
                    uat.as_ref(),
                    &req,
                    &idms_prox_write.qs_write,
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin delete: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin delete event {:?}", del);

                idms_prox_write
                    .qs_write
                    .delete(&mut audit, &del)
                    .and_then(|_| {
                        idms_prox_write
                            .commit(&mut audit)
                            .map(|_| OperationResponse {})
                    })
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_internaldelete(
        &self,
        uat: Option<UserAuthToken>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let mut audit = AuditScope::new("internal_delete", eventid, self.log_level);
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_write::handle<InternalDeleteMessage>",
            || {
                let del = match DeleteEvent::from_parts(
                    &mut audit,
                    uat.as_ref(),
                    &filter,
                    &idms_prox_write.qs_write,
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin delete: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin delete event {:?}", del);

                idms_prox_write
                    .qs_write
                    .delete(&mut audit, &del)
                    .and_then(|_| idms_prox_write.commit(&mut audit).map(|_| ()))
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_reviverecycled(
        &self,
        uat: Option<UserAuthToken>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let mut audit = AuditScope::new("revive", eventid, self.log_level);
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_write::handle<ReviveRecycledMessage>",
            || {
                let rev = match ReviveRecycledEvent::from_parts(
                    &mut audit,
                    uat.as_ref(),
                    &filter,
                    &idms_prox_write.qs_write,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin revive: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin revive event {:?}", rev);

                idms_prox_write
                    .qs_write
                    .revive_recycled(&mut audit, &rev)
                    .and_then(|_| idms_prox_write.commit(&mut audit).map(|_| ()))
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    // === IDM native types for modifications
    pub async fn handle_credentialset(
        &self,
        uat: Option<UserAuthToken>,
        uuid_or_name: String,
        appid: Option<String>,
        sac: SetCredentialRequest,
        eventid: Uuid,
    ) -> Result<SetCredentialResponse, OperationError> {
        let mut audit = AuditScope::new("internal_credential_set_message", eventid, self.log_level);
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write_async(ct).await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_write::handle<InternalCredentialSetMessage>",
            || {
                // Trigger a session clean *before* we take any auth steps.
                // It's important to do this before to ensure that timeouts on
                // the session are enforced.
                idms_prox_write.expire_mfareg_sessions(ct);

                // given the uuid_or_name, determine the target uuid.
                // We can either do this by trying to parse the name or by creating a filter
                // to find the entry - there are risks to both TBH ... especially when the uuid
                // is also an entries name, but that they aren't the same entry.

                let target_uuid = idms_prox_write
                    .qs_write
                    .name_to_uuid(&mut audit, uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_error!(audit, "Error resolving id to target");
                        e
                    })?;

                // What type of auth set did we recieve?
                match sac {
                    SetCredentialRequest::Password(cleartext) => {
                        let pce = PasswordChangeEvent::from_parts(
                            &mut audit,
                            &idms_prox_write.qs_write,
                            uat.as_ref(),
                            target_uuid,
                            cleartext,
                            appid,
                        )
                        .map_err(|e| {
                            ladmin_error!(
                                audit,
                                "Failed to begin internal_credential_set_message: {:?}",
                                e
                            );
                            e
                        })?;
                        idms_prox_write
                            .set_account_password(&mut audit, &pce)
                            .and_then(|_| idms_prox_write.commit(&mut audit))
                            .map(|_| SetCredentialResponse::Success)
                    }
                    SetCredentialRequest::GeneratePassword => {
                        let gpe = GeneratePasswordEvent::from_parts(
                            &mut audit,
                            &idms_prox_write.qs_write,
                            uat.as_ref(),
                            target_uuid,
                            appid,
                        )
                        .map_err(|e| {
                            ladmin_error!(
                                audit,
                                "Failed to begin internal_credential_set_message: {:?}",
                                e
                            );
                            e
                        })?;
                        idms_prox_write
                            .generate_account_password(&mut audit, &gpe)
                            .and_then(|r| idms_prox_write.commit(&mut audit).map(|_| r))
                            .map(SetCredentialResponse::Token)
                    }
                    SetCredentialRequest::TotpGenerate(label) => {
                        let gte = GenerateTotpEvent::from_parts(
                            &mut audit,
                            &idms_prox_write.qs_write,
                            uat.as_ref(),
                            target_uuid,
                            label,
                        )
                        .map_err(|e| {
                            ladmin_error!(
                                audit,
                                "Failed to begin internal_credential_set_message: {:?}",
                                e
                            );
                            e
                        })?;
                        idms_prox_write
                            .generate_account_totp(&mut audit, &gte, ct)
                            .and_then(|r| idms_prox_write.commit(&mut audit).map(|_| r))
                    }
                    SetCredentialRequest::TotpVerify(uuid, chal) => {
                        let vte = VerifyTotpEvent::from_parts(
                            &mut audit,
                            &idms_prox_write.qs_write,
                            uat.as_ref(),
                            target_uuid,
                            uuid,
                            chal,
                        )
                        .map_err(|e| {
                            ladmin_error!(
                                audit,
                                "Failed to begin internal_credential_set_message: {:?}",
                                e
                            );
                            e
                        })?;
                        idms_prox_write
                            .verify_account_totp(&mut audit, &vte, ct)
                            .and_then(|r| idms_prox_write.commit(&mut audit).map(|_| r))
                    }
                    SetCredentialRequest::TotpRemove => {
                        let rte = RemoveTotpEvent::from_parts(
                            &mut audit,
                            &idms_prox_write.qs_write,
                            uat.as_ref(),
                            target_uuid,
                        )
                        .map_err(|e| {
                            ladmin_error!(
                                audit,
                                "Failed to begin internal_credential_set_message: {:?}",
                                e
                            );
                            e
                        })?;
                        idms_prox_write
                            .remove_account_totp(&mut audit, &rte)
                            .and_then(|r| idms_prox_write.commit(&mut audit).map(|_| r))
                    }
                    SetCredentialRequest::WebauthnBegin(label) => {
                        let wre = WebauthnInitRegisterEvent::from_parts(
                            &mut audit,
                            &idms_prox_write.qs_write,
                            uat.as_ref(),
                            target_uuid,
                            label,
                        )
                        .map_err(|e| {
                            ladmin_error!(
                                audit,
                                "Failed to begin internal_credential_set_message: {:?}",
                                e
                            );
                            e
                        })?;
                        idms_prox_write
                            .reg_account_webauthn_init(&mut audit, &wre, ct)
                            .and_then(|r| idms_prox_write.commit(&mut audit).map(|_| r))
                    }
                    SetCredentialRequest::WebauthnRegister(uuid, rpkc) => {
                        let wre = WebauthnDoRegisterEvent::from_parts(
                            &mut audit,
                            &idms_prox_write.qs_write,
                            uat.as_ref(),
                            target_uuid,
                            uuid,
                            rpkc,
                        )
                        .map_err(|e| {
                            ladmin_error!(
                                audit,
                                "Failed to begin internal_credential_set_message: {:?}",
                                e
                            );
                            e
                        })?;
                        idms_prox_write
                            .reg_account_webauthn_complete(&mut audit, &wre)
                            .and_then(|r| idms_prox_write.commit(&mut audit).map(|_| r))
                    }
                    SetCredentialRequest::WebauthnRemove(label) => {
                        let rwe = RemoveWebauthnEvent::from_parts(
                            &mut audit,
                            &idms_prox_write.qs_write,
                            uat.as_ref(),
                            target_uuid,
                            label,
                        )
                        .map_err(|e| {
                            ladmin_error!(
                                audit,
                                "Failed to begin internal_credential_set_message: {:?}",
                                e
                            );
                            e
                        })?;
                        idms_prox_write
                            .remove_account_webauthn(&mut audit, &rwe)
                            .and_then(|r| idms_prox_write.commit(&mut audit).map(|_| r))
                    }
                }
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_idmaccountsetpassword(
        &self,
        uat: Option<UserAuthToken>,
        cleartext: String,
        eventid: Uuid,
    ) -> Result<OperationResponse, OperationError> {
        let mut audit = AuditScope::new("idm_account_set_password", eventid, self.log_level);
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write_async(ct).await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_write::handle<IdmAccountSetPasswordMessage>",
            || {
                idms_prox_write.expire_mfareg_sessions(ct);

                let pce = PasswordChangeEvent::from_idm_account_set_password(
                    &mut audit,
                    uat.as_ref(),
                    cleartext,
                    &idms_prox_write.qs_write,
                )
                .map_err(|e| {
                    ladmin_error!(audit, "Failed to begin idm_account_set_password: {:?}", e);
                    e
                })?;

                idms_prox_write
                    .set_account_password(&mut audit, &pce)
                    .and_then(|_| idms_prox_write.commit(&mut audit))
                    .map(|_| OperationResponse::new(()))
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_regenerateradius(
        &self,
        uat: Option<UserAuthToken>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<String, OperationError> {
        let mut audit = AuditScope::new("idm_account_regenerate_radius", eventid, self.log_level);
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write_async(ct).await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_write::handle<InternalRegenerateRadiusMessage>",
            || {
                idms_prox_write.expire_mfareg_sessions(ct);

                let target_uuid = idms_prox_write
                    .qs_write
                    .name_to_uuid(&mut audit, uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_error!(audit, "Error resolving id to target");
                        e
                    })?;

                let rrse = RegenerateRadiusSecretEvent::from_parts(
                    &mut audit,
                    &idms_prox_write.qs_write,
                    uat.as_ref(),
                    target_uuid,
                )
                .map_err(|e| {
                    ladmin_error!(
                        audit,
                        "Failed to begin idm_account_regenerate_radius: {:?}",
                        e
                    );
                    e
                })?;

                idms_prox_write
                    .regenerate_radius_secret(&mut audit, &rrse)
                    .and_then(|r| idms_prox_write.commit(&mut audit).map(|_| r))
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_purgeattribute(
        &self,
        uat: Option<UserAuthToken>,
        uuid_or_name: String,
        attr: String,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let mut audit = AuditScope::new("purge_attribute", eventid, self.log_level);
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_write::handle<PurgeAttributeMessage>",
            || {
                let target_uuid = idms_prox_write
                    .qs_write
                    .name_to_uuid(&mut audit, uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_error!(audit, "Error resolving id to target");
                        e
                    })?;

                let mdf = match ModifyEvent::from_target_uuid_attr_purge(
                    &mut audit,
                    uat.as_ref(),
                    target_uuid,
                    &attr,
                    filter,
                    &idms_prox_write.qs_write,
                ) {
                    Ok(m) => m,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin modify: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin modify event {:?}", mdf);

                idms_prox_write
                    .qs_write
                    .modify(&mut audit, &mdf)
                    .and_then(|_| idms_prox_write.commit(&mut audit).map(|_| ()))
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_removeattributevalues(
        &self,
        uat: Option<UserAuthToken>,
        uuid_or_name: String,
        attr: String,
        values: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let mut audit = AuditScope::new("remove_attribute_values", eventid, self.log_level);
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_write::handle<RemoveAttributeValuesMessage>",
            || {
                let target_uuid = idms_prox_write
                    .qs_write
                    .name_to_uuid(&mut audit, uuid_or_name.as_str())
                    .map_err(|e| {
                        ladmin_error!(audit, "Error resolving id to target");
                        e
                    })?;

                let proto_ml = ProtoModifyList::new_list(
                    values
                        .into_iter()
                        .map(|v| ProtoModify::Removed(attr.clone(), v))
                        .collect(),
                );

                let mdf = match ModifyEvent::from_parts(
                    &mut audit,
                    uat.as_ref(),
                    target_uuid,
                    &proto_ml,
                    filter,
                    &idms_prox_write.qs_write,
                ) {
                    Ok(m) => m,
                    Err(e) => {
                        ladmin_error!(audit, "Failed to begin modify: {:?}", e);
                        return Err(e);
                    }
                };

                ltrace!(audit, "Begin modify event {:?}", mdf);

                idms_prox_write
                    .qs_write
                    .modify(&mut audit, &mdf)
                    .and_then(|_| idms_prox_write.commit(&mut audit).map(|_| ()))
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_appendattribute(
        &self,
        uat: Option<UserAuthToken>,
        uuid_or_name: String,
        attr: String,
        values: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let mut audit = AuditScope::new("append_attribute", eventid, self.log_level);
        // We need to turn these into proto modlists so they can be converted
        // and validated.
        let proto_ml = ProtoModifyList::new_list(
            values
                .into_iter()
                .map(|v| ProtoModify::Present(attr.clone(), v))
                .collect(),
        );
        let res = self
            .modify_from_parts(
                &mut audit,
                "actors::v1_write::handle<AppendAttributeMessage>",
                uat,
                &uuid_or_name,
                &proto_ml,
                filter,
            )
            .await;
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_setattribute(
        &self,
        uat: Option<UserAuthToken>,
        uuid_or_name: String,
        attr: String,
        values: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let mut audit = AuditScope::new("set_attribute", eventid, self.log_level);
        // We need to turn these into proto modlists so they can be converted
        // and validated.
        let proto_ml = ProtoModifyList::new_list(
            std::iter::once(ProtoModify::Purged(attr.clone()))
                .chain(
                    values
                        .into_iter()
                        .map(|v| ProtoModify::Present(attr.clone(), v)),
                )
                .collect(),
        );
        let res = self
            .modify_from_parts(
                &mut audit,
                "actors::v1_write::handle<SetAttributeMessage>",
                uat,
                &uuid_or_name,
                &proto_ml,
                filter,
            )
            .await;
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_sshkeycreate(
        &self,
        uat: Option<UserAuthToken>,
        uuid_or_name: String,
        tag: String,
        key: String,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let mut audit = AuditScope::new("internal_sshkey_create", eventid, self.log_level);
        // Because this is from internal, we can generate a real modlist, rather
        // than relying on the proto ones.
        let ml = ModifyList::new_append("ssh_publickey", Value::new_sshkey(tag, key));

        let res = self
            .modify_from_internal_parts(
                &mut audit,
                "actors::v1_write::handle<InternalSshKeyCreateMessage>",
                uat,
                &uuid_or_name,
                &ml,
                filter,
            )
            .await;
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_idmaccountpersonextend(
        &self,
        uat: Option<UserAuthToken>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let mut audit = AuditScope::new("idm_account_person_extend", eventid, self.log_level);
        // The filter_map here means we only create the mods if the gidnumber or shell are set
        // in the actual request.
        // NOTE: This is an iter for future requirements to be added
        let mods: Vec<_> = iter::once(Some(Modify::Present(
            "class".into(),
            Value::new_class("person"),
        )))
        .flatten()
        .collect();

        let ml = ModifyList::new_list(mods);

        let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));

        let res = self
            .modify_from_internal_parts(
                &mut audit,
                "actors::v1_write::handle<IdmAccountPersonExtendMessage>",
                uat,
                &uuid_or_name,
                &ml,
                filter,
            )
            .await;
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_idmaccountunixextend(
        &self,
        uat: Option<UserAuthToken>,
        uuid_or_name: String,
        ux: AccountUnixExtend,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let AccountUnixExtend { gidnumber, shell } = ux;
        let mut audit = AuditScope::new("idm_account_unix_extend", eventid, self.log_level);
        // The filter_map here means we only create the mods if the gidnumber or shell are set
        // in the actual request.
        let mods: Vec<_> = iter::once(Some(Modify::Present(
            "class".into(),
            Value::new_class("posixaccount"),
        )))
        .chain(iter::once(
            gidnumber
                .as_ref()
                .map(|_| Modify::Purged("gidnumber".into())),
        ))
        .chain(iter::once(gidnumber.map(|n| {
            Modify::Present("gidnumber".into(), Value::new_uint32(n))
        })))
        .chain(iter::once(
            shell.as_ref().map(|_| Modify::Purged("loginshell".into())),
        ))
        .chain(iter::once(shell.map(|s| {
            Modify::Present("loginshell".into(), Value::new_iutf8(s.as_str()))
        })))
        .flatten()
        .collect();

        let ml = ModifyList::new_list(mods);

        let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));

        let res = self
            .modify_from_internal_parts(
                &mut audit,
                "actors::v1_write::handle<IdmAccountUnixExtendMessage>",
                uat,
                &uuid_or_name,
                &ml,
                filter,
            )
            .await;
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_idmgroupunixextend(
        &self,
        uat: Option<UserAuthToken>,
        uuid_or_name: String,
        gx: GroupUnixExtend,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let mut audit = AuditScope::new("idm_group_unix_extend", eventid, self.log_level);
        // The filter_map here means we only create the mods if the gidnumber or shell are set
        // in the actual request.
        let mods: Vec<_> = iter::once(Some(Modify::Present(
            "class".into(),
            Value::new_class("posixgroup"),
        )))
        .chain(iter::once(gx.gidnumber.map(|n| {
            Modify::Present("gidnumber".into(), Value::new_uint32(n))
        })))
        .flatten()
        .collect();

        let ml = ModifyList::new_list(mods);

        let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));

        let res = self
            .modify_from_internal_parts(
                &mut audit,
                "actors::v1_write::handle<IdmGroupUnixExtendMessage>",
                uat,
                &uuid_or_name,
                &ml,
                filter,
            )
            .await;
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    pub async fn handle_idmaccountunixsetcred(
        &self,
        uat: Option<UserAuthToken>,
        uuid_or_name: String,
        cred: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let mut audit = AuditScope::new("idm_account_unix_set_cred", eventid, self.log_level);
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write_async(ct).await;
        let res = lperf_op_segment!(
            &mut audit,
            "actors::v1_write::handle<IdmAccountUnixSetCredMessage>",
            || {
                idms_prox_write.expire_mfareg_sessions(ct);

                let target_uuid = Uuid::parse_str(uuid_or_name.as_str()).or_else(|_| {
                    idms_prox_write
                        .qs_write
                        .name_to_uuid(&mut audit, uuid_or_name.as_str())
                        .map_err(|e| {
                            ladmin_info!(&mut audit, "Error resolving as gidnumber continuing ...");
                            e
                        })
                })?;

                let upce = UnixPasswordChangeEvent::from_parts(
                    &mut audit,
                    &idms_prox_write.qs_write,
                    uat.as_ref(),
                    target_uuid,
                    cred,
                )
                .map_err(|e| {
                    ladmin_error!(audit, "Failed to begin UnixPasswordChangeEvent: {:?}", e);
                    e
                })?;
                idms_prox_write
                    .set_unix_account_password(&mut audit, &upce)
                    .and_then(|_| idms_prox_write.commit(&mut audit))
                    .map(|_| ())
            }
        );
        self.log.send(audit).map_err(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
            OperationError::InvalidState
        })?;
        res
    }

    // ===== These below are internal only event types. =====
    pub(crate) async fn handle_purgetombstoneevent(&self, msg: PurgeTombstoneEvent) {
        let mut audit = AuditScope::new("purge tombstones", msg.eventid, self.log_level);

        ltrace!(audit, "Begin purge tombstone event {:?}", msg);
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;

        lperf_op_segment!(
            &mut audit,
            "actors::v1_write::handle<PurgeTombstoneEvent>",
            || {
                let res = idms_prox_write
                    .qs_write
                    .purge_tombstones(&mut audit)
                    .and_then(|_| idms_prox_write.commit(&mut audit));
                ladmin_info!(audit, "Purge tombstones result: {:?}", res);
                #[allow(clippy::expect_used)]
                res.expect("Invalid Server State");
            }
        );
        // At the end of the event we send it for logging.
        self.log.send(audit).unwrap_or_else(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
        });
    }

    pub(crate) async fn handle_purgerecycledevent(&self, msg: PurgeRecycledEvent) {
        let mut audit = AuditScope::new("purge recycled", msg.eventid, self.log_level);
        ltrace!(audit, "Begin purge recycled event {:?}", msg);
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        lperf_op_segment!(
            &mut audit,
            "actors::v1_write::handle<PurgeRecycledEvent>",
            || {
                let res = idms_prox_write
                    .qs_write
                    .purge_recycled(&mut audit)
                    .and_then(|_| idms_prox_write.commit(&mut audit));
                ladmin_info!(audit, "Purge recycled result: {:?}", res);
                #[allow(clippy::expect_used)]
                res.expect("Invalid Server State");
            }
        );
        // At the end of the event we send it for logging.
        self.log.send(audit).unwrap_or_else(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
        });
    }

    pub(crate) async fn handle_delayedaction(&self, da: DelayedAction) {
        let eventid = Uuid::new_v4();
        let mut audit = AuditScope::new("delayed action", eventid, self.log_level);
        ltrace!(audit, "Begin delayed action ...");
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write_async(ct).await;
        lperf_op_segment!(
            &mut audit,
            "actors::v1_write::handle<DelayedAction>",
            || {
                if let Err(res) = idms_prox_write
                    .process_delayedaction(&mut audit, da)
                    .and_then(|_| idms_prox_write.commit(&mut audit))
                {
                    ladmin_info!(audit, "delayed action error: {:?}", res);
                }
            }
        );
        self.log.send(audit).unwrap_or_else(|_| {
            error!("CRITICAL: UNABLE TO COMMIT LOGS");
        });
    }
}
