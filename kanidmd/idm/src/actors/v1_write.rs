use std::iter;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, instrument, span, trace, Level};

use crate::idm::event::GenerateBackupCodeEvent;
use crate::idm::event::RemoveBackupCodeEvent;
use crate::prelude::*;

use crate::idm::credupdatesession::{
    CredentialUpdateIntentToken, CredentialUpdateSessionToken, InitCredentialUpdateEvent,
    InitCredentialUpdateIntentEvent,
};

use crate::event::{
    CreateEvent, DeleteEvent, ModifyEvent, PurgeRecycledEvent, PurgeTombstoneEvent,
    ReviveRecycledEvent,
};
use crate::idm::event::{
    AcceptSha1TotpEvent, GeneratePasswordEvent, GenerateTotpEvent, PasswordChangeEvent,
    RegenerateRadiusSecretEvent, RemoveTotpEvent, RemoveWebauthnEvent, UnixPasswordChangeEvent,
    VerifyTotpEvent, WebauthnDoRegisterEvent, WebauthnInitRegisterEvent,
};
use crate::modify::{Modify, ModifyInvalid, ModifyList};
use crate::value::{PartialValue, Value};
use kanidm_proto::v1::OperationError;

use crate::filter::{Filter, FilterInvalid};
use crate::idm::delayed::DelayedAction;
use crate::idm::server::{IdmServer, IdmServerTransaction};
use crate::utils::duration_from_epoch_now;

use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::Modify as ProtoModify;
use kanidm_proto::v1::ModifyList as ProtoModifyList;
use kanidm_proto::v1::{
    AccountPersonSet, AccountUnixExtend, CUIntentToken, CUSessionToken, CUStatus, CreateRequest,
    DeleteRequest, GroupUnixExtend, ModifyRequest, SetCredentialRequest, SetCredentialResponse,
};

use uuid::Uuid;

pub struct QueryServerWriteV1 {
    _log_level: Option<u32>,
    idms: Arc<IdmServer>,
}

impl QueryServerWriteV1 {
    pub fn new(log_level: Option<u32>, idms: Arc<IdmServer>) -> Self {
        info!("Starting query server v1 worker ...");
        QueryServerWriteV1 {
            _log_level: log_level,
            idms,
        }
    }

    pub fn start_static(
        log_level: Option<u32>,
        idms: Arc<IdmServer>,
    ) -> &'static QueryServerWriteV1 {
        let x = Box::new(QueryServerWriteV1::new(log_level, idms));

        let x_ptr = Box::leak(x);
        &(*x_ptr)
    }

    async fn modify_from_parts(
        &self,
        uat: Option<String>,
        uuid_or_name: &str,
        proto_ml: &ProtoModifyList,
        filter: Filter<FilterInvalid>,
    ) -> Result<(), OperationError> {
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        spanned!("modify_from_parts", {
            let ct = duration_from_epoch_now();

            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;

            let target_uuid = idms_prox_write
                .qs_write
                .name_to_uuid(uuid_or_name)
                .map_err(|e| {
                    admin_error!(err = ?e, "Error resolving id to target");
                    e
                })?;

            let mdf = match ModifyEvent::from_parts(
                ident,
                target_uuid,
                proto_ml,
                filter,
                &idms_prox_write.qs_write,
            ) {
                Ok(m) => m,
                Err(e) => {
                    admin_error!(err=?e, "Failed to begin modify");
                    return Err(e);
                }
            };

            trace!(?mdf, "Begin modify event");

            idms_prox_write
                .qs_write
                .modify(&mdf)
                .and_then(|_| idms_prox_write.commit().map(|_| ()))
        })
    }

    async fn modify_from_internal_parts(
        &self,
        uat: Option<String>,
        uuid_or_name: &str,
        ml: &ModifyList<ModifyInvalid>,
        filter: Filter<FilterInvalid>,
    ) -> Result<(), OperationError> {
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        spanned!("modify_from_internal_parts", {
            let ct = duration_from_epoch_now();

            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;

            let target_uuid = idms_prox_write
                .qs_write
                .name_to_uuid(uuid_or_name)
                .map_err(|e| {
                    admin_error!("Error resolving id to target");
                    e
                })?;

            let f_uuid = filter_all!(f_eq("uuid", PartialValue::new_uuid(target_uuid)));
            // Add any supplemental conditions we have.
            let joined_filter = Filter::join_parts_and(f_uuid, filter);

            let mdf = match ModifyEvent::from_internal_parts(
                ident,
                ml,
                &joined_filter,
                &idms_prox_write.qs_write,
            ) {
                Ok(m) => m,
                Err(e) => {
                    admin_error!(err = ?e, "Failed to begin modify");
                    return Err(e);
                }
            };

            trace!(?mdf, "Begin modify event");

            idms_prox_write
                .qs_write
                .modify(&mdf)
                .and_then(|_| idms_prox_write.commit().map(|_| ()))
        })
    }

    #[instrument(
        level = "trace",
        name = "create",
        skip(self, uat, req, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_create(
        &self,
        uat: Option<String>,
        req: CreateRequest,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = spanned!("actors::v1_write::handle<CreateMessage>", {
            let ct = duration_from_epoch_now();

            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;

            let crt = match CreateEvent::from_message(ident, &req, &idms_prox_write.qs_write) {
                Ok(c) => c,
                Err(e) => {
                    admin_warn!(err = ?e, "Failed to begin create");
                    return Err(e);
                }
            };

            trace!(?crt, "Begin create event");

            idms_prox_write
                .qs_write
                .create(&crt)
                .and_then(|_| idms_prox_write.commit())
        });
        // At the end of the event we send it for logging.
        res
    }

    pub async fn handle_modify(
        &self,
        uat: Option<String>,
        req: ModifyRequest,
        _eventid: Uuid,
    ) -> Result<(), OperationError> {
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = spanned!("actors::v1_write::handle<ModifyMessage>", {
            let ct = duration_from_epoch_now();
            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;

            let mdf = match ModifyEvent::from_message(ident, &req, &idms_prox_write.qs_write) {
                Ok(m) => m,
                Err(e) => {
                    admin_error!(err = ?e, "Failed to begin modify");
                    return Err(e);
                }
            };

            trace!(?mdf, "Begin modify event");

            idms_prox_write
                .qs_write
                .modify(&mdf)
                .and_then(|_| idms_prox_write.commit())
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "delete",
        skip(self, uat, req, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_delete(
        &self,
        uat: Option<String>,
        req: DeleteRequest,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = spanned!("actors::v1_write::handle<DeleteMessage>", {
            let ct = duration_from_epoch_now();
            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;
            let del = match DeleteEvent::from_message(ident, &req, &idms_prox_write.qs_write) {
                Ok(d) => d,
                Err(e) => {
                    admin_error!(err = ?e, "Failed to begin delete");
                    return Err(e);
                }
            };

            trace!(?del, "Begin delete event");

            idms_prox_write
                .qs_write
                .delete(&del)
                .and_then(|_| idms_prox_write.commit())
        });
        res
    }

    pub async fn handle_internalpatch(
        &self,
        uat: Option<String>,
        filter: Filter<FilterInvalid>,
        update: ProtoEntry,
        _eventid: Uuid,
    ) -> Result<(), OperationError> {
        // Given a protoEntry, turn this into a modification set.
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = spanned!("actors::v1_write::handle<InternalPatch>", {
            let ct = duration_from_epoch_now();
            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;

            // Transform the ProtoEntry to a Modlist
            let modlist =
                ModifyList::from_patch(&update, &idms_prox_write.qs_write).map_err(|e| {
                    admin_error!(err = ?e, "Invalid Patch Request");
                    e
                })?;

            let mdf = ModifyEvent::from_internal_parts(
                ident,
                &modlist,
                &filter,
                &idms_prox_write.qs_write,
            )
            .map_err(|e| {
                admin_error!(err = ?e, "Failed to begin modify");
                e
            })?;

            trace!(?mdf, "Begin modify event");

            idms_prox_write
                .qs_write
                .modify(&mdf)
                .and_then(|_| idms_prox_write.commit())
        });
        res.map(|_| ())
    }

    #[instrument(
        level = "trace",
        name = "internal_delete",
        skip(self, uat, filter, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internaldelete(
        &self,
        uat: Option<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = spanned!("actors::v1_write::handle<InternalDeleteMessage>", {
            let ct = duration_from_epoch_now();
            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;
            let del = match DeleteEvent::from_parts(ident, &filter, &idms_prox_write.qs_write) {
                Ok(d) => d,
                Err(e) => {
                    admin_error!(err = ?e, "Failed to begin delete");
                    return Err(e);
                }
            };

            trace!(?del, "Begin delete event");

            idms_prox_write
                .qs_write
                .delete(&del)
                .and_then(|_| idms_prox_write.commit().map(|_| ()))
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "reviverecycled",
        skip(self, uat, filter, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_reviverecycled(
        &self,
        uat: Option<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = spanned!("actors::v1_write::handle<ReviveRecycledMessage>", {
            let ct = duration_from_epoch_now();
            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;
            let rev =
                match ReviveRecycledEvent::from_parts(ident, &filter, &idms_prox_write.qs_write) {
                    Ok(r) => r,
                    Err(e) => {
                        admin_error!(err = ?e, "Failed to begin revive");
                        return Err(e);
                    }
                };

            trace!(?rev, "Begin revive event");

            idms_prox_write
                .qs_write
                .revive_recycled(&rev)
                .and_then(|_| idms_prox_write.commit().map(|_| ()))
        });
        res
    }

    // === IDM native types for modifications
    #[instrument(
        level = "trace",
        name = "credentialset",
        skip(self, uat, uuid_or_name, sac, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_credentialset(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        sac: SetCredentialRequest,
        eventid: Uuid,
    ) -> Result<SetCredentialResponse, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write_async(ct).await;
        let res = spanned!("actors::v1_write::handle<InternalCredentialSetMessage>", {
            // Trigger a session clean *before* we take any auth steps.
            // It's important to do this before to ensure that timeouts on
            // the session are enforced.
            idms_prox_write.expire_mfareg_sessions(ct);

            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;

            // given the uuid_or_name, determine the target uuid.
            // We can either do this by trying to parse the name or by creating a filter
            // to find the entry - there are risks to both TBH ... especially when the uuid
            // is also an entries name, but that they aren't the same entry.

            let target_uuid = idms_prox_write
                .qs_write
                .name_to_uuid(uuid_or_name.as_str())
                .map_err(|e| {
                    admin_error!(err = ?e, "Error resolving id to target");
                    e
                })?;

            // What type of auth set did we recieve?
            match sac {
                SetCredentialRequest::Password(cleartext) => {
                    let pce = PasswordChangeEvent::from_parts(
                        // &idms_prox_write.qs_write,
                        ident,
                        target_uuid,
                        cleartext,
                    )
                    .map_err(|e| {
                        admin_error!(
                            err = ?e,
                            "Failed to begin internal_credential_set_message",
                        );
                        e
                    })?;
                    idms_prox_write
                        .set_account_password(&pce)
                        .and_then(|_| idms_prox_write.commit())
                        .map(|_| SetCredentialResponse::Success)
                }
                SetCredentialRequest::GeneratePassword => {
                    let gpe = GeneratePasswordEvent::from_parts(
                        // &idms_prox_write.qs_write,
                        ident,
                        target_uuid,
                    )
                    .map_err(|e| {
                        admin_error!(
                            err = ?e,
                            "Failed to begin internal_credential_set_message",
                        );
                        e
                    })?;
                    idms_prox_write
                        .generate_account_password(&gpe)
                        .and_then(|r| idms_prox_write.commit().map(|_| r))
                        .map(SetCredentialResponse::Token)
                }
                SetCredentialRequest::TotpGenerate => {
                    let gte = GenerateTotpEvent::from_parts(
                        // &idms_prox_write.qs_write,
                        ident,
                        target_uuid,
                    )
                    .map_err(|e| {
                        admin_error!(
                            err = ?e,
                            "Failed to begin internal_credential_set_message",
                        );
                        e
                    })?;
                    idms_prox_write
                        .generate_account_totp(&gte, ct)
                        .and_then(|r| idms_prox_write.commit().map(|_| r))
                }
                SetCredentialRequest::TotpVerify(uuid, chal) => {
                    let vte = VerifyTotpEvent::from_parts(
                        // &idms_prox_write.qs_write,
                        ident,
                        target_uuid,
                        uuid,
                        chal,
                    )
                    .map_err(|e| {
                        admin_error!(
                            err = ?e,
                            "Failed to begin internal_credential_set_message",
                        );
                        e
                    })?;
                    idms_prox_write
                        .verify_account_totp(&vte, ct)
                        .and_then(|r| idms_prox_write.commit().map(|_| r))
                }
                SetCredentialRequest::TotpAcceptSha1(uuid) => {
                    let aste =
                        AcceptSha1TotpEvent::from_parts(ident, target_uuid, uuid).map_err(|e| {
                            admin_error!(
                                err = ?e,
                                "Failed to begin internal_credential_set_message",
                            );
                            e
                        })?;
                    idms_prox_write
                        .accept_account_sha1_totp(&aste)
                        .and_then(|r| idms_prox_write.commit().map(|_| r))
                }
                SetCredentialRequest::TotpRemove => {
                    let rte = RemoveTotpEvent::from_parts(
                        // &idms_prox_write.qs_write,
                        ident,
                        target_uuid,
                    )
                    .map_err(|e| {
                        admin_error!(
                            err = ?e,
                            "Failed to begin internal_credential_set_message",
                        );
                        e
                    })?;
                    idms_prox_write
                        .remove_account_totp(&rte)
                        .and_then(|r| idms_prox_write.commit().map(|_| r))
                }
                SetCredentialRequest::WebauthnBegin(label) => {
                    let wre = WebauthnInitRegisterEvent::from_parts(
                        // &idms_prox_write.qs_write,
                        ident,
                        target_uuid,
                        label,
                    )
                    .map_err(|e| {
                        admin_error!(
                            err = ?e,
                            "Failed to begin internal_credential_set_message",
                        );
                        e
                    })?;
                    idms_prox_write
                        .reg_account_webauthn_init(&wre, ct)
                        .and_then(|r| idms_prox_write.commit().map(|_| r))
                }
                SetCredentialRequest::WebauthnRegister(uuid, rpkc) => {
                    let wre = WebauthnDoRegisterEvent::from_parts(
                        // &idms_prox_write.qs_write,
                        ident,
                        target_uuid,
                        uuid,
                        rpkc,
                    )
                    .map_err(|e| {
                        admin_error!(
                            err = ?e,
                            "Failed to begin internal_credential_set_message",
                        );
                        e
                    })?;
                    idms_prox_write
                        .reg_account_webauthn_complete(&wre)
                        .and_then(|r| idms_prox_write.commit().map(|_| r))
                }
                SetCredentialRequest::WebauthnRemove(label) => {
                    let rwe = RemoveWebauthnEvent::from_parts(
                        // &idms_prox_write.qs_write,
                        ident,
                        target_uuid,
                        label,
                    )
                    .map_err(|e| {
                        admin_error!(
                            err = ?e,
                            "Failed to begin internal_credential_set_message",
                        );
                        e
                    })?;
                    idms_prox_write
                        .remove_account_webauthn(&rwe)
                        .and_then(|r| idms_prox_write.commit().map(|_| r))
                }
                SetCredentialRequest::BackupCodeGenerate => {
                    let gbe = GenerateBackupCodeEvent::from_parts(
                        // &idms_prox_write.qs_write,
                        ident,
                        target_uuid,
                    )
                    .map_err(|e| {
                        admin_error!(
                            err = ?e,
                            "Failed to begin internal_credential_set_message",
                        );
                        e
                    })?;
                    idms_prox_write
                        .generate_backup_code(&gbe)
                        .and_then(|r| idms_prox_write.commit().map(|_| r))
                        .map(SetCredentialResponse::BackupCodes)
                }
                SetCredentialRequest::BackupCodeRemove => {
                    let rbe = RemoveBackupCodeEvent::from_parts(
                        // &idms_prox_write.qs_write,
                        ident,
                        target_uuid,
                    )
                    .map_err(|e| {
                        admin_error!(
                            err = ?e,
                            "Failed to begin internal_credential_set_message",
                        );
                        e
                    })?;
                    idms_prox_write
                        .remove_backup_code(&rbe)
                        .and_then(|r| idms_prox_write.commit().map(|_| r))
                }
            }
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "idmcredentialupdate",
        skip(self, uat, uuid_or_name, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialupdate(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<(CUSessionToken, CUStatus), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write_async(ct).await;
        let res = spanned!("actors::v1_write::handle<IdmCredentialUpdate>", {
            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;

            let target_uuid = idms_prox_write
                .qs_write
                .name_to_uuid(uuid_or_name.as_str())
                .map_err(|e| {
                    admin_error!(err = ?e, "Error resolving id to target");
                    e
                })?;

            idms_prox_write
                .init_credential_update(&InitCredentialUpdateEvent::new(ident, target_uuid), ct)
                .and_then(|tok| idms_prox_write.commit().map(|_| tok))
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin init_credential_update",
                    );
                    e
                })
                .map(|(tok, sta)| {
                    (
                        CUSessionToken {
                            token: tok.token_enc,
                        },
                        sta.into(),
                    )
                })
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "idmcredentialupdateintent",
        skip(self, uat, uuid_or_name, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialupdateintent(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        ttl: Option<Duration>,
        eventid: Uuid,
    ) -> Result<CUIntentToken, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write_async(ct).await;
        let res = spanned!("actors::v1_write::handle<IdmCredentialUpdateIntent>", {
            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;

            let target_uuid = idms_prox_write
                .qs_write
                .name_to_uuid(uuid_or_name.as_str())
                .map_err(|e| {
                    admin_error!(err = ?e, "Error resolving id to target");
                    e
                })?;

            idms_prox_write
                .init_credential_update_intent(
                    &InitCredentialUpdateIntentEvent::new(ident, target_uuid, ttl),
                    ct,
                )
                .and_then(|tok| idms_prox_write.commit().map(|_| tok))
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin init_credential_update_intent",
                    );
                    e
                })
                .map(|tok| CUIntentToken {
                    token: tok.intent_id,
                })
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "idmcredentialexchangeintent",
        skip(self, intent_token, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialexchangeintent(
        &self,
        intent_token: CUIntentToken,
        eventid: Uuid,
    ) -> Result<(CUSessionToken, CUStatus), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write_async(ct).await;
        let res = spanned!("actors::v1_write::handle<IdmCredentialExchangeIntent>", {
            let intent_token = CredentialUpdateIntentToken {
                intent_id: intent_token.token,
            };
            // TODO: this is throwing a 500 error when a session is already in use, that seems bad?
            idms_prox_write
                .exchange_intent_credential_update(intent_token, ct)
                .and_then(|tok| idms_prox_write.commit().map(|_| tok))
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin exchange_intent_credential_update",
                    );
                    e
                })
                .map(|(tok, sta)| {
                    (
                        CUSessionToken {
                            token: tok.token_enc,
                        },
                        sta.into(),
                    )
                })
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "idmcredentialupdatecommit",
        skip(self, session_token, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialupdatecommit(
        &self,
        session_token: CUSessionToken,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write_async(ct).await;
        let res = spanned!("actors::v1_write::handle<IdmCredentialUpdateCommit>", {
            let session_token = CredentialUpdateSessionToken {
                token_enc: session_token.token,
            };

            idms_prox_write
                .commit_credential_update(session_token, ct)
                .and_then(|tok| idms_prox_write.commit().map(|_| tok))
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin commit_credential_update",
                    );
                    e
                })
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "idmaccountsetpassword",
        skip(self, uat, cleartext, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmaccountsetpassword(
        &self,
        uat: Option<String>,
        cleartext: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write_async(ct).await;
        let res = spanned!("actors::v1_write::handle<IdmAccountSetPasswordMessage>", {
            idms_prox_write.expire_mfareg_sessions(ct);

            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;

            let pce = PasswordChangeEvent::from_idm_account_set_password(
                ident, cleartext,
                // &idms_prox_write.qs_write,
            )
            .map_err(|e| {
                admin_error!(err = ?e, "Failed to begin idm_account_set_password");
                e
            })?;

            idms_prox_write
                .set_account_password(&pce)
                .and_then(|_| idms_prox_write.commit())
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "regenerateradius",
        skip(self, uat, uuid_or_name, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_regenerateradius(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<String, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write_async(ct).await;
        let res = spanned!(
            "actors::v1_write::handle<InternalRegenerateRadiusMessage>",
            {
                idms_prox_write.expire_mfareg_sessions(ct);

                let ident = idms_prox_write
                    .validate_and_parse_uat(uat.as_deref(), ct)
                    .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                    .map_err(|e| {
                        admin_error!(err = ?e, "Invalid identity");
                        e
                    })?;

                let target_uuid = idms_prox_write
                    .qs_write
                    .name_to_uuid(uuid_or_name.as_str())
                    .map_err(|e| {
                        admin_error!(err = ?e, "Error resolving id to target");
                        e
                    })?;

                let rrse = RegenerateRadiusSecretEvent::from_parts(
                    // &idms_prox_write.qs_write,
                    ident,
                    target_uuid,
                )
                .map_err(|e| {
                    admin_error!(
                        err = ?e,
                        "Failed to begin idm_account_regenerate_radius",
                    );
                    e
                })?;

                idms_prox_write
                    .regenerate_radius_secret(&rrse)
                    .and_then(|r| idms_prox_write.commit().map(|_| r))
            }
        );
        res
    }

    #[instrument(
        level = "trace",
        name = "purgeattribute",
        skip(self, uat, uuid_or_name, attr, filter, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_purgeattribute(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        attr: String,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = spanned!("actors::v1_write::handle<PurgeAttributeMessage>", {
            let ct = duration_from_epoch_now();
            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;
            let target_uuid = idms_prox_write
                .qs_write
                .name_to_uuid(uuid_or_name.as_str())
                .map_err(|e| {
                    admin_error!(err = ?e, "Error resolving id to target");
                    e
                })?;

            let mdf = match ModifyEvent::from_target_uuid_attr_purge(
                ident,
                target_uuid,
                &attr,
                filter,
                &idms_prox_write.qs_write,
            ) {
                Ok(m) => m,
                Err(e) => {
                    admin_error!(err = ?e, "Failed to begin modify");
                    return Err(e);
                }
            };

            trace!(?mdf, "Begin modify event");

            idms_prox_write
                .qs_write
                .modify(&mdf)
                .and_then(|_| idms_prox_write.commit().map(|_| ()))
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "removeattributevalues",
        skip(self, uat, uuid_or_name, attr, values, filter, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_removeattributevalues(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        attr: String,
        values: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        let res = spanned!("actors::v1_write::handle<RemoveAttributeValuesMessage>", {
            let ct = duration_from_epoch_now();
            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;
            let target_uuid = idms_prox_write
                .qs_write
                .name_to_uuid(uuid_or_name.as_str())
                .map_err(|e| {
                    admin_error!(err = ?e, "Error resolving id to target");
                    e
                })?;

            let proto_ml = ProtoModifyList::new_list(
                values
                    .into_iter()
                    .map(|v| ProtoModify::Removed(attr.clone(), v))
                    .collect(),
            );

            let mdf = match ModifyEvent::from_parts(
                ident,
                target_uuid,
                &proto_ml,
                filter,
                &idms_prox_write.qs_write,
            ) {
                Ok(m) => m,
                Err(e) => {
                    admin_error!(err = ?e, "Failed to begin modify");
                    return Err(e);
                }
            };

            trace!(?mdf, "Begin modify event");

            idms_prox_write
                .qs_write
                .modify(&mdf)
                .and_then(|_| idms_prox_write.commit().map(|_| ()))
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "appendattribute",
        skip(self, uat, uuid_or_name, attr, values, filter, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_appendattribute(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        attr: String,
        values: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // We need to turn these into proto modlists so they can be converted
        // and validated.
        let proto_ml = ProtoModifyList::new_list(
            values
                .into_iter()
                .map(|v| ProtoModify::Present(attr.clone(), v))
                .collect(),
        );
        let res = self
            .modify_from_parts(uat, &uuid_or_name, &proto_ml, filter)
            .await;
        res
    }

    #[instrument(
        level = "trace",
        name = "setattribute",
        skip(self, uat, uuid_or_name, attr, values, filter, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_setattribute(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        attr: String,
        values: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
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
            .modify_from_parts(uat, &uuid_or_name, &proto_ml, filter)
            .await;
        res
    }

    #[instrument(
        level = "trace",
        name = "sshkeycreate",
        skip(self, uat, uuid_or_name, tag, key, filter, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_sshkeycreate(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        tag: String,
        key: String,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // Because this is from internal, we can generate a real modlist, rather
        // than relying on the proto ones.
        let ml = ModifyList::new_append("ssh_publickey", Value::new_sshkey(tag, key));

        let res = self
            .modify_from_internal_parts(uat, &uuid_or_name, &ml, filter)
            .await;
        res
    }

    #[instrument(
        level = "trace",
        name = "idmaccountpersonextend",
        skip(self, uat, uuid_or_name, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmaccountpersonextend(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        px: AccountPersonSet,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let AccountPersonSet { mail, legalname } = px;

        let mut mods: Vec<_> = Vec::with_capacity(4 + mail.as_ref().map(|v| v.len()).unwrap_or(0));
        mods.push(Modify::Present("class".into(), Value::new_class("person")));

        if let Some(s) = legalname {
            mods.push(Modify::Purged("legalname".into()));
            mods.push(Modify::Present("legalname".into(), Value::new_utf8(s)));
        }

        if let Some(mail) = mail {
            mods.push(Modify::Purged("mail".into()));

            let mut miter = mail.into_iter();
            if let Some(m_primary) = miter.next() {
                let v =
                    Value::new_email_address_primary_s(m_primary.as_str()).ok_or_else(|| {
                        OperationError::InvalidAttribute(format!(
                            "Invalid mail address {}",
                            m_primary
                        ))
                    })?;
                mods.push(Modify::Present("mail".into(), v));
            }

            for m in miter {
                let v = Value::new_email_address_s(m.as_str()).ok_or_else(|| {
                    OperationError::InvalidAttribute(format!("Invalid mail address {}", m))
                })?;
                mods.push(Modify::Present("mail".into(), v));
            }
        }

        let ml = ModifyList::new_list(mods);

        let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));

        let res = self
            .modify_from_internal_parts(uat, &uuid_or_name, &ml, filter)
            .await;
        res
    }

    #[instrument(
        level = "trace",
        name = "idmaccountpersonset",
        skip(self, uat, uuid_or_name, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmaccountpersonset(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        px: AccountPersonSet,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let AccountPersonSet { mail, legalname } = px;

        let mut mods: Vec<_> = Vec::with_capacity(3 + mail.as_ref().map(|v| v.len()).unwrap_or(0));

        if let Some(s) = legalname {
            mods.push(Modify::Purged("legalname".into()));
            mods.push(Modify::Present("legalname".into(), Value::new_utf8(s)));
        }

        if let Some(mail) = mail {
            mods.push(Modify::Purged("mail".into()));

            let mut miter = mail.into_iter();
            if let Some(m_primary) = miter.next() {
                let v =
                    Value::new_email_address_primary_s(m_primary.as_str()).ok_or_else(|| {
                        OperationError::InvalidAttribute(format!(
                            "Invalid mail address {}",
                            m_primary
                        ))
                    })?;
                mods.push(Modify::Present("mail".into(), v));
            }

            for m in miter {
                let v = Value::new_email_address_s(m.as_str()).ok_or_else(|| {
                    OperationError::InvalidAttribute(format!("Invalid mail address {}", m))
                })?;
                mods.push(Modify::Present("mail".into(), v));
            }
        }

        let ml = ModifyList::new_list(mods);

        let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));

        let res = self
            .modify_from_internal_parts(uat, &uuid_or_name, &ml, filter)
            .await;
        res
    }

    #[instrument(
        level = "trace",
        name = "idmaccountunixextend",
        skip(self, uat, uuid_or_name, ux, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmaccountunixextend(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        ux: AccountUnixExtend,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let AccountUnixExtend { gidnumber, shell } = ux;
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
            .modify_from_internal_parts(uat, &uuid_or_name, &ml, filter)
            .await;
        res
    }

    #[instrument(
        level = "trace",
        name = "idmgroupunixextend",
        skip(self, uat, uuid_or_name, gx, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmgroupunixextend(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        gx: GroupUnixExtend,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
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
            .modify_from_internal_parts(uat, &uuid_or_name, &ml, filter)
            .await;
        res
    }

    #[instrument(
        level = "trace",
        name = "idmaccountunixsetcred",
        skip(self, uat, uuid_or_name, cred, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmaccountunixsetcred(
        &self,
        uat: Option<String>,
        uuid_or_name: String,
        cred: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write_async(ct).await;
        let res = spanned!("actors::v1_write::handle<IdmAccountUnixSetCredMessage>", {
            idms_prox_write.expire_mfareg_sessions(ct);

            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;

            let target_uuid = Uuid::parse_str(uuid_or_name.as_str()).or_else(|_| {
                idms_prox_write
                    .qs_write
                    .name_to_uuid(uuid_or_name.as_str())
                    .map_err(|e| {
                        admin_info!("Error resolving as gidnumber continuing ...");
                        e
                    })
            })?;

            let upce = UnixPasswordChangeEvent::from_parts(
                // &idms_prox_write.qs_write,
                ident,
                target_uuid,
                cred,
            )
            .map_err(|e| {
                admin_error!(err = ?e, "Failed to begin UnixPasswordChangeEvent");
                e
            })?;
            idms_prox_write
                .set_unix_account_password(&upce)
                .and_then(|_| idms_prox_write.commit())
                .map(|_| ())
        });
        res
    }

    #[instrument(
        level = "trace",
        name = "oauth2_scopemap_create",
        skip(self, uat, filter, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_scopemap_create(
        &self,
        uat: Option<String>,
        group: String,
        scopes: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // Because this is from internal, we can generate a real modlist, rather
        // than relying on the proto ones.
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        spanned!("handle_oauth2_scopemap_create", {
            let ct = duration_from_epoch_now();

            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;

            let group_uuid = idms_prox_write
                .qs_write
                .name_to_uuid(group.as_str())
                .map_err(|e| {
                    admin_error!(err = ?e, "Error resolving group name to target");
                    e
                })?;

            let ml = ModifyList::new_append(
                "oauth2_rs_scope_map",
                Value::new_oauthscopemap(group_uuid, scopes.into_iter().collect()).ok_or_else(
                    || {
                        OperationError::InvalidAttribute(
                            "Invalid Oauth Scope Map syntax".to_string(),
                        )
                    },
                )?,
            );

            let mdf = match ModifyEvent::from_internal_parts(
                ident,
                &ml,
                &filter,
                &idms_prox_write.qs_write,
            ) {
                Ok(m) => m,
                Err(e) => {
                    admin_error!(err = ?e, "Failed to begin modify");
                    return Err(e);
                }
            };

            trace!(?mdf, "Begin modify event");

            idms_prox_write
                .qs_write
                .modify(&mdf)
                .and_then(|_| idms_prox_write.commit().map(|_| ()))
        })
    }

    #[instrument(
        level = "trace",
        name = "oauth2_scopemap_delete",
        skip(self, uat, filter, eventid)
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_scopemap_delete(
        &self,
        uat: Option<String>,
        group: String,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        spanned!("handle_oauth2_scopemap_create", {
            let ct = duration_from_epoch_now();

            let ident = idms_prox_write
                .validate_and_parse_uat(uat.as_deref(), ct)
                .and_then(|uat| idms_prox_write.process_uat_to_identity(&uat, ct))
                .map_err(|e| {
                    admin_error!(err = ?e, "Invalid identity");
                    e
                })?;

            let group_uuid = idms_prox_write
                .qs_write
                .name_to_uuid(group.as_str())
                .map_err(|e| {
                    admin_error!(err = ?e, "Error resolving group name to target");
                    e
                })?;

            let ml = ModifyList::new_remove(
                "oauth2_rs_scope_map",
                PartialValue::new_oauthscopemap(group_uuid),
            );

            let mdf = match ModifyEvent::from_internal_parts(
                ident,
                &ml,
                &filter,
                &idms_prox_write.qs_write,
            ) {
                Ok(m) => m,
                Err(e) => {
                    admin_error!(err = ?e, "Failed to begin modify");
                    return Err(e);
                }
            };

            trace!(?mdf, "Begin modify event");

            idms_prox_write
                .qs_write
                .modify(&mdf)
                .and_then(|_| idms_prox_write.commit().map(|_| ()))
        })
    }

    // ===== These below are internal only event types. =====
    #[instrument(
        level = "trace",
        name = "purge_tombstone_event",
        skip(self, msg)
        fields(uuid = ?msg.eventid)
    )]
    pub(crate) async fn handle_purgetombstoneevent(&self, msg: PurgeTombstoneEvent) {
        trace!(?msg, "Begin purge tombstone event");
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;

        spanned!("actors::v1_write::handle<PurgeTombstoneEvent>", {
            let res = idms_prox_write
                .qs_write
                .purge_tombstones()
                .and_then(|_| idms_prox_write.commit());
            admin_info!(?res, "Purge tombstones result");
            #[allow(clippy::expect_used)]
            res.expect("Invalid Server State");
        });
    }

    #[instrument(
        level = "trace",
        name = "purge_recycled_event",
        skip(self, msg)
        fields(uuid = ?msg.eventid)
    )]
    pub(crate) async fn handle_purgerecycledevent(&self, msg: PurgeRecycledEvent) {
        trace!(?msg, "Begin purge recycled event");
        let idms_prox_write = self.idms.proxy_write_async(duration_from_epoch_now()).await;
        spanned!("actors::v1_write::handle<PurgeRecycledEvent>", {
            let res = idms_prox_write
                .qs_write
                .purge_recycled()
                .and_then(|_| idms_prox_write.commit());
            admin_info!(?res, "Purge recycled result");
            #[allow(clippy::expect_used)]
            res.expect("Invalid Server State");
        });
    }

    pub(crate) async fn handle_delayedaction(&self, da: DelayedAction) {
        let eventid = Uuid::new_v4();
        let nspan = span!(Level::TRACE, "delayedaction", uuid = ?eventid);
        let _span = nspan.enter();

        trace!("Begin delayed action ...");
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write_async(ct).await;
        spanned!("actors::v1_write::handle<DelayedAction>", {
            if let Err(res) = idms_prox_write
                .process_delayedaction(da)
                .and_then(|_| idms_prox_write.commit())
            {
                admin_info!(?res, "delayed action error");
            }
        });
    }
}
