use super::{QueryServerReadV1, QueryServerWriteV1};
use kanidm_proto::scim_v1::{
    client::{ScimEntryPostGeneric, ScimEntryPutGeneric},
    server::{ScimEntryKanidm, ScimListResponse},
    ScimApplicationPassword, ScimApplicationPasswordCreate, ScimEntryGetQuery, ScimFilter,
    ScimSyncRequest, ScimSyncState,
};
use kanidmd_lib::idm::application::GenerateApplicationPasswordEvent;
use kanidmd_lib::idm::scim::{
    GenerateScimSyncTokenEvent, ScimSyncFinaliseEvent, ScimSyncTerminateEvent, ScimSyncUpdateEvent,
};
use kanidmd_lib::idm::server::IdmServerTransaction;
use kanidmd_lib::prelude::*;
use kanidmd_lib::server::scim::{ScimCreateEvent, ScimDeleteEvent, ScimEntryPutEvent};

impl QueryServerWriteV1 {
    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_sync_account_token_generate(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        label: String,
        eventid: Uuid,
    ) -> Result<String, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                admin_error!(err = ?e, "Invalid identity");
                e
            })?;

        let target = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                admin_error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let gte = GenerateScimSyncTokenEvent {
            ident,
            target,
            label,
        };

        idms_prox_write
            .scim_sync_generate_token(&gte, ct)
            .map(|token| token.to_string())
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_sync_account_token_destroy(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                admin_error!(err = ?e, "Invalid identity");
                e
            })?;

        let target = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                admin_error!(err = ?e, "Error resolving id to target");
                e
            })?;

        idms_prox_write
            .sync_account_destroy_token(&ident, target, ct)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_sync_account_finalise(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                admin_error!(err = ?e, "Invalid identity");
                e
            })?;

        let target = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                admin_error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let sfe = ScimSyncFinaliseEvent { ident, target };

        idms_prox_write
            .scim_sync_finalise(&sfe)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_sync_account_terminate(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                admin_error!(err = ?e, "Invalid identity");
                e
            })?;

        let target = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                admin_error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let ste = ScimSyncTerminateEvent { ident, target };

        idms_prox_write
            .scim_sync_terminate(&ste)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_scim_sync_apply(
        &self,
        client_auth_info: ClientAuthInfo,
        changes: ScimSyncRequest,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident =
            idms_prox_write.validate_sync_client_auth_info_to_ident(client_auth_info, ct)?;

        let sse = ScimSyncUpdateEvent { ident };

        idms_prox_write
            .scim_sync_apply(&sse, &changes, ct)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn scim_entry_create(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
        classes: &[EntryClass],
        entry: ScimEntryPostGeneric,
    ) -> Result<ScimEntryKanidm, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                admin_error!(err = ?e, "Invalid identity");
                e
            })?;

        let scim_create_event =
            ScimCreateEvent::try_from(ident, classes, entry, &mut idms_prox_write.qs_write)?;

        idms_prox_write
            .qs_write
            .scim_create(scim_create_event)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn scim_entry_id_delete(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
        uuid_or_name: String,
        class: EntryClass,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                admin_error!(err = ?e, "Invalid identity");
                e
            })?;

        let target = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                admin_error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let scim_delete_event = ScimDeleteEvent::new(ident, target, class);

        idms_prox_write
            .qs_write
            .scim_delete(scim_delete_event)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn scim_person_application_create_password(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
        uuid_or_name: String,
        request: ScimApplicationPasswordCreate,
    ) -> Result<ScimApplicationPassword, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let ScimApplicationPasswordCreate {
            application_uuid,
            label,
        } = request;

        let target = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let generate_application_password_event =
            GenerateApplicationPasswordEvent::from_parts(ident, target, application_uuid, label)?;

        idms_prox_write
            .generate_application_password(&generate_application_password_event)
            .and_then(|(secret, uuid)| {
                idms_prox_write.commit()?;

                Ok(ScimApplicationPassword {
                    uuid,
                    label: generate_application_password_event.label,
                    secret,
                })
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn scim_person_application_delete_password(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
        uuid_or_name: String,
        apppwd_id: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        idms_prox_write
            .application_password_delete(&ident, target, apppwd_id)
            .and_then(|()| idms_prox_write.commit())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_scim_entry_put(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
        generic: ScimEntryPutGeneric,
    ) -> Result<ScimEntryKanidm, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|op_err| {
                admin_error!(err = ?op_err, "Invalid identity");
                op_err
            })?;

        let scim_entry_put_event =
            ScimEntryPutEvent::try_from(ident, generic, &mut idms_prox_write.qs_write)?;

        idms_prox_write
            .qs_write
            .scim_put(scim_entry_put_event)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }
}

impl QueryServerReadV1 {
    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_scim_sync_status(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
    ) -> Result<ScimSyncState, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;

        let ident = idms_prox_read.validate_sync_client_auth_info_to_ident(client_auth_info, ct)?;

        idms_prox_read.scim_sync_get_state(&ident)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn scim_entry_id_get(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
        uuid_or_name: String,
        class: EntryClass,
        query: ScimEntryGetQuery,
    ) -> Result<ScimEntryKanidm, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .inspect_err(|err| {
                error!(?err, "Invalid identity");
            })?;

        let target_uuid = idms_prox_read
            .qs_read
            .name_to_uuid(uuid_or_name.as_str())
            .inspect_err(|err| {
                error!(?err, "Error resolving id to target");
            })?;

        idms_prox_read
            .qs_read
            .scim_entry_id_get_ext(target_uuid, class, query, ident)
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn scim_entry_search(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
        filter: ScimFilter,
        query: ScimEntryGetQuery,
    ) -> Result<ScimListResponse, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .inspect_err(|err| {
                error!(?err, "Invalid identity");
            })?;

        idms_prox_read.qs_read.scim_search_ext(ident, filter, query)
    }
}
