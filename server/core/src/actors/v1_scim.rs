use super::{QueryServerReadV1, QueryServerWriteV1};
use kanidm_proto::scim_v1::{
    server::ScimEntryKanidm, ScimEntryGetQuery, ScimSyncRequest, ScimSyncState,
};
use kanidmd_lib::idm::scim::{
    GenerateScimSyncTokenEvent, ScimSyncFinaliseEvent, ScimSyncTerminateEvent, ScimSyncUpdateEvent,
};
use kanidmd_lib::idm::server::IdmServerTransaction;
use kanidmd_lib::prelude::*;
use std::collections::BTreeSet;

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
        filter_intent: Filter<FilterInvalid>,
        eventid: Uuid,
        attrs: Option<BTreeSet<Attribute>>,
        acp: bool,
    ) -> Result<Vec<ScimEntryKanidm>, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_read = self.idms.proxy_read().await?;
        let ident = idms_prox_read
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .inspect_err(|err| {
                error!(?err, "Invalid identity");
            })?;

        let filter = filter_all!(f_and!([f_eq(Attribute::Class, EntryClass::Account.into())]));

        idms_prox_read
            .qs_read
            .impersonate_search_ext(filter_intent, filter, &ident, attrs, acp)?
            .into_iter()
            .map(|entry| entry.to_scim_kanidm(&mut idms_prox_read.qs_read))
            .collect()
    }
}
