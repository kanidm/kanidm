use std::iter;

use compact_jwt::JweCompact;
use kanidm_proto::internal::{
    CUIntentToken, CUSessionToken, CUStatus, CreateRequest, DeleteRequest, ImageValue,
    Modify as ProtoModify, ModifyList as ProtoModifyList, ModifyRequest,
    Oauth2ClaimMapJoin as ProtoOauth2ClaimMapJoin, OperationError,
};
use kanidm_proto::v1::{AccountUnixExtend, Entry as ProtoEntry, GroupUnixExtend};
use std::str::FromStr;
use time::OffsetDateTime;
use tracing::{info, instrument, trace};
use uuid::Uuid;

use kanidmd_lib::{
    event::{CreateEvent, DeleteEvent, ModifyEvent, ReviveRecycledEvent},
    filter::{Filter, FilterInvalid},
    idm::account::DestroySessionTokenEvent,
    idm::credupdatesession::{
        CredentialUpdateIntentTokenExchange, CredentialUpdateSessionToken,
        InitCredentialUpdateEvent, InitCredentialUpdateIntentEvent,
    },
    idm::event::{GeneratePasswordEvent, RegenerateRadiusSecretEvent, UnixPasswordChangeEvent},
    idm::oauth2::{
        AccessTokenRequest, AccessTokenResponse, AuthorisePermitSuccess, Oauth2Error,
        TokenRevokeRequest,
    },
    idm::server::IdmServerTransaction,
    idm::serviceaccount::{DestroyApiTokenEvent, GenerateApiTokenEvent},
    modify::{Modify, ModifyInvalid, ModifyList},
    value::{OauthClaimMapJoin, PartialValue, Value},
};

use kanidmd_lib::prelude::*;

use super::QueryServerWriteV1;

impl QueryServerWriteV1 {
    #[instrument(level = "debug", skip_all)]
    async fn modify_from_parts(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: &str,
        proto_ml: &ProtoModifyList,
        filter: Filter<FilterInvalid>,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name)
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let mdf = match ModifyEvent::from_parts(
            ident,
            target_uuid,
            proto_ml,
            filter,
            &mut idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err=?e, "Failed to begin modify during modify_from_parts");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(level = "debug", skip_all)]
    async fn modify_from_internal_parts(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: &str,
        ml: &ModifyList<ModifyInvalid>,
        filter: Filter<FilterInvalid>,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name)
            .inspect_err(|err| {
                error!(?err, "Error resolving id to target");
            })?;

        let f_uuid = filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(target_uuid)));
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
                error!(err = ?e, "Failed to begin modify during modify_from_internal_parts");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_create(
        &self,
        client_auth_info: ClientAuthInfo,
        req: CreateRequest,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let crt = match CreateEvent::from_message(ident, &req, &mut idms_prox_write.qs_write) {
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
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_modify(
        &self,
        client_auth_info: ClientAuthInfo,
        req: ModifyRequest,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let mdf = match ModifyEvent::from_message(ident, &req, &mut idms_prox_write.qs_write) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify during handle_modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_delete(
        &self,
        client_auth_info: ClientAuthInfo,
        req: DeleteRequest,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;
        let del = match DeleteEvent::from_message(ident, &req, &mut idms_prox_write.qs_write) {
            Ok(d) => d,
            Err(e) => {
                error!(err = ?e, "Failed to begin delete");
                return Err(e);
            }
        };

        trace!(?del, "Begin delete event");

        idms_prox_write
            .qs_write
            .delete(&del)
            .and_then(|_| idms_prox_write.commit())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalpatch(
        &self,
        client_auth_info: ClientAuthInfo,
        filter: Filter<FilterInvalid>,
        update: ProtoEntry,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // Given a protoEntry, turn this into a modification set.
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        // Transform the ProtoEntry to a Modlist
        let modlist =
            ModifyList::from_patch(&update, &mut idms_prox_write.qs_write).map_err(|e| {
                error!(err = ?e, "Invalid Patch Request");
                e
            })?;

        let mdf =
            ModifyEvent::from_internal_parts(ident, &modlist, &filter, &idms_prox_write.qs_write)
                .map_err(|e| {
                error!(err = ?e, "Failed to begin modify during handle_internalpatch");
                e
            })?;

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internaldelete(
        &self,
        client_auth_info: ClientAuthInfo,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;
        let del = match DeleteEvent::from_parts(ident, &filter, &mut idms_prox_write.qs_write) {
            Ok(d) => d,
            Err(e) => {
                error!(err = ?e, "Failed to begin delete");
                return Err(e);
            }
        };

        trace!(?del, "Begin delete event");

        idms_prox_write
            .qs_write
            .delete(&del)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_reviverecycled(
        &self,
        client_auth_info: ClientAuthInfo,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;
        let rev = match ReviveRecycledEvent::from_parts(ident, &filter, &idms_prox_write.qs_write) {
            Ok(r) => r,
            Err(e) => {
                error!(err = ?e, "Failed to begin revive");
                return Err(e);
            }
        };

        trace!(?rev, "Begin revive event");

        idms_prox_write
            .qs_write
            .revive_recycled(&rev)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_service_account_credential_generate(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<String, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
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
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let gpe = GeneratePasswordEvent::from_parts(ident, target_uuid).map_err(|e| {
            error!(
                err = ?e,
                "Failed to begin handle_service_account_credential_generate",
            );
            e
        })?;
        idms_prox_write
            .generate_service_account_password(&gpe)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_service_account_api_token_generate(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        label: String,
        expiry: Option<OffsetDateTime>,
        read_write: bool,
        eventid: Uuid,
    ) -> Result<String, OperationError> {
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

        let gte = GenerateApiTokenEvent {
            ident,
            target,
            label,
            expiry,
            read_write,
        };

        idms_prox_write
            .service_account_generate_api_token(&gte, ct)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
            .map(|token| token.to_string())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_service_account_api_token_destroy(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        token_id: Uuid,
        eventid: Uuid,
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

        let dte = DestroyApiTokenEvent {
            ident,
            target,
            token_id,
        };

        idms_prox_write
            .service_account_destroy_api_token(&dte)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_account_user_auth_token_destroy(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        token_id: Uuid,
        eventid: Uuid,
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

        let dte = DestroySessionTokenEvent {
            ident,
            target,
            token_id,
        };

        idms_prox_write
            .account_destroy_session_token(&dte)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_logout(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        // We specifically need a uat here to assess the auth type!
        let validate_result =
            idms_prox_write.validate_client_auth_info_to_ident(client_auth_info, ct);

        let ident = match validate_result {
            Ok(ident) => ident,
            Err(OperationError::SessionExpired) | Err(OperationError::NotAuthenticated) => {
                return Ok(())
            }
            Err(err) => {
                error!(?err, "Invalid identity");
                return Err(err);
            }
        };

        if !ident.can_logout() {
            info!("Ignoring request to logout session - these sessions are not recorded");
            return Ok(());
        };

        let target = ident.get_uuid().ok_or_else(|| {
            error!("Invalid identity - no uuid present");
            OperationError::InvalidState
        })?;

        let token_id = ident.get_session_id();

        let dte = DestroySessionTokenEvent {
            ident,
            target,
            token_id,
        };

        idms_prox_write
            .account_destroy_session_token(&dte)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialupdate(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<(CUSessionToken, CUStatus), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        idms_prox_write
            .init_credential_update(&InitCredentialUpdateEvent::new(ident, target_uuid), ct)
            .and_then(|tok| idms_prox_write.commit().map(|_| tok))
            .map_err(|e| {
                error!(
                    err = ?e,
                    "Failed to begin init_credential_update",
                );
                e
            })
            .map(|(tok, sta)| {
                (
                    CUSessionToken {
                        token: tok.token_enc.to_string(),
                    },
                    sta.into(),
                )
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid),
    )]
    pub async fn handle_idmcredentialupdateintent(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        ttl: Option<Duration>,
        eventid: Uuid,
    ) -> Result<CUIntentToken, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        idms_prox_write
            .init_credential_update_intent(
                &InitCredentialUpdateIntentEvent::new(ident, target_uuid, ttl),
                ct,
            )
            .and_then(|tok| idms_prox_write.commit().map(|_| tok))
            .map_err(|e| {
                error!(
                    err = ?e,
                    "Failed to begin init_credential_update_intent",
                );
                e
            })
            .map(|tok| CUIntentToken {
                token: tok.intent_id,
                expiry_time: tok.expiry_time,
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialexchangeintent(
        &self,
        intent_id: String,
        eventid: Uuid,
    ) -> Result<(CUSessionToken, CUStatus), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let intent_token = CredentialUpdateIntentTokenExchange { intent_id };
        // TODO: this is throwing a 500 error when a session is already in use, that seems bad?
        idms_prox_write
            .exchange_intent_credential_update(intent_token, ct)
            .and_then(|tok| idms_prox_write.commit().map(|_| tok))
            .map_err(|e| {
                error!(
                    err = ?e,
                    "Failed to begin exchange_intent_credential_update",
                );
                e
            })
            .map(|(tok, sta)| {
                (
                    CUSessionToken {
                        token: tok.token_enc.to_string(),
                    },
                    sta.into(),
                )
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialupdatecommit(
        &self,
        session_token: CUSessionToken,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let session_token = JweCompact::from_str(session_token.token.as_str())
            .map(|token_enc| CredentialUpdateSessionToken { token_enc })
            .map_err(|err| {
                error!(?err, "malformed token");
                OperationError::InvalidRequestState
            })?;

        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        idms_prox_write
            .commit_credential_update(&session_token, ct)
            .and_then(|tok| idms_prox_write.commit().map(|_| tok))
            .map_err(|e| {
                error!(
                    err = ?e,
                    "Failed to begin commit_credential_update",
                );
                e
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialupdatecancel(
        &self,
        session_token: CUSessionToken,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let session_token = JweCompact::from_str(session_token.token.as_str())
            .map(|token_enc| CredentialUpdateSessionToken { token_enc })
            .map_err(|err| {
                error!(?err, "malformed token");
                OperationError::InvalidRequestState
            })?;

        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        idms_prox_write
            .cancel_credential_update(&session_token, ct)
            .and_then(|tok| idms_prox_write.commit().map(|_| tok))
            .map_err(|e| {
                error!(
                    err = ?e,
                    "Failed to begin commit_credential_cancel",
                );
                e
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_service_account_into_person(
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
                error!(err = ?e, "Invalid identity");
                e
            })?;
        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        idms_prox_write
            .service_account_into_person(&ident, target_uuid)
            .and_then(|_| idms_prox_write.commit())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_regenerateradius(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<String, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let rrse = RegenerateRadiusSecretEvent::from_parts(
            // &idms_prox_write.qs_write,
            ident,
            target_uuid,
        )
        .map_err(|e| {
            error!(
                err = ?e,
                "Failed to begin idm_account_regenerate_radius",
            );
            e
        })?;

        idms_prox_write
            .regenerate_radius_secret(&rrse)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_purgeattribute(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        attr: String,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;
        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let target_attr = Attribute::from(attr.as_str());
        let mdf = match ModifyEvent::from_target_uuid_attr_purge(
            ident,
            target_uuid,
            target_attr,
            filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify during purge attribute");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_removeattributevalues(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        attr: String,
        values: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;
        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
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
            &mut idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        name = "append_attribute",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_appendattribute(
        &self,
        client_auth_info: ClientAuthInfo,
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
        self.modify_from_parts(client_auth_info, &uuid_or_name, &proto_ml, filter)
            .await
    }

    #[instrument(
        level = "info",
        name = "set_attribute",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_setattribute(
        &self,
        client_auth_info: ClientAuthInfo,
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
        self.modify_from_parts(client_auth_info, &uuid_or_name, &proto_ml, filter)
            .await
    }

    #[instrument(
        level = "info",
        name = "ssh_key_create",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_sshkeycreate(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        tag: &str,
        key: &str,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let v_sk = Value::new_sshkey_str(tag, key)?;

        // Because this is from internal, we can generate a real modlist, rather
        // than relying on the proto ones.
        let ml = ModifyList::new_append(Attribute::SshPublicKey, v_sk);

        self.modify_from_internal_parts(client_auth_info, &uuid_or_name, &ml, filter)
            .await
    }

    #[instrument(
        level = "info",
        name = "idm_account_unix_extend",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmaccountunixextend(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        ux: AccountUnixExtend,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let AccountUnixExtend { gidnumber, shell } = ux;
        // The filter_map here means we only create the mods if the gidnumber or shell are set
        // in the actual request.
        let mods: Vec<_> = iter::once(Some(Modify::Present(
            Attribute::Class,
            EntryClass::PosixAccount.into(),
        )))
        .chain(iter::once(
            gidnumber
                .as_ref()
                .map(|_| Modify::Purged(Attribute::GidNumber)),
        ))
        .chain(iter::once(gidnumber.map(|n| {
            Modify::Present(Attribute::GidNumber, Value::new_uint32(n))
        })))
        .chain(iter::once(
            shell
                .as_ref()
                .map(|_| Modify::Purged(Attribute::LoginShell)),
        ))
        .chain(iter::once(shell.map(|s| {
            Modify::Present(Attribute::LoginShell, Value::new_iutf8(s.as_str()))
        })))
        .flatten()
        .collect();

        let ml = ModifyList::new_list(mods);

        let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));

        self.modify_from_internal_parts(client_auth_info, &uuid_or_name, &ml, filter)
            .await
    }

    #[instrument(
        level = "info",
        name = "idm_group_unix_extend",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmgroupunixextend(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        gx: GroupUnixExtend,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // The if let Some here means we only create the mods if the gidnumber is set
        // in the actual request.

        let gidnumber_mods = if let Some(gid) = gx.gidnumber {
            [
                Some(Modify::Purged(Attribute::GidNumber)),
                Some(Modify::Present(
                    Attribute::GidNumber,
                    Value::new_uint32(gid),
                )),
            ]
        } else {
            [None, None]
        };
        let mods: Vec<_> = iter::once(Some(Modify::Present(
            Attribute::Class,
            EntryClass::PosixGroup.into(),
        )))
        .chain(gidnumber_mods)
        .flatten()
        .collect();

        let ml = ModifyList::new_list(mods);

        let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));

        self.modify_from_internal_parts(client_auth_info, &uuid_or_name, &ml, filter)
            .await
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmaccountunixsetcred(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        cred: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = Uuid::parse_str(uuid_or_name.as_str()).or_else(|_| {
            idms_prox_write
                .qs_write
                .name_to_uuid(uuid_or_name.as_str())
                .inspect_err(|err| {
                    info!(?err, "Error resolving as gidnumber continuing ...");
                })
        })?;

        let upce = UnixPasswordChangeEvent::from_parts(
            // &idms_prox_write.qs_write,
            ident,
            target_uuid,
            cred,
        )
        .map_err(|e| {
            error!(err = ?e, "Failed to begin UnixPasswordChangeEvent");
            e
        })?;
        idms_prox_write
            .set_unix_account_password(&upce)
            .and_then(|_| idms_prox_write.commit())
            .map(|_| ())
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn handle_image_update(
        &self,
        client_auth_info: ClientAuthInfo,
        request_filter: Filter<FilterInvalid>,
        image: Option<ImageValue>,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .inspect_err(|err| {
                error!(?err, "Invalid identity in handle_image_update");
            })?;

        let modlist = if let Some(image) = image {
            ModifyList::new_purge_and_set(Attribute::Image, Value::Image(image))
        } else {
            ModifyList::new_purge(Attribute::Image)
        };

        let mdf = ModifyEvent::from_internal_parts(
            ident,
            &modlist,
            &request_filter,
            &idms_prox_write.qs_write,
        )
        .inspect_err(|err| {
            error!(?err, "Failed to begin modify during handle_image_update");
        })?;

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_scopemap_update(
        &self,
        client_auth_info: ClientAuthInfo,
        group: String,
        scopes: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // Because this is from internal, we can generate a real modlist, rather
        // than relying on the proto ones.
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let group_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(group.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving group name to target");
                e
            })?;

        let ml = ModifyList::new_append(
            Attribute::OAuth2RsScopeMap,
            Value::new_oauthscopemap(group_uuid, scopes.into_iter().collect()).ok_or_else(
                || OperationError::InvalidAttribute("Invalid Oauth Scope Map syntax".to_string()),
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
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_scopemap_delete(
        &self,
        client_auth_info: ClientAuthInfo,
        group: String,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let group_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(group.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving group name to target");
                e
            })?;

        let ml =
            ModifyList::new_remove(Attribute::OAuth2RsScopeMap, PartialValue::Refer(group_uuid));

        let mdf = match ModifyEvent::from_internal_parts(
            ident,
            &ml,
            &filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_claimmap_update(
        &self,
        client_auth_info: ClientAuthInfo,
        claim_name: String,
        group: String,
        claims: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // Because this is from internal, we can generate a real modlist, rather
        // than relying on the proto ones.
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let group_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(group.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving group name to target");
                e
            })?;

        let ml = ModifyList::new_append(
            Attribute::OAuth2RsClaimMap,
            Value::new_oauthclaimmap(claim_name, group_uuid, claims.into_iter().collect())
                .ok_or_else(|| {
                    OperationError::InvalidAttribute("Invalid Oauth Claim Map syntax".to_string())
                })?,
        );

        let mdf = match ModifyEvent::from_internal_parts(
            ident,
            &ml,
            &filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_claimmap_join_update(
        &self,
        client_auth_info: ClientAuthInfo,
        claim_name: String,
        join: ProtoOauth2ClaimMapJoin,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // Because this is from internal, we can generate a real modlist, rather
        // than relying on the proto ones.
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let join = match join {
            ProtoOauth2ClaimMapJoin::Csv => OauthClaimMapJoin::CommaSeparatedValue,
            ProtoOauth2ClaimMapJoin::Ssv => OauthClaimMapJoin::SpaceSeparatedValue,
            ProtoOauth2ClaimMapJoin::Array => OauthClaimMapJoin::JsonArray,
        };

        let ml = ModifyList::new_append(
            Attribute::OAuth2RsClaimMap,
            Value::OauthClaimMap(claim_name, join),
        );

        let mdf = match ModifyEvent::from_internal_parts(
            ident,
            &ml,
            &filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_claimmap_delete(
        &self,
        client_auth_info: ClientAuthInfo,
        claim_name: String,
        group: String,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let group_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(group.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving group name to target");
                e
            })?;

        let ml = ModifyList::new_remove(
            Attribute::OAuth2RsClaimMap,
            PartialValue::OauthClaim(claim_name, group_uuid),
        );

        let mdf = match ModifyEvent::from_internal_parts(
            ident,
            &ml,
            &filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_sup_scopemap_update(
        &self,
        client_auth_info: ClientAuthInfo,
        group: String,
        scopes: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // Because this is from internal, we can generate a real modlist, rather
        // than relying on the proto ones.
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let group_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(group.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving group name to target");
                e
            })?;

        let ml = ModifyList::new_append(
            Attribute::OAuth2RsSupScopeMap,
            Value::new_oauthscopemap(group_uuid, scopes.into_iter().collect()).ok_or_else(
                || OperationError::InvalidAttribute("Invalid Oauth Scope Map syntax".to_string()),
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
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_sup_scopemap_delete(
        &self,
        client_auth_info: ClientAuthInfo,
        group: String,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let group_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(group.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving group name to target");
                e
            })?;

        let ml = ModifyList::new_remove(
            Attribute::OAuth2RsSupScopeMap,
            PartialValue::Refer(group_uuid),
        );

        let mdf = match ModifyEvent::from_internal_parts(
            ident,
            &ml,
            &filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_authorise_permit(
        &self,
        client_auth_info: ClientAuthInfo,
        consent_req: String,
        eventid: Uuid,
    ) -> Result<AuthorisePermitSuccess, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .inspect_err(|err| {
                error!(?err, "Invalid identity");
            })?;

        idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_req, ct)
            .and_then(|r| idms_prox_write.commit().map(|()| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_token_exchange(
        &self,
        client_auth_info: ClientAuthInfo,
        token_req: AccessTokenRequest,
        eventid: Uuid,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self
            .idms
            .proxy_write(ct)
            .await
            .map_err(Oauth2Error::ServerError)?;
        // Now we can send to the idm server for authorisation checking.
        let resp = idms_prox_write.check_oauth2_token_exchange(&client_auth_info, &token_req, ct);

        match &resp {
            Err(Oauth2Error::InvalidGrant) | Ok(_) => {
                idms_prox_write.commit().map_err(Oauth2Error::ServerError)?;
            }
            _ => {}
        };

        resp
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_token_revoke(
        &self,
        client_auth_info: ClientAuthInfo,
        intr_req: TokenRevokeRequest,
        eventid: Uuid,
    ) -> Result<(), Oauth2Error> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self
            .idms
            .proxy_write(ct)
            .await
            .map_err(Oauth2Error::ServerError)?;
        idms_prox_write
            .oauth2_token_revoke(&client_auth_info, &intr_req, ct)
            .and_then(|()| idms_prox_write.commit().map_err(Oauth2Error::ServerError))
    }

    #[cfg(feature = "dev-oauth2-device-flow")]
    pub async fn handle_oauth2_device_flow_start(
        &self,
        client_auth_info: ClientAuthInfo,
        client_id: &str,
        scope: &Option<BTreeSet<String>>,
        eventid: Uuid,
    ) -> Result<kanidm_proto::oauth2::DeviceAuthorizationResponse, Oauth2Error> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self
            .idms
            .proxy_write(ct)
            .await
            .map_err(Oauth2Error::ServerError)?;
        idms_prox_write
            .handle_oauth2_start_device_flow(client_auth_info, client_id, scope, eventid)
            .and_then(|res| {
                idms_prox_write.commit().map_err(Oauth2Error::ServerError)?;
                Ok(res)
            })
    }
}
