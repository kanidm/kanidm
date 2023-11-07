use axum::{middleware::from_fn, response::Redirect, routing::get, Router};
use kanidm_proto::{scim_v1, v1};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi, ToSchema
};
use utoipa_swagger_ui::SwaggerUi;

use super::{errors::WebError, ServerState};

pub(crate) mod path_schema;
pub(crate) mod response_schema;
#[cfg(test)]
pub(crate) mod tests;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "token_jwt",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            )
        }
    }
}

// docs for the derive macro are here: <https://docs.rs/utoipa-gen/3.5.0/utoipa_gen/derive.OpenApi.html#info-attribute-syntax>
#[derive(OpenApi)]
#[openapi(
    paths(
        super::generic::status,
        super::generic::robots_txt,

        super::oauth2::oauth2_image_get,

        super::v1::raw_create,
        super::v1::raw_delete,
        super::v1::raw_modify,
        super::v1::raw_search,

        super::v1_oauth2::oauth2_id_image_delete,
        super::v1_oauth2::oauth2_id_image_post,
        super::v1_oauth2::oauth2_get,
        super::v1_oauth2::oauth2_basic_post,
        super::v1_oauth2::oauth2_public_post,
        super::v1_oauth2::oauth2_id_get,
        super::v1_oauth2::oauth2_id_patch,
        super::v1_oauth2::oauth2_id_delete,
        super::v1_oauth2::oauth2_id_image_post,
        super::v1_oauth2::oauth2_id_image_delete,
        super::v1_oauth2::oauth2_id_get_basic_secret,
        super::v1_oauth2::oauth2_id_scopemap_post,
        super::v1_oauth2::oauth2_id_scopemap_delete,
        super::v1_oauth2::oauth2_id_sup_scopemap_post,
        super::v1_oauth2::oauth2_id_sup_scopemap_delete,
        super::v1_scim::scim_sync_post,
        super::v1_scim::scim_sync_get,

        super::v1::schema_get,
        super::v1::whoami,
        super::v1::whoami_uat,
        super::v1::applinks_get,
        super::v1::schema_attributetype_get,
        super::v1::schema_attributetype_get_id,
        super::v1::schema_classtype_get,
        super::v1::schema_classtype_get_id,
        super::v1::person_get,
        super::v1::person_post,
        super::v1::service_account_credential_generate,
        super::v1::service_account_api_token_delete,
        super::v1::service_account_api_token_get,
        super::v1::service_account_api_token_post,
        super::v1::person_id_get,
        super::v1::person_id_patch,
        super::v1::person_id_delete,
        super::v1::person_id_get_attr,
        super::v1::person_id_put_attr,
        super::v1::person_id_post_attr,
        super::v1::person_id_delete_attr,
        super::v1::person_get_id_credential_status,
        super::v1::person_id_credential_update_get,
        super::v1::person_id_credential_update_intent_get,
        super::v1::person_id_credential_update_intent_ttl_get,

        super::v1::service_account_id_ssh_pubkeys_get,
        super::v1::service_account_id_ssh_pubkeys_post,

        super::v1::person_id_ssh_pubkeys_get,
        super::v1::person_id_ssh_pubkeys_post,
        super::v1::person_id_ssh_pubkeys_tag_get,
        super::v1::person_id_ssh_pubkeys_tag_delete,

        super::v1::person_id_radius_get,
        super::v1::person_id_radius_post,
        super::v1::person_id_radius_delete,
        super::v1::person_id_radius_token_get,

        super::v1::account_id_ssh_pubkeys_get,
        super::v1::account_id_radius_token_post,
        super::v1::service_account_id_unix_post,
        super::v1::person_id_unix_credential_put,
        super::v1::person_id_unix_credential_delete,
        super::v1::person_identify_user_post,
        super::v1::service_account_get,
        super::v1::service_account_post,
        super::v1::service_account_get,
        super::v1::service_account_post,
        super::v1::service_account_id_get,
        super::v1::service_account_id_delete,
        super::v1::service_account_id_patch,
        super::v1::service_account_id_get_attr,
        super::v1::service_account_id_put_attr,
        super::v1::service_account_id_post_attr,
        super::v1::service_account_id_delete_attr,
        super::v1::service_account_into_person,
        super::v1::service_account_api_token_post,
        super::v1::service_account_api_token_get,
        super::v1::service_account_api_token_delete,
        super::v1::service_account_credential_generate,
        super::v1::service_account_id_credential_status_get,
        super::v1::service_account_id_ssh_pubkeys_tag_get,
        super::v1::service_account_id_ssh_pubkeys_tag_delete,
        super::v1::account_id_unix_post,
        super::v1::account_id_unix_auth_post,
        super::v1::account_id_unix_token,
        super::v1::account_id_unix_token,
        super::v1::account_id_radius_token_post,
        super::v1::account_id_radius_token_get,
        super::v1::account_id_ssh_pubkeys_get,
        super::v1::account_id_ssh_pubkeys_tag_get,
        super::v1::account_id_user_auth_token_get,
        super::v1::account_user_auth_token_delete,
        super::v1::credential_update_exchange_intent,
        super::v1::credential_update_status,
        super::v1::credential_update_update,
        super::v1::credential_update_commit,
        super::v1::credential_update_cancel,
        super::v1::domain_get,
        super::v1::domain_attr_get,
        super::v1::domain_attr_put,
        super::v1::domain_attr_delete,
        super::v1::group_id_unix_token_get,
        super::v1::group_id_unix_post,
        super::v1::group_get,
        super::v1::group_post,
        super::v1::group_id_get,
        super::v1::group_id_delete,
        super::v1::group_id_attr_delete,
        super::v1::group_id_attr_get,
        super::v1::group_id_attr_put,
        super::v1::group_id_attr_post,
        super::v1::system_get,
        super::v1::system_attr_get,
        super::v1::system_attr_post,
        super::v1::system_attr_put,
        super::v1::system_attr_delete,
        super::v1::recycle_bin_get,
        super::v1::recycle_bin_id_get,
        super::v1::recycle_bin_revive_id_post,
        super::v1::auth,
        super::v1::auth_valid,
        super::v1::logout,
        super::v1::reauth,
        super::v1_scim::sync_account_get,
        super::v1_scim::sync_account_post,
        super::v1_scim::sync_account_id_get,
        super::v1_scim::sync_account_id_patch,
        super::v1_scim::sync_account_id_attr_get,
        super::v1_scim::sync_account_id_attr_put,
        super::v1_scim::sync_account_id_finalise_get,
        super::v1_scim::sync_account_id_terminate_get,
        super::v1_scim::sync_account_token_post,
        super::v1_scim::sync_account_token_delete,
        super::v1::debug_ipinfo,

    ),
    components(
        schemas(
            scim_v1::ScimSyncState,
            scim_v1::ScimSyncRequest,
            scim_v1::ScimSyncRetentionMode,
            // TODO: can't add Entry/ProtoEntry to schema as this was only recently supported utoipa v3.5.0 doesn't support it - ref <https://github.com/juhaku/utoipa/pull/756/files>
            // v1::Entry,
            v1::AccountUnixExtend,
            v1::ApiToken,
            v1::ApiTokenGenerate,
            v1::AuthRequest,
            v1::AuthResponse,
            v1::AuthState,
            v1::BackupCodesView,
            v1::Claim,
            v1::CreateRequest,
            v1::CredentialDetail,
            v1::CredentialStatus,
            v1::CUIntentToken,
            v1::CUSessionToken,
            v1::CUStatus,
            v1::DeleteRequest,
            v1::Group,
            v1::GroupUnixExtend,
            v1::ModifyList,
            v1::ModifyRequest,
            v1::PasskeyDetail,
            v1::RadiusAuthToken,
            v1::SearchRequest,
            v1::SearchResponse,
            v1::SingleStringRequest,
            v1::TotpSecret,
            v1::TotpAlgo,
            v1::UatStatus,
            v1::UnixGroupToken,
            v1::UnixUserToken,
            v1::UserAuthToken,
            v1::WhoamiResponse,
            v1::ApiTokenPurpose,
            v1::AuthStep,
            v1::AuthIssueSession,
            v1::AuthMech,
            v1::AuthCredential,
            v1::AuthAllowed,
            v1::CUExtPortal,
            v1::CURegState,
            v1::CredentialDetailType,
            v1::Entry,
            v1::Filter,
            v1::Modify,
            v1::UatStatusState,
            v1::UatPurposeStatus,
            v1::UatPurpose,
            v1::OperationError,
            v1::SchemaError,
            v1::PluginError,
            v1::PasswordFeedback,

            kanidm_proto::internal::IdentifyUserRequest,
            // terrible workaround for other things
            response_schema::CreationChallengeResponse,
            // terrible workaround for other things
            response_schema::ProtoEntry,
            // terrible workaround for other things
            response_schema::PublicKeyCredential,
            // terrible workaround for other things
            response_schema::RequestChallengeResponse,
            // terrible workaround for other things
            response_schema::Base64UrlSafeData,
            // terrible workaround for other things
            response_schema::BTreeSet,
            // terrible workaround for other things
            response_schema::Result,
            // terrible workaround for other things
            response_schema::ScimEntry,


            WebError,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "kanidm", description = "Kanidm API")
    ),
    info(
        title = "Kanidm",
        description = "API for interacting with the Kanidm system. This is a work in progress",
        contact( // <https://docs.rs/utoipa-gen/3.5.0/utoipa_gen/derive.OpenApi.html#info-attribute-syntax>
            name="Kanidm",
            url="https://github.com/kanidm/kanidm",
        )
    )
)]
pub(crate) struct ApiDoc;

pub(crate) fn router() -> Router<ServerState> {
    Router::new()
        .route("/docs", get(Redirect::temporary("/docs/swagger-ui")))
        .route("/docs/", get(Redirect::temporary("/docs/swagger-ui")))
        .merge(SwaggerUi::new("/docs/swagger-ui").url("/docs/v1/openapi.json", ApiDoc::openapi()))
        // overlay the version middleware because the client is sad without it
        .layer(from_fn(super::middleware::version_middleware))
}
