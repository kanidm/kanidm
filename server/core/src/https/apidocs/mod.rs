use axum::{middleware::from_fn, response::Redirect, routing::get, Router};
use kanidm_proto::{attribute, internal, scim_v1, v1};
use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

use super::{errors::WebError, ServerState};

// pub(crate) mod path_schema;

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
    servers(
        (url="https://{host}:{port}",
            variables(
                ("host" = (default="localhost", description="Server's hostname")),
                ("port" = (default="8443", description="Server HTTPS port")),
            )
        )
    ),
    external_docs(url = "https://kanidm.com/docs", description = "Kanidm documentation page"),

    paths(
        super::generic::status,
        super::generic::robots_txt,

        super::oauth2::oauth2_image_get,

        super::v1::raw_create,
        super::v1::raw_delete,
        super::v1::raw_modify,
        super::v1::raw_search,

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
        super::v1_oauth2::oauth2_id_claimmap_join_post,
        super::v1_oauth2::oauth2_id_claimmap_post,
        super::v1_oauth2::oauth2_id_claimmap_delete,

        super::v1_scim::scim_sync_post,
        super::v1_scim::scim_sync_get,
        super::v1_scim::scim_entry_id_get,
        super::v1_scim::scim_person_id_get,
        super::v1_scim::scim_person_id_application_create_password,
        super::v1_scim::scim_person_id_application_delete_password,
        super::v1_scim::scim_person_id_message_send_test_get,
        super::v1_scim::scim_application_get,
        super::v1_scim::scim_application_post,
        super::v1_scim::scim_application_id_get,
        super::v1_scim::scim_application_id_delete,
        super::v1_scim::scim_schema_attribute_get,
        super::v1_scim::scim_schema_class_get,
        super::v1_scim::scim_message_get,
        super::v1_scim::scim_message_id_get,
        super::v1_scim::scim_message_ready_get,
        super::v1_scim::scim_message_id_sent_post,

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
        super::v1::person_search_id,
        super::v1::person_id_get,
        super::v1::person_id_patch,
        super::v1::person_id_delete,
        super::v1::person_id_get_attr,
        super::v1::person_id_put_attr,
        super::v1::person_id_post_attr,
        super::v1::person_id_delete_attr,
        super::v1::person_get_id_certificate,
        super::v1::person_post_id_certificate,
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
        // super::v1::account_id_radius_token_post,
        super::v1::person_id_unix_post,
        super::v1::person_id_unix_credential_put,
        super::v1::person_id_unix_credential_delete,
        super::v1::person_identify_user_post,
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
        // super::v1::service_account_api_token_post,
        // super::v1::service_account_api_token_get,
        // super::v1::service_account_api_token_delete,
        // super::v1::service_account_credential_generate,
        super::v1::service_account_id_credential_status_get,
        super::v1::service_account_id_ssh_pubkeys_tag_get,
        super::v1::service_account_id_ssh_pubkeys_tag_delete,
        super::v1::service_account_id_unix_post,
        super::v1::account_id_unix_auth_post,
        // super::v1::account_id_unix_token,
        super::v1::account_id_unix_token,
        super::v1::account_id_radius_token_post,
        super::v1::account_id_radius_token_get,
        // super::v1::account_id_ssh_pubkeys_get,
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
        super::v1_domain::image_post,
        super::v1_domain::image_delete,

        super::v1::group_id_unix_token_get,
        super::v1::group_id_unix_post,
        super::v1::group_get,
        super::v1::group_post,
        super::v1::group_search_id,
        super::v1::group_id_get,
        super::v1::group_id_patch,
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
        super::v1::public_jwk_key_id_get,

    ),
    components(
        schemas(
            attribute::Attribute,

            scim_v1::ScimSyncState,
            scim_v1::ScimSyncRequest,
            scim_v1::ScimSyncRetentionMode,
            scim_v1::ScimEntry,
            scim_v1::ScimValue,
            scim_v1::ScimMeta,
            scim_v1::ScimAttr,
            scim_v1::ScimApplicationPasswordCreate,
            scim_v1::ScimApplicationPassword,
            scim_v1::client::ScimEntryPostGeneric,

            internal::ApiToken,
            internal::ApiTokenPurpose,
            internal::BackupCodesView,
            internal::ConsistencyError,
            internal::CreateRequest,
            internal::CredentialDetail,
            internal::CredentialDetailType,
            internal::CredentialStatus,
            internal::CUExtPortal,
            internal::CUIntentToken,
            internal::CURegState,
            internal::CUSessionToken,
            internal::CUStatus,
            internal::DeleteRequest,
            internal::Filter,
            internal::Group,
            internal::Modify,
            internal::ModifyList,
            internal::ModifyRequest,
            internal::Oauth2ClaimMapJoin,
            internal::OperationError,
            internal::PasskeyDetail,
            internal::PasswordFeedback,
            internal::PluginError,
            internal::RadiusAuthToken,
            internal::SchemaError,
            internal::SearchRequest,
            internal::SearchResponse,
            internal::TotpAlgo,
            internal::TotpSecret,
            internal::UatPurpose,
            internal::UserAuthToken,
            v1::AccountUnixExtend,
            v1::ApiTokenGenerate,
            v1::AuthAllowed,
            v1::AuthCredential,
            v1::AuthIssueSession,
            v1::AuthMech,
            v1::AuthRequest,
            v1::AuthResponse,
            v1::AuthState,
            v1::AuthStep,
            v1::Entry,
            v1::GroupUnixExtend,
            v1::PublicKeyKindSchema,
            v1::SingleStringRequest,
            v1::SshPublicKeySchema,
            v1::KeyTypeKindSchema,
            v1::KeyTypeSchema,
            internal::UiHint,
            v1::UatPurposeStatus,
            v1::UatStatus,
            v1::UatStatusState,
            v1::UnixGroupToken,
            v1::UnixUserToken,
            v1::WhoamiResponse,
            internal::CUCredState,
            internal::CURegWarning,
            internal::IdentifyUserResponse,
            internal::AppLink,

            internal::IdentifyUserRequest,
            // terrible workaround for other things
            response_schema::CreationChallengeResponse,

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
            //  workaround for the fact that BTreeSet can't be represented in JSON
            response_schema::ProtoEntry,
            // terrible workaround for other things
            response_schema::Jwk,
            response_schema::ScimComplexAttr,
            WebError,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "kanidm", description = "Kanidm API")
    ),
    info(
        title = "Kanidm",
        description = "API for interacting with the Kanidm system. This is a work in progress.",
        contact( // <https://docs.rs/utoipa-gen/3.5.0/utoipa_gen/derive.OpenApi.html#info-attribute-syntax>
            name="Kanidm Github",
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
