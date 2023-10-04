use utoipa::{
    openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme},
    Modify, OpenApi,
};
use utoipa_swagger_ui::SwaggerUi;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            // components.add_security_scheme(
            //     "bearer",
            //     SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("todo_apikey"))),
            // );
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
        super::status,
        super::oauth2::oauth2_image_get,
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
        // super::v1::raw_create,
        // super::v1::raw_modify,
        // super::v1::raw_delete,
        // super::v1::raw_search,
        // super::v1::schema_get,
    ),
    components(
        // TODO: can't add ProtoEntry to schema as this was only recently supported utoipa v3.5.0 doesn't support it - ref <https://github.com/juhaku/utoipa/pull/756/files>
        // schemas(ProtoEntry)

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

pub(crate) fn router() -> SwaggerUi {
    SwaggerUi::new("/docs/swagger-ui").url(
        "/docs/v1/openapi.json",
        <ApiDoc as utoipa::OpenApi>::openapi(),
    )
}
