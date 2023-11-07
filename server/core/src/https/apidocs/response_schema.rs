//! This file contains the default response schemas for the API.
//!
//! These are used to generate the OpenAPI schema definitions.
//!
use kanidm_proto::constants::APPLICATION_JSON;
use std::collections::BTreeMap;
use utoipa::{
    openapi::{Content, RefOr, Response, ResponseBuilder, ResponsesBuilder},
    IntoResponses, ToSchema,
};

#[allow(dead_code)] // because this is used for the OpenAPI schema gen
/// An empty response with `application/json` content type - use [ApiResponseWithout200] if you want to do everything but a 200
pub(crate) enum DefaultApiResponse {
    Ok,
    InvalidRequest,
    NeedsAuthorization,
    NotAuthorized,
}

impl IntoResponses for DefaultApiResponse {
    fn responses() -> BTreeMap<String, RefOr<Response>> {
        ResponsesBuilder::new()
            .response(
                "200",
                ResponseBuilder::new()
                    .content(APPLICATION_JSON, Content::default())
                    .description("Ok"),
            )
            .response("400", ResponseBuilder::new().description("Invalid Request"))
            .response(
                "401",
                ResponseBuilder::new().description("Authorization required"),
            )
            .response("403", ResponseBuilder::new().description("Not Authorized"))
            .build()
            .into()
    }
}

#[allow(dead_code)] // because this is used for the OpenAPI schema gen
/// A response set without the 200 status so the "defaults" can be handled.
pub(crate) enum ApiResponseWithout200 {
    InvalidRequest,
    NeedsAuthorization,
    NotAuthorized,
}

impl IntoResponses for ApiResponseWithout200 {
    fn responses() -> BTreeMap<String, RefOr<Response>> {
        ResponsesBuilder::new()
            .response("400", ResponseBuilder::new().description("Invalid Request"))
            .response(
                "401",
                ResponseBuilder::new().description("Authorization required"),
            )
            .response("403", ResponseBuilder::new().description("Not Authorized"))
            .build()
            .into()
    }
}

/// Placeholder until we can handle a BTree in utipa
#[derive(Debug, Clone, ToSchema)]
pub(crate) struct ProtoEntry {}

#[derive(Debug, Clone, ToSchema)]
// TODO: this should be `webauthn_rs_proto::auth::PublicKeyCredential``, but ... I don't know how to make it possible in utoipa
pub(crate) struct PublicKeyCredential {}

#[derive(Debug, Clone, ToSchema)]
// TODO: this should be `webauthn_rs_proto::auth::RequestChallengeResponse``, but ... I don't know how to make it possible in utoipa
pub(crate) struct RequestChallengeResponse {}

#[derive(Debug, Clone, ToSchema)]
// TODO: this should be `webauthn_rs_proto::auth::CreationChallengeResponse``, but ... I don't know how to make it possible in utoipa
pub(crate) struct CreationChallengeResponse {}

#[derive(Debug, Clone, ToSchema)]
// TODO: this should be `Base64UrlSafeData`, but ... I don't know how to make it possible in utoipa
pub(crate) struct Base64UrlSafeData {}

#[derive(Debug, Clone, ToSchema)]
// TODO: this should be handled elsewhere, but ... I don't know how to make it possible in utoipa
pub(crate) struct BTreeSet {}

#[derive(Debug, Clone, ToSchema)]
// TODO: this should be handled elsewhere, but ... I don't know how to make it possible in utoipa
pub(crate) struct Result {}

#[derive(Debug, Clone, ToSchema)]
// TODO: this should be handled elsewhere, but ... I don't know how to make it possible in utoipa
pub(crate) struct ScimEntry {}
