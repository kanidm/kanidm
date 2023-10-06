// TODO: this should/could be a macro, or we could stop using IntoResponse :D

use kanidm_proto::constants::APPLICATION_JSON;
use std::collections::BTreeMap;
use utoipa::{
    openapi::{Content, RefOr, Response, ResponseBuilder, ResponsesBuilder},
    IntoResponses,
};

#[allow(dead_code)] // because this is used for the OpenAPI schema gen
pub(crate) enum DefaultApiResponse {
    Ok,
    NotFound,
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
            .response("404", ResponseBuilder::new().description("Not Found"))
            .response("403", ResponseBuilder::new().description("Not Authorized"))
            .build()
            .into()
    }
}
