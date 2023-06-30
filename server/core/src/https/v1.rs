#[allow(unused_imports)]
// //! The V1 API things!
use std::str::FromStr;

use axum::body;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use axum_macros::debug_handler;
use axum_sessions::extractors::WritableSession;
use http::{HeaderMap, HeaderValue};
use hyper::Body;
use kanidm_proto::v1::{
    AccountUnixExtend, ApiTokenGenerate, AuthIssueSession, AuthRequest, AuthResponse,
    AuthState as ProtoAuthState, CUIntentToken, CURequest, CUSessionToken, CreateRequest,
    DeleteRequest, Entry as ProtoEntry, GroupUnixExtend, ModifyRequest, OperationError,
    SearchRequest, SearchResponse, SingleStringRequest, WhoamiResponse,
};
use kanidmd_lib::filter::{Filter, FilterInvalid};
use kanidmd_lib::idm::event::AuthResult;
use kanidmd_lib::idm::AuthState;
use kanidmd_lib::prelude::*;
use kanidmd_lib::status::StatusRequestEvent;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use super::ServerState;

pub fn new(state: ServerState) -> Router<ServerState> {
    Router::new()
        .route(
            "/",
            get(|| async { json!({"Hello" : "world"}).to_string() }),
        )
        .nest("/auth", auth(state.clone()))
        .with_state(state)
}

pub fn auth(state: ServerState) -> Router<ServerState> {
    Router::new()
        .route(
            "/",
            get(|| async { json!({"Hello" : "world"}).to_string() }),
        )
        .route(
            "/valid",
            get(|| async { json!({"Hello" : "world"}).to_string() }),
        )
        .with_state(state)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct SessionId {
    pub sessionid: Uuid,
}

pub fn to_axum_response<T: Serialize>(
    v: Result<T, OperationError>,
    hvalue: String,
) -> Response<Body> {
    match v {
        Ok(iv) => {
            let body = serde_json::to_string(&iv).unwrap();
            Response::builder()
                .header("X-KANIDM-OPID", HeaderValue::from_str(&hvalue).unwrap())
                .body(Body::from(body))
                .unwrap()
        }
        Err(e) => {
            (match &e {
                OperationError::NotAuthenticated | OperationError::SessionExpired => {
                    // https://datatracker.ietf.org/doc/html/rfc7235#section-4.1
                    Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .header("WWW-Authenticate", "Bearer")
                }
                OperationError::SystemProtectedObject | OperationError::AccessDenied => {
                    Response::builder().status(http::StatusCode::FORBIDDEN)
                }
                OperationError::NoMatchingEntries => {
                    Response::builder().status(http::StatusCode::NOT_FOUND)
                }
                OperationError::PasswordQuality(_)
                | OperationError::EmptyRequest
                | OperationError::SchemaViolation(_) => {
                    Response::builder().status(http::StatusCode::BAD_REQUEST)
                }
                _ => Response::builder().status(http::StatusCode::INTERNAL_SERVER_ERROR),
            })
            .header("X-KANIDM-OPID", HeaderValue::from_str(&hvalue).unwrap())
            .body(body::Body::empty())
            .unwrap()
        }
    }
}

#[debug_handler]
pub async fn create(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(msg): Json<CreateRequest>,
) -> Response<Body> {
    let uat = state.get_current_uat(headers);
    // parse the req to a CreateRequest
    // let msg: CreateRequest = req.body_json().await?;

    let (eventid, hvalue) = state.new_eventid();

    let res = state.qe_w_ref.handle_create(uat, msg, eventid).await;
    to_axum_response(res, hvalue)
}

pub async fn modify(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(msg): Json<ModifyRequest>,
) -> Response<Body> {
    let uat = state.get_current_uat(headers);
    let (eventid, hvalue) = state.new_eventid();
    let res = state.qe_w_ref.handle_modify(uat, msg, eventid).await;
    to_axum_response(res, hvalue)
}

pub async fn delete(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(msg): Json<DeleteRequest>,
) -> Response<Body> {
    let uat = state.get_current_uat(headers);
    let (eventid, hvalue) = state.new_eventid();
    let res = state.qe_w_ref.handle_delete(uat, msg, eventid).await;
    to_axum_response(res, hvalue)
}

pub async fn search(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(msg): Json<SearchRequest>,
) -> Response<Body> {
    let uat = state.get_current_uat(headers);
    let (eventid, hvalue) = state.new_eventid();
    let res = state.qe_r_ref.handle_search(uat, msg, eventid).await;
    to_axum_response(res, hvalue)
}

#[debug_handler]
pub async fn whoami(State(state): State<ServerState>, headers: HeaderMap) -> Response<Body> {
    let uat = state.get_current_uat(headers);
    let (eventid, hvalue) = state.new_eventid();
    // New event, feed current auth data from the token to it.
    let res = state.qe_r_ref.handle_whoami(uat, eventid).await;
    to_axum_response(res, hvalue)
}

pub async fn whoami_uat(State(state): State<ServerState>, headers: HeaderMap) -> impl IntoResponse {
    let uat = state.get_current_uat(headers);
    let (eventid, hvalue) = state.new_eventid();
    let res = state.qe_r_ref.handle_whoami_uat(uat, eventid).await;
    to_axum_response(res, hvalue)
}

// pub async fn logout(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Json(msg): Json<CreateRequest>,
//     mut msession: WritableSession,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let (eventid, hvalue) = state.new_eventid();

//     // Now lets nuke any cookies for the session. We do this before the handle_logout
//     // so that if any errors occur, the cookies are still removed.

//     msession.remove("auth-session-id");
//     msession.remove("bearer");

//     let res = state.qe_w_ref.handle_logout(uat, eventid).await;

//     to_axum_response(res, hvalue)
// }

// // =============== REST generics ========================

// pub async fn json_rest_event_get(
//     state: State<ServerState>,
//     filter: Filter<FilterInvalid>,
//     headers: HeaderMap,
//     attrs: Option<Vec<String>>,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_internalsearch(uat, filter, attrs, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn json_rest_event_get_id(
//     Path(id): Path<String>,
//     State(state): State<ServerState>,
//     filter: Filter<FilterInvalid>,
//     attrs: Option<Vec<String>>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);

//     let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_internalsearch(uat, filter, attrs, eventid)
//         .await
//         .map(|mut r| r.pop());
//     to_axum_response(res, hvalue)
// }

// pub async fn json_rest_event_delete_id(
//     Path(id): Path<String>,
//     State(state): State<ServerState>,
//     filter: Filter<FilterInvalid>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);

//     let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_w_ref
//         .handle_internaldelete(uat, filter, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn json_rest_event_get_attr(
//     Path(attr): Path<String>,
//     State(state): State<ServerState>,
//     id: &str,
//     filter: Filter<FilterInvalid>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let filter = Filter::join_parts_and(filter, filter_all!(f_id(id)));

//     let (eventid, hvalue) = state.new_eventid();

//     let attrs = Some(vec![attr.clone()]);

//     let res: Result<Option<_>, _> = state
//         .qe_r_ref
//         .handle_internalsearch(uat, filter, attrs, eventid)
//         .await
//         .map(|mut event_result| event_result.pop().and_then(|mut e| e.attrs.remove(&attr)));
//     to_axum_response(res, hvalue)
// }

// // pub async fn json_rest_event_get_id_attr(
// //     State(state): State<ServerState>,
// //     filter: Filter<FilterInvalid>,
// // ) -> impl IntoResponse {
// //     let id = req.get_url_param("id")?;
// //     json_rest_event_get_attr(state, id.as_str(), filter).await
// // }

// pub async fn json_rest_event_post(
//     state: ServerState,
//     classes: Vec<String>,
//     obj: &mut ProtoEntry,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     debug_assert!(!classes.is_empty());
//     let (eventid, hvalue) = state.new_eventid();
//     let uat = state.get_current_uat(headers);

//     obj.attrs.insert("class".to_string(), classes);
//     let msg = CreateRequest {
//         entries: vec![obj.to_owned()],
//     };

//     let res = state.qe_w_ref.handle_create(uat, msg, eventid).await;
//     to_axum_response(res, hvalue)
// }

// pub async fn json_rest_event_post_id_attr(
//     Path((id, attr)): Path<(String, String)>,

//     State(state): State<ServerState>,
//     filter: Filter<FilterInvalid>,
//     Json(values): Json<Vec<String>>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = id;

//     // let values: Vec<String> = req.body_json().await?;
//     let (eventid, hvalue) = state.new_eventid();
//     let res = state
//         .qe_w_ref
//         .handle_appendattribute(uat, uuid_or_name, attr, values, filter, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn json_rest_event_put_attr(
//     State(state): State<ServerState>,
//     Path((id, attr)): Path<(String, String)>,
//     uuid_or_name: String,
//     filter: Filter<FilterInvalid>,
//     Json(values): Json<Vec<String>>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = id;
//     // let values: Vec<String> = req.body_json().await?;

//     let (eventid, hvalue) = state.new_eventid();
//     let res = state
//         .qe_w_ref
//         .handle_setattribute(uat, uuid_or_name, attr, values, filter, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn json_rest_event_post_attr(
//     State(state): State<ServerState>,
//     Path((id, attr)): Path<(String, String)>,

//     filter: Filter<FilterInvalid>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let attr = req.get_url_param("attr")?;
//     let uuid_or_name = id;
//     let values: Vec<String> = req.body_json().await?;

//     let (eventid, hvalue) = state.new_eventid();
//     let res = state
//         .qe_w_ref
//         .handle_appendattribute(uat, uuid_or_name, attr, values, filter, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// // pub async fn json_rest_event_put_id_attr(
// //     State(state): State<ServerState>,
// //     filter: Filter<FilterInvalid>,
// // ) -> impl IntoResponse {
// //     let uuid_or_name = req.get_url_param("id")?;
// //     json_rest_event_put_attr(state, uuid_or_name, filter).await
// // }

// // pub async fn json_rest_event_delete_id_attr(
// //     State(state): State<ServerState>,
// //     filter: Filter<FilterInvalid>,
// //     attr: String,
// // ) -> impl IntoResponse {
// //     let uuid_or_name = req.get_url_param("id")?;
// //     json_rest_event_delete_attr(state, filter, uuid_or_name, attr).await
// // }

// pub async fn json_rest_event_delete_attr(
//     State(state): State<ServerState>,
//     filter: Filter<FilterInvalid>,
//     uuid_or_name: String,
//     headers: HeaderMap,
//     // Separate for account_delete_id_radius
//     attr: String,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let (eventid, hvalue) = state.new_eventid();

//     // TODO #211: Attempt to get an option Vec<String> here?
//     // It's probably better to focus on SCIM instead, it seems richer than this.
//     let body = req.take_body();
//     let values: Vec<String> = if body.is_empty().unwrap_or(true) {
//         vec![]
//     } else {
//         // Must now be a valid list.
//         body.into_json().await?
//     };

//     if values.is_empty() {
//         let res = state
//             .qe_w_ref
//             .handle_purgeattribute(uat, uuid_or_name, attr, filter, eventid)
//             .await;
//         to_axum_response(res, hvalue)
//     } else {
//         let res = state
//             .qe_w_ref
//             .handle_removeattributevalues(uat, uuid_or_name, attr, values, filter, eventid)
//             .await;
//         to_axum_response(res, hvalue)
//     }
// }

// // Okay, so a put normally needs
// //  * filter of what we are working on (id + class)
// //  * a Map<String, Vec<String>> that we turn into a modlist.
// //
// // OR
// //  * filter of what we are working on (id + class)
// //  * a Vec<String> that we are changing
// //  * the attr name  (as a param to this in path)
// //
// // json_rest_event_put_id(path, req, state

// pub async fn schema_get(State(state): State<ServerState>, headers: HeaderMap) -> impl IntoResponse {
//     // NOTE: This is filter_all, because from_internal_message will still do the alterations
//     // needed to make it safe. This is needed because there may be aci's that block access
//     // to the recycle/ts types in the filter, and we need the aci to only eval on this
//     // part of the filter!
//     let filter = filter_all!(f_or!([
//         f_eq("class", PartialValue::new_class("attributetype")),
//         f_eq("class", PartialValue::new_class("classtype"))
//     ]));
//     json_rest_event_get(state, filter, headers, None).await
// }

// pub async fn schema_attributetype_get(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("attributetype")));
//     json_rest_event_get(state, filter, headers, None).await
// }

// pub async fn schema_attributetype_get_id(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     // These can't use get_id because they attribute name and class name aren't ... well name.
//     let uat = state.get_current_uat(headers);
//     let id = req.get_url_param("id")?;

//     let filter = filter_all!(f_and!([
//         f_eq("class", PartialValue::new_class("attributetype")),
//         f_eq("attributename", PartialValue::new_iutf8(id.as_str()))
//     ]));

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_internalsearch(uat, filter, None, eventid)
//         .await
//         .map(|mut r| r.pop());
//     to_axum_response(res, hvalue)
// }

// pub async fn schema_classtype_get(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("classtype")));
//     json_rest_event_get(state, filter, headers, None).await
// }

// pub async fn schema_classtype_get_id(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     // These can't use get_id because they attribute name and class name aren't ... well name.
//     let uat = state.get_current_uat(headers);
//     let id = req.get_url_param("id")?;

//     let filter = filter_all!(f_and!([
//         f_eq("class", PartialValue::new_class("classtype")),
//         f_eq("classname", PartialValue::new_iutf8(id.as_str()))
//     ]));

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_internalsearch(uat, filter, None, eventid)
//         .await
//         .map(|mut r| r.pop());
//     to_axum_response(res, hvalue)
// }

// // == person ==

// pub async fn person_get(State(state): State<ServerState>, headers: HeaderMap) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
//     json_rest_event_get(state, filter, headers, None).await
// }

// // expects the following fields in the attrs field of the req: [name, displayname]
// pub async fn person_post(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let classes = vec![
//         "person".to_string(),
//         "account".to_string(),
//         "object".to_string(),
//     ];
//     json_rest_event_post(state, classes, headers).await
// }

// pub async fn person_id_get(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
//     json_rest_event_get_id(state, filter, None).await
// }

// pub async fn person_account_id_delete(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
//     json_rest_event_delete_id(state, filter).await
// }

// // == account ==

// pub async fn service_account_get(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("service_account")));
//     json_rest_event_get(state, filter, None).await
// }

// pub async fn service_account_post(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let classes = vec![
//         "service_account".to_string(),
//         "account".to_string(),
//         "object".to_string(),
//     ];
//     json_rest_event_post(state, classes, headers).await
// }

// pub async fn service_account_id_get(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("service_account")));
//     json_rest_event_get_id(state, filter, None).await
// }

// pub async fn service_account_id_delete(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("service_account")));
//     json_rest_event_delete_id(state, filter).await
// }

// pub async fn service_account_credential_generate(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_w_ref
//         .handle_service_account_credential_generate(uat, uuid_or_name, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// // Due to how the migrations work in 6 -> 7, we can accidentally
// // mark "accounts" as service accounts when they are persons. This
// // allows migrating them to the person type due to it's similarities.
// //
// // In the future this will be REMOVED!
// pub async fn service_account_into_person(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_w_ref
//         .handle_service_account_into_person(uat, uuid_or_name, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// // Api Token
// pub async fn service_account_api_token_get(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_service_account_api_token_get(uat, uuid_or_name, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn service_account_api_token_post(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Json(msg): Json<CreateRequest>,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;
//     let ApiTokenGenerate {
//         label,
//         expiry,
//         read_write,
//     } = req.body_json().await?;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_w_ref
//         .handle_service_account_api_token_generate(
//             uat,
//             uuid_or_name,
//             label,
//             expiry,
//             read_write,
//             eventid,
//         )
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn service_account_api_token_delete(
//     State(state): State<ServerState>,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;
//     let token_id = req.get_url_param_uuid("token_id")?;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_w_ref
//         .handle_service_account_api_token_destroy(uat, uuid_or_name, token_id, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// // Account stuff
// pub async fn account_id_get_attr(
//     State(state): State<ServerState>,
//     Path(id): Path<String>,
// ) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
//     json_rest_event_get_attr(state, id.as_str(), filter).await
// }

// pub async fn account_id_post_attr(
//     State(state): State<ServerState>,
//     Path(id): Path<String>,
// ) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
//     json_rest_event_post_id_attr(state, filter).await
// }

// pub async fn account_id_delete_attr(
//     State(state): State<ServerState>,
//     Path(id): Path<String>,
// ) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
//     let attr = req.get_url_param("attr")?;
//     json_rest_event_delete_id_attr(state, filter, attr).await
// }

// pub async fn account_id_put_attr(
//     State(state): State<ServerState>,
//     Path(id): Path<String>,
// ) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
//     json_rest_event_put_attr(id, filter).await
// }

// pub async fn account_id_patch(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Json(msg): Json<CreateRequest>,
// ) -> impl IntoResponse {
//     // Update a value / attrs
//     let uat = state.get_current_uat(headers);
//     let id = req.get_url_param("id")?;

//     let obj: ProtoEntry = req.body_json().await?;

//     let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
//     let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_w_ref
//         .handle_internalpatch(uat, filter, obj, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_get_id_credential_update(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Query(uuid_or_name): Query<String>,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);

//     let (eventid, hvalue) = req.new_eventid();

//     let res = req
//         .qe_w_ref
//         .handle_idmcredentialupdate(uat, uuid_or_name, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_get_id_credential_update_intent(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Query(uuid_or_name): Query<String>,
// ) -> impl IntoResponse {
//     let uat = req.get_current_uat(headers);
//     let ttl = req
//         .param("ttl")
//         .ok()
//         .and_then(|s| {
//             u64::from_str(s)
//                 .map_err(|_e| {
//                     error!("Invalid TTL integer, ignoring.");
//                 })
//                 .ok()
//         })
//         .map(Duration::from_secs);

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_w_ref
//         .handle_idmcredentialupdateintent(uat, uuid_or_name, ttl, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_get_id_user_auth_token(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_account_user_auth_token_get(uat, uuid_or_name, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_user_auth_token_delete(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;
//     let token_id = req.get_url_param_uuid("token_id")?;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_w_ref
//         .handle_account_user_auth_token_destroy(uat, uuid_or_name, token_id, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn credential_update_exchange_intent(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Json(msg): Json<CreateRequest>,
// ) -> impl IntoResponse {
//     let (eventid, hvalue) = state.new_eventid();
//     let intent_token: CUIntentToken = req.body_json().await?;

//     let res = state
//         .qe_w_ref
//         .handle_idmcredentialexchangeintent(intent_token, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn credential_update_status(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Json(msg): Json<CreateRequest>,
// ) -> impl IntoResponse {
//     let (eventid, hvalue) = state.new_eventid();
//     let session_token: CUSessionToken = req.body_json().await?;

//     let res = state
//         .qe_r_ref
//         .handle_idmcredentialupdatestatus(session_token, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn credential_update_update(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Json(msg): Json<CreateRequest>,
// ) -> impl IntoResponse {
//     let (eventid, hvalue) = state.new_eventid();
//     let (scr, session_token): (CURequest, CUSessionToken) = req.body_json().await?;

//     let res = state
//         .qe_r_ref
//         .handle_idmcredentialupdate(session_token, scr, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn credential_update_commit(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Json(msg): Json<CreateRequest>,
// ) -> impl IntoResponse {
//     let (eventid, hvalue) = state.new_eventid();
//     let session_token: CUSessionToken = req.body_json().await?;

//     let res = state
//         .qe_w_ref
//         .handle_idmcredentialupdatecommit(session_token, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn credential_update_cancel(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Json(msg): Json<CreateRequest>,
// ) -> impl IntoResponse {
//     let (eventid, hvalue) = state.new_eventid();
//     let session_token: CUSessionToken = req.body_json().await?;

//     let res = state
//         .qe_w_ref
//         .handle_idmcredentialupdatecancel(session_token, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_get_id_credential_status(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_idmcredentialstatus(uat, uuid_or_name, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// // Return a vec of str
// pub async fn account_get_id_ssh_pubkeys(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_internalsshkeyread(uat, uuid_or_name, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_post_id_ssh_pubkey(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Json(msg): Json<CreateRequest>,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;
//     let (tag, key): (String, String) = req.body_json().await?;
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));

//     let (eventid, hvalue) = state.new_eventid();
//     // Add a msg here
//     let res = state
//         .qe_w_ref
//         .handle_sshkeycreate(uat, uuid_or_name, tag, key, filter, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_get_id_ssh_pubkey_tag(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;
//     let tag = req.get_url_param("tag")?;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_internalsshkeytagread(uat, uuid_or_name, tag, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_delete_id_ssh_pubkey_tag(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;
//     let tag = req.get_url_param("tag")?;
//     let attr = "ssh_publickey".to_string();
//     let values = vec![tag];
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_w_ref
//         .handle_removeattributevalues(uat, uuid_or_name, attr, values, filter, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// // Get and return a single str
// pub async fn account_get_id_radius(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_internalradiusread(uat, uuid_or_name, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_post_id_radius_regenerate(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     // Need to to send the regen msg
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_w_ref
//         .handle_regenerateradius(uat, uuid_or_name, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_delete_id_radius(State(state): State<ServerState>) -> impl IntoResponse {
//     let attr = "radius_secret".to_string();
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
//     json_rest_event_delete_id_attr(state, filter, attr).await
// }

// pub async fn account_get_id_radius_token(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_internalradiustokenread(uat, uuid_or_name, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_post_id_unix(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Json(msg): Json<CreateRequest>,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;
//     let obj: AccountUnixExtend = req.body_json().await?;
//     let (eventid, hvalue) = state.new_eventid();
//     let res = state
//         .qe_w_ref
//         .handle_idmaccountunixextend(uat, uuid_or_name, obj, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_get_id_unix_token(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_internalunixusertokenread(uat, uuid_or_name, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_post_id_unix_auth(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Json(msg): Json<CreateRequest>,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;
//     let obj: SingleStringRequest = req.body_json().await?;
//     let cred = obj.value;
//     let (eventid, hvalue) = state.new_eventid();
//     let res = state
//         .qe_r_ref
//         .handle_idmaccountunixauth(uat, uuid_or_name, cred, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_put_id_unix_credential(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Json(msg): Json<CreateRequest>,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;
//     let obj: SingleStringRequest = req.body_json().await?;
//     let cred = obj.value;
//     let (eventid, hvalue) = state.new_eventid();
//     let res = state
//         .qe_w_ref
//         .handle_idmaccountunixsetcred(uat, uuid_or_name, cred, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn account_delete_id_unix_credential(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = req.get_url_param("id")?;
//     let attr = "unix_password".to_string();
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("posixaccount")));

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_w_ref
//         .handle_purgeattribute(uat, uuid_or_name, attr, filter, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn group_get(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
//     json_rest_event_get(state, filter, None).await
// }

// pub async fn group_post(State(state): State<ServerState>) -> impl IntoResponse {
//     let classes = vec!["group".to_string(), "object".to_string()];
//     json_rest_event_post(state, classes).await
// }

// pub async fn group_id_get(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
//     json_rest_event_get_id(state, filter, None).await
// }

// pub async fn group_id_get_attr(
//     State(state): State<ServerState>,
//     Path(id): Path<String>,
// ) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
//     json_rest_event_get_id_attr(state, filter).await
// }

// pub async fn group_id_post_attr(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
//     json_rest_event_post_id_attr(state, filter).await
// }

// pub async fn group_id_delete_attr(
//     Path(attr): Path<String>,
//     State(state): State<ServerState>,
// ) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));

//     json_rest_event_delete_id_attr(state, filter, attr).await
// }

// pub async fn group_id_put_attr(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
//     json_rest_event_put_id_attr(state, filter).await
// }

// pub async fn group_id_delete(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
//     json_rest_event_delete_id(state, filter).await
// }

// pub async fn group_post_id_unix(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Path(id): Path<String>,
//     Json(obj): Json<GroupUnixExtend>,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = id;

//     let (eventid, hvalue) = state.new_eventid();
//     let res = state
//         .qe_w_ref
//         .handle_idmgroupunixextend(uat, uuid_or_name, obj, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn group_get_id_unix_token(
//     Path(id): Path<String>,
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let uuid_or_name = id;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_internalunixgrouptokenread(uat, uuid_or_name, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn domain_get(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("uuid", PartialValue::Uuid(UUID_DOMAIN_INFO)));
//     json_rest_event_get(state, filter, None).await
// }

// pub async fn domain_get_attr(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
//     json_rest_event_get_attr(state, STR_UUID_DOMAIN_INFO, filter).await
// }

// pub async fn domain_put_attr(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
//     json_rest_event_put_attr(state, STR_UUID_DOMAIN_INFO.to_string(), filter).await
// }

// pub async fn domain_delete_attr(
//     State(state): State<ServerState>,
//     Path(attr): Path<String>,
// ) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));

//     json_rest_event_delete_attr(state, filter, STR_UUID_DOMAIN_INFO.to_string(), attr).await
// }

// pub async fn system_get(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("uuid", PartialValue::Uuid(UUID_SYSTEM_CONFIG)));
//     json_rest_event_get(state, filter, None).await
// }

// pub async fn system_get_attr(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("system_config")));
//     json_rest_event_get_attr(state, STR_UUID_SYSTEM_CONFIG, filter).await
// }

// pub async fn system_post_attr(State(state): State<ServerState>) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("system_config")));
//     json_rest_event_post_attr(state, STR_UUID_SYSTEM_CONFIG.to_string(), filter).await
// }

// pub async fn system_delete_attr(
//     State(state): State<ServerState>,
//     Path(attr): Path<String>,
// ) -> impl IntoResponse {
//     let filter = filter_all!(f_eq("class", PartialValue::new_class("system_config")));

//     json_rest_event_delete_attr(state, filter, STR_UUID_SYSTEM_CONFIG.to_string(), attr).await
// }

// pub async fn recycle_bin_get(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let filter = filter_all!(f_pres("class"));
//     let uat = state.get_current_uat(headers);
//     let attrs = None;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_internalsearchrecycled(uat, filter, attrs, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn recycle_bin_id_get(
//     State(state): State<ServerState>,

//     Path(id): Path<String>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);

//     let filter = filter_all!(f_id(id.as_str()));
//     let attrs = None;

//     let (eventid, hvalue) = state.new_eventid();

//     let res = state
//         .qe_r_ref
//         .handle_internalsearchrecycled(uat, filter, attrs, eventid)
//         .await
//         .map(|mut r| r.pop());
//     to_axum_response(res, hvalue)
// }

// pub async fn recycle_bin_revive_id_post(
//     State(state): State<ServerState>,
//     Path(id): Path<String>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);

//     let filter = filter_all!(f_id(id.as_str()));

//     let (eventid, hvalue) = state.new_eventid();
//     let res = state
//         .qe_w_ref
//         .handle_reviverecycled(uat, filter, eventid)
//         .await;
//     to_axum_response(res, hvalue)
// }

// pub async fn applinks_get(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
// ) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let (eventid, hvalue) = state.new_eventid();
//     let res = state.qe_r_ref.handle_list_applinks(uat, eventid).await;
//     to_axum_response(res, hvalue)
// }

// pub async fn do_routemap(state: tide::Request<RouteMap>) -> impl IntoResponse {
//     let mut res = tide::Response::new(200);

//     res.set_body(state.do_map());
//     Ok(res)
// }

// // pub async fn do_nothing(_State(state): State<ServerState>) -> impl IntoResponse {
// //     let mut res = tide::Response::new(200);
// //     res.set_body("did nothing");
// //     Ok(res)
// // }

// pub async fn reauth(
//     State(state): State<ServerState>,
//     headers: HeaderMap,
//     Json(msg): Json<CreateRequest>,
// ) -> impl IntoResponse {
//     // check that we can get the remote IP address first, since this doesn't touch the backend at all
//     let ip_addr = req.get_remote_addr().ok_or_else(|| {
//         error!("Unable to get remote addr for auth event, refusing to proceed");
//         tide::Error::from_str(
//             tide::StatusCode::InternalServerError,
//             "unable to validate peer address",
//         )
//     })?;

//     let uat = state.get_current_uat(headers);
//     let (eventid, hvalue) = state.new_eventid();

//     let obj: AuthIssueSession = req.body_json().await.map_err(|e| {
//         debug!("Failed get body JSON? {:?}", e);
//         e
//     })?;

//     let inter = state // This may change in the future ...
//         .qe_r_ref
//         .handle_reauth(uat, obj, eventid, ip_addr)
//         .await;

//     auth_session_state_management(state, inter, hvalue)
// }

// // pub async fn auth(
// //     State(state): State<ServerState>,
// //     headers: HeaderMap,
// //     Json(msg): Json<CreateRequest>,
// // ) -> impl IntoResponse {
// //     // check that we can get the remote IP address first, since this doesn't touch the backend at all
// //     let ip_addr = req.get_remote_addr().ok_or_else(|| {
// //         error!("Unable to get remote addr for auth event, refusing to proceed");
// //         tide::Error::from_str(
// //             tide::StatusCode::InternalServerError,
// //             "unable to validate peer address",
// //         )
// //     })?;
// //     // First, deal with some state management.
// //     // Do anything here first that's needed like getting the session details
// //     // out of the req cookie.
// //     let (eventid, hvalue) = state.new_eventid();

// //     let maybe_sessionid: Option<Uuid> = req.get_current_auth_session_id();

// //     let obj: AuthRequest = req.body_json().await.map_err(|e| {
// //         debug!("Failed get body JSON? {:?}", e);
// //         e
// //     })?;

// //     // We probably need to know if we allocate the cookie, that this is a
// //     // new session, and in that case, anything *except* authrequest init is
// //     // invalid.
// //     let inter = state// This may change in the future ...
// //         .qe_r_ref
// //         .handle_auth(maybe_sessionid, obj, eventid, ip_addr)
// //         .await;

// //     auth_session_state_management(state, inter, hvalue)
// // }

// fn auth_session_state_management(
//     State(state): State<ServerState>,
//     inter: Result<AuthResult, OperationError>,
//     hvalue: String,
//     mut msession: WritableSession,
// ) -> impl IntoResponse {
//     let mut auth_session_id_tok = None;

//     let res: Result<AuthResponse, _> = match inter {
//         Ok(AuthResult { state, sessionid }) => {
//             // Do some response/state management.
//             match state {
//                 AuthState::Choose(allowed) => {
//                     debug!("🧩 -> AuthState::Choose");

//                     // Ensure the auth-session-id is set
//                     msession.remove("auth-session-id");
//                     msession
//                         .insert("auth-session-id", sessionid)
//                         .map_err(|e| {
//                             error!(?e);
//                             OperationError::InvalidSessionState
//                         })
//                         .and_then(|_| {
//                             let kref = &state.jws_signer;

//                             let jws = Jws::new(SessionId { sessionid });
//                             // Get the header token ready.
//                             jws.sign(kref)
//                                 .map(|jwss| {
//                                     auth_session_id_tok = Some(jwss.to_string());
//                                 })
//                                 .map_err(|e| {
//                                     error!(?e);
//                                     OperationError::InvalidSessionState
//                                 })
//                         })
//                         .map(|_| ProtoAuthState::Choose(allowed))
//                 }
//                 AuthState::Continue(allowed) => {
//                     debug!("🧩 -> AuthState::Continue");

//                     // Ensure the auth-session-id is set
//                     msession.remove("auth-session-id");
//                     trace!(?sessionid, "🔥  🔥 ");
//                     msession
//                         .insert("auth-session-id", sessionid)
//                         .map_err(|e| {
//                             error!(?e);
//                             OperationError::InvalidSessionState
//                         })
//                         .and_then(|_| {
//                             let kref = &state.jws_signer;
//                             // Get the header token ready.
//                             let jws = Jws::new(SessionId { sessionid });
//                             jws.sign(kref)
//                                 .map(|jwss| {
//                                     auth_session_id_tok = Some(jwss.to_string());
//                                 })
//                                 .map_err(|e| {
//                                     error!(?e);
//                                     OperationError::InvalidSessionState
//                                 })
//                         })
//                         .map(|_| ProtoAuthState::Continue(allowed))
//                 }
//                 AuthState::Success(token, issue) => {
//                     debug!("🧩 -> AuthState::Success");
//                     // Remove the auth-session-id

//                     msession.remove("auth-session-id");
//                     // Create a session cookie?
//                     msession.remove("bearer");

//                     match issue {
//                         AuthIssueSession::Cookie => msession
//                             .insert("bearer", token)
//                             .map_err(|_| OperationError::InvalidSessionState)
//                             .map(|_| ProtoAuthState::SuccessCookie),
//                         AuthIssueSession::Token => Ok(ProtoAuthState::Success(token)),
//                     }
//                 }
//                 AuthState::Denied(reason) => {
//                     debug!("🧩 -> AuthState::Denied");

//                     // Remove the auth-session-id
//                     msession.remove("auth-session-id");
//                     Ok(ProtoAuthState::Denied(reason))
//                 }
//             }
//             .map(|state| AuthResponse { sessionid, state })
//         }
//         Err(e) => Err(e),
//     };

//     to_axum_response(res, hvalue).map(|mut res| {
//         // if the sessionid was injected into our cookie, set it in the
//         // header too.
//         if let Some(tok) = auth_session_id_tok {
//             let headers = res.headers_mut();
//             headers.insert(
//                 "X-KANIDM-AUTH-SESSION-ID",
//                 HeaderValue::from_str(&hvalue).unwrap(),
//             );
//         }
//         res
//     })
// }

// pub async fn auth_valid(State(state): State<ServerState>, headers: HeaderMap) -> impl IntoResponse {
//     let uat = state.get_current_uat(headers);
//     let (eventid, hvalue) = state.new_eventid();
//     let res = state.qe_r_ref.handle_auth_valid(uat, eventid).await;
//     to_axum_response(res, hvalue)
// }
