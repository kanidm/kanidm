use actix_session::Session;
use actix_web::web::{Data, HttpResponse, Json, Path};

use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_read::{
    AuthMessage, IdmAccountUnixAuthMessage, InternalRadiusReadMessage,
    InternalRadiusTokenReadMessage, InternalSearchMessage, InternalSearchRecycledMessage,
    InternalSshKeyReadMessage, InternalSshKeyTagReadMessage, InternalUnixGroupTokenReadMessage,
    InternalUnixUserTokenReadMessage, SearchMessage, WhoamiMessage,
};
use crate::actors::v1_write::QueryServerWriteV1;
use crate::actors::v1_write::{
    AppendAttributeMessage, CreateMessage, DeleteMessage, IdmAccountPersonExtendMessage,
    IdmAccountSetPasswordMessage, IdmAccountUnixExtendMessage, IdmAccountUnixSetCredMessage,
    IdmGroupUnixExtendMessage, InternalCredentialSetMessage, InternalDeleteMessage,
    InternalRegenerateRadiusMessage, InternalSshKeyCreateMessage, ModifyMessage,
    PurgeAttributeMessage, RemoveAttributeValueMessage, ReviveRecycledMessage, SetAttributeMessage,
};
use crate::filter::{Filter, FilterInvalid};
use crate::status::{StatusActor, StatusRequestEvent};
use crate::value::PartialValue;

use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::{
    AccountUnixExtend, AuthRequest, AuthState, CreateRequest, DeleteRequest, GroupUnixExtend,
    ModifyRequest, SearchRequest, SetCredentialRequest, SingleStringRequest, UserAuthToken,
};

use async_std::io;
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder};
use serde::Serialize;
use std::net;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub status_ref: &'static StatusActor,
    pub qe_w_ref: &'static QueryServerWriteV1,
    pub qe_r_ref: &'static QueryServerReadV1,
}

pub trait RequestExtensions {
    fn get_current_uat(&self) -> Option<UserAuthToken>;
}

impl<State> RequestExtensions for tide::Request<State> {
    fn get_current_uat(&self) -> Option<UserAuthToken> {
        self.session().get::<UserAuthToken>("uat")
    }
}

pub fn get_current_user(session: &Session) -> Option<UserAuthToken> {
    match session.get::<UserAuthToken>("uat") {
        Ok(maybe_uat) => maybe_uat,
        Err(_) => None,
    }
}

pub fn operation_error_to_response(e: OperationError, hvalue: String) -> HttpResponse {
    match e {
        OperationError::NotAuthenticated => HttpResponse::Unauthorized()
            .header("X-KANIDM-OPID", hvalue)
            .json(e),
        OperationError::AccessDenied | OperationError::SystemProtectedObject => {
            HttpResponse::Forbidden()
                .header("X-KANIDM-OPID", hvalue)
                .json(e)
        }
        OperationError::EmptyRequest
        | OperationError::NoMatchingEntries
        | OperationError::SchemaViolation(_) => HttpResponse::BadRequest()
            .header("X-KANIDM-OPID", hvalue)
            .json(e),
        _ => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json(e),
    }
}

pub fn to_tide_response<T: Serialize>(
    v: Result<T, OperationError>,
    hvalue: String,
) -> tide::Result {
    match v {
        Ok(iv) => {
            let mut res = tide::Response::new(200);
            tide::Body::from_json(&iv).and_then(|b| {
                res.set_body(b);
                Ok(res)
            })
        }
        Err(OperationError::NotAuthenticated) => {
            Ok(tide::Response::new(tide::StatusCode::Unauthorized))
        }
        Err(OperationError::SystemProtectedObject) | Err(OperationError::AccessDenied) => {
            Ok(tide::Response::new(tide::StatusCode::Forbidden))
        }
        Err(OperationError::EmptyRequest)
        | Err(OperationError::NoMatchingEntries)
        | Err(OperationError::SchemaViolation(_)) => {
            Ok(tide::Response::new(tide::StatusCode::BadRequest))
        }
        Err(_) => Ok(tide::Response::new(tide::StatusCode::InternalServerError)),
    }
    .map(|mut res| {
        res.insert_header("X-KANIDM-OPID", hvalue);
        res
    })
}

macro_rules! new_eventid {
    () => {{
        let eventid = Uuid::new_v4();
        let hv = eventid.to_hyphenated().to_string();
        (eventid, hv)
    }};
}

// Handle the various end points we need to expose

// pub async fn create((req, session, state): (Json<CreateRequest>, Session, Data<AppState>),
pub async fn create(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    // parse the req to a CreateRequest
    let msg: CreateRequest = req.body_json().await?;

    let (eventid, hvalue) = new_eventid!();
    let m_obj = CreateMessage::new(uat, msg, eventid);

    let res = req.state().qe_w_ref.handle_create(m_obj).await;
    to_tide_response(res, hvalue)
}

pub async fn modify(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let msg: ModifyRequest = req.body_json().await?;
    let (eventid, hvalue) = new_eventid!();
    let m_obj = ModifyMessage::new(uat, msg, eventid);
    let res = req.state().qe_w_ref.handle_modify(m_obj).await;
    to_tide_response(res, hvalue)
}

pub async fn delete(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let msg: DeleteRequest = req.body_json().await?;
    let (eventid, hvalue) = new_eventid!();
    let m_obj = DeleteMessage::new(uat, msg, eventid);
    let res = req.state().qe_w_ref.handle_delete(m_obj).await;
    to_tide_response(res, hvalue)
}

pub async fn search(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let msg: SearchRequest = req.body_json().await?;
    let (eventid, hvalue) = new_eventid!();
    let m_obj = SearchMessage::new(uat, msg, eventid);
    let res = req.state().qe_r_ref.handle_search(m_obj).await;
    to_tide_response(res, hvalue)
}

pub async fn whoami(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let (eventid, hvalue) = new_eventid!();
    // New event, feed current auth data from the token to it.
    let m_obj = WhoamiMessage { uat, eventid };

    let res = req.state().qe_r_ref.handle_whoami(m_obj).await;
    to_tide_response(res, hvalue)
}

// =============== REST generics ========================

pub async fn json_rest_event_get(
    session: Session,
    state: Data<AppState>,
    filter: Filter<FilterInvalid>,
    attrs: Option<Vec<String>>,
) -> HttpResponse {
    let uat = get_current_user(&session);

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalSearchMessage {
        uat,
        filter,
        attrs,
        eventid,
    };

    match state.qe_r_ref.handle_internalsearch(obj).await {
        Ok(r) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

async fn json_rest_event_get_id(
    path: Path<String>,
    session: Session,
    state: Data<AppState>,
    filter: Filter<FilterInvalid>,
    attrs: Option<Vec<String>>,
) -> HttpResponse {
    let uat = get_current_user(&session);

    let filter = Filter::join_parts_and(filter, filter_all!(f_id(path.as_str())));

    let (eventid, hvalue) = new_eventid!();

    let obj = InternalSearchMessage {
        uat,
        filter,
        attrs,
        eventid,
    };

    match state.qe_r_ref.handle_internalsearch(obj).await {
        Ok(mut r) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(r.pop()),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

async fn json_rest_event_delete_id(
    path: Path<String>,
    session: Session,
    state: Data<AppState>,
    filter: Filter<FilterInvalid>,
) -> HttpResponse {
    let uat = get_current_user(&session);

    let filter = Filter::join_parts_and(filter, filter_all!(f_id(path.as_str())));
    let (eventid, hvalue) = new_eventid!();

    let obj = InternalDeleteMessage {
        uat,
        filter,
        eventid,
    };

    match state.qe_w_ref.handle_internaldelete(obj).await {
        Ok(()) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

async fn json_rest_event_get_id_attr(
    path: Path<(String, String)>,
    session: Session,
    state: Data<AppState>,
    filter: Filter<FilterInvalid>,
) -> HttpResponse {
    let (id, attr) = path.into_inner();
    let uat = get_current_user(&session);

    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
    let (eventid, hvalue) = new_eventid!();

    let obj = InternalSearchMessage {
        uat,
        filter,
        attrs: Some(vec![attr.clone()]),
        eventid,
    };

    match state.qe_r_ref.handle_internalsearch(obj).await {
        Ok(mut event_result) => {
            // Only get one result
            let r = event_result.pop().and_then(|mut e| {
                // Only get the attribute as requested.
                e.attrs.remove(&attr)
            });
            // Only send back the first result, or None
            HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r)
        }
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

async fn json_rest_event_post(
    mut obj: ProtoEntry,
    session: Session,
    state: Data<AppState>,
    classes: Vec<String>,
) -> HttpResponse {
    // Read the json from the wire.
    let uat = get_current_user(&session);

    obj.attrs.insert("class".to_string(), classes);
    let (eventid, hvalue) = new_eventid!();
    let m_obj = CreateMessage::new_entry(uat, obj, eventid);
    match state.qe_w_ref.handle_create(m_obj).await {
        Ok(r) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

async fn json_rest_event_post_id_attr(
    path: Path<(String, String)>,
    session: Session,
    state: Data<AppState>,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
) -> HttpResponse {
    let uat = get_current_user(&session);
    let (id, attr) = path.into_inner();

    let (eventid, hvalue) = new_eventid!();
    let m_obj = AppendAttributeMessage {
        uat,
        uuid_or_name: id,
        attr,
        values,
        filter,
        eventid,
    };
    // Add a msg here
    match state.qe_w_ref.handle_appendattribute(m_obj).await {
        Ok(()) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

async fn json_rest_event_put_id_attr(
    path: Path<(String, String)>,
    session: Session,
    state: Data<AppState>,
    filter: Filter<FilterInvalid>,
    values: Vec<String>,
) -> HttpResponse {
    let uat = get_current_user(&session);
    let (id, attr) = path.into_inner();

    let (eventid, hvalue) = new_eventid!();
    let m_obj = SetAttributeMessage {
        uat,
        uuid_or_name: id,
        attr,
        values,
        filter,
        eventid,
    };
    match state.qe_w_ref.handle_setattribute(m_obj).await {
        Ok(()) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

async fn json_rest_event_delete_id_attr(
    path: Path<(String, String)>,
    session: Session,
    state: Data<AppState>,
    filter: Filter<FilterInvalid>,
) -> HttpResponse {
    let uat = get_current_user(&session);
    let (id, attr) = path.into_inner();

    let (eventid, hvalue) = new_eventid!();
    // TODO #211: Attempt to get an option Vec<String> here?
    // It's probably better to focus on SCIM instead, it seems richer than this.
    let obj = PurgeAttributeMessage {
        uat,
        uuid_or_name: id,
        attr,
        filter,
        eventid,
    };

    match state.qe_w_ref.handle_purgeattribute(obj).await {
        Ok(()) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

async fn json_rest_event_credential_put(
    id: String,
    cred_id: Option<String>,
    session: Session,
    state: Data<AppState>,
    obj: SetCredentialRequest,
) -> HttpResponse {
    let uat = get_current_user(&session);

    let (eventid, hvalue) = new_eventid!();
    let m_obj = InternalCredentialSetMessage {
        uat,
        uuid_or_name: id,
        appid: cred_id,
        sac: obj,
        eventid,
    };
    match state.qe_w_ref.handle_credentialset(m_obj).await {
        Ok(r) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

// Okay, so a put normally needs
//  * filter of what we are working on (id + class)
//  * a Map<String, Vec<String>> that we turn into a modlist.
//
// OR
//  * filter of what we are working on (id + class)
//  * a Vec<String> that we are changing
//  * the attr name  (as a param to this in path)
//
// json_rest_event_put_id(path, req, state

pub async fn schema_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
    // NOTE: This is filter_all, because from_internal_message will still do the alterations
    // needed to make it safe. This is needed because there may be aci's that block access
    // to the recycle/ts types in the filter, and we need the aci to only eval on this
    // part of the filter!
    let filter = filter_all!(f_or!([
        f_eq("class", PartialValue::new_class("attributetype")),
        f_eq("class", PartialValue::new_class("classtype"))
    ]));
    json_rest_event_get(session, state, filter, None).await
}

pub async fn schema_attributetype_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("attributetype")));
    json_rest_event_get(session, state, filter, None).await
}

pub async fn schema_attributetype_get_id(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    // These can't use get_id because they attribute name and class name aren't ... well name.
    let uat = get_current_user(&session);

    let filter = filter_all!(f_and!([
        f_eq("class", PartialValue::new_class("attributetype")),
        f_eq("attributename", PartialValue::new_iutf8(path.as_str()))
    ]));

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalSearchMessage {
        uat,
        filter,
        attrs: None,
        eventid,
    };

    match state.qe_r_ref.handle_internalsearch(obj).await {
        Ok(mut r) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(r.pop()),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn schema_classtype_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("classtype")));
    json_rest_event_get(session, state, filter, None).await
}

pub async fn schema_classtype_get_id(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    // These can't use get_id because they attribute name and class name aren't ... well name.
    let uat = get_current_user(&session);

    let filter = filter_all!(f_and!([
        f_eq("class", PartialValue::new_class("classtype")),
        f_eq("classname", PartialValue::new_iutf8(path.as_str()))
    ]));

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalSearchMessage {
        uat,
        filter,
        attrs: None,
        eventid,
    };

    match state.qe_r_ref.handle_internalsearch(obj).await {
        Ok(mut r) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(r.pop()),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

// == person ==

pub async fn person_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
    json_rest_event_get(session, state, filter, None).await
}

pub async fn person_post(
    (obj, session, state): (Json<ProtoEntry>, Session, Data<AppState>),
) -> HttpResponse {
    let classes = vec!["account".to_string(), "object".to_string()];
    json_rest_event_post(obj.into_inner(), session, state, classes).await
}

pub async fn person_id_get(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
    json_rest_event_get_id(path, session, state, filter, None).await
}

// == account ==

pub async fn account_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_get(session, state, filter, None).await
}

pub async fn account_post(
    (obj, session, state): (Json<ProtoEntry>, Session, Data<AppState>),
) -> HttpResponse {
    let classes = vec!["account".to_string(), "object".to_string()];
    json_rest_event_post(obj.into_inner(), session, state, classes).await
}

pub async fn account_id_get(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_get_id(path, session, state, filter, None).await
}

pub async fn account_id_get_attr(
    (path, session, state): (Path<(String, String)>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_get_id_attr(path, session, state, filter).await
}

// Matches actix-web styles
#[allow(clippy::type_complexity)]
pub async fn account_id_post_attr(
    (values, path, session, state): (
        Json<Vec<String>>,
        Path<(String, String)>,
        Session,
        Data<AppState>,
    ),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_post_id_attr(path, session, state, filter, values.into_inner()).await
}

pub async fn account_id_delete_attr(
    (path, session, state): (Path<(String, String)>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_delete_id_attr(path, session, state, filter).await
}

// Matches actix-web styles
#[allow(clippy::type_complexity)]
pub async fn account_id_put_attr(
    (values, path, session, state): (
        Json<Vec<String>>,
        Path<(String, String)>,
        Session,
        Data<AppState>,
    ),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_put_id_attr(path, session, state, filter, values.into_inner()).await
}

pub async fn account_id_delete(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_delete_id(path, session, state, filter).await
}

pub async fn account_put_id_credential_primary(
    (obj, path, session, state): (
        Json<SetCredentialRequest>,
        Path<String>,
        Session,
        Data<AppState>,
    ),
) -> HttpResponse {
    let id = path.into_inner();
    json_rest_event_credential_put(id, None, session, state, obj.into_inner()).await
}

// Return a vec of str
pub async fn account_get_id_ssh_pubkeys(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let id = path.into_inner();

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalSshKeyReadMessage {
        uat,
        uuid_or_name: id,
        eventid,
    };

    match state.qe_r_ref.handle_internalsshkeyread(obj).await {
        Ok(r) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

// Matches actix-web styles
#[allow(clippy::type_complexity)]
pub async fn account_post_id_ssh_pubkey(
    (obj, path, session, state): (
        Json<(String, String)>,
        Path<String>,
        Session,
        Data<AppState>,
    ),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let id = path.into_inner();
    let (tag, key) = obj.into_inner();

    let (eventid, hvalue) = new_eventid!();
    let m_obj = InternalSshKeyCreateMessage {
        uat,
        uuid_or_name: id,
        tag,
        key,
        filter: filter_all!(f_eq("class", PartialValue::new_class("account"))),
        eventid,
    };
    // Add a msg here
    match state.qe_w_ref.handle_sshkeycreate(m_obj).await {
        Ok(()) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn account_get_id_ssh_pubkey_tag(
    (path, session, state): (Path<(String, String)>, Session, Data<AppState>),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let (id, tag) = path.into_inner();

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalSshKeyTagReadMessage {
        uat,
        uuid_or_name: id,
        tag,
        eventid,
    };

    match state.qe_r_ref.handle_internalsshkeytagread(obj).await {
        Ok(r) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn account_delete_id_ssh_pubkey_tag(
    (path, session, state): (Path<(String, String)>, Session, Data<AppState>),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let (id, tag) = path.into_inner();

    let (eventid, hvalue) = new_eventid!();
    let obj = RemoveAttributeValueMessage {
        uat,
        uuid_or_name: id,
        attr: "ssh_publickey".to_string(),
        value: tag,
        filter: filter_all!(f_eq("class", PartialValue::new_class("account"))),
        eventid,
    };

    match state.qe_w_ref.handle_removeattributevalue(obj).await {
        Ok(()) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

// Get and return a single str
pub async fn account_get_id_radius(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let id = path.into_inner();

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalRadiusReadMessage {
        uat,
        uuid_or_name: id,
        eventid,
    };

    match state.qe_r_ref.handle_internalradiusread(obj).await {
        Ok(r) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn account_post_id_radius_regenerate(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    // Need to to send the regen msg
    let uat = get_current_user(&session);
    let id = path.into_inner();

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalRegenerateRadiusMessage::new(uat, id, eventid);

    match state.qe_w_ref.handle_regenerateradius(obj).await {
        Ok(r) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn account_delete_id_radius(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    // We reconstruct path here to keep json_rest_event_delete_id_attr generic.
    let p = Path::from((path.into_inner(), "radius_secret".to_string()));
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_delete_id_attr(p, session, state, filter).await
}

pub async fn account_get_id_radius_token(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let id = path.into_inner();

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalRadiusTokenReadMessage {
        uat,
        uuid_or_name: id,
        eventid,
    };

    match state.qe_r_ref.handle_internalradiustokenread(obj).await {
        Ok(r) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn account_post_id_person_extend(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let uuid_or_name = path.into_inner();
    let (eventid, hvalue) = new_eventid!();
    let m_obj = IdmAccountPersonExtendMessage {
        uat,
        uuid_or_name,
        eventid,
    };
    match state.qe_w_ref.handle_idmaccountpersonextend(m_obj).await {
        Ok(()) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn account_post_id_unix(
    (obj, path, session, state): (
        Json<AccountUnixExtend>,
        Path<String>,
        Session,
        Data<AppState>,
    ),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let id = path.into_inner();
    let (eventid, hvalue) = new_eventid!();
    let m_obj = IdmAccountUnixExtendMessage::new(uat, id, obj.into_inner(), eventid);
    match state.qe_w_ref.handle_idmaccountunixextend(m_obj).await {
        Ok(()) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn account_get_id_unix_token(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let id = path.into_inner();

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalUnixUserTokenReadMessage {
        uat,
        uuid_or_name: id,
        eventid,
    };

    match state.qe_r_ref.handle_internalunixusertokenread(obj).await {
        Ok(r) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn account_post_id_unix_auth(
    (obj, path, session, state): (
        Json<SingleStringRequest>,
        Path<String>,
        Session,
        Data<AppState>,
    ),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let id = path.into_inner();
    let (eventid, hvalue) = new_eventid!();
    let m_obj = IdmAccountUnixAuthMessage {
        uat,
        uuid_or_name: id,
        cred: obj.into_inner().value,
        eventid,
    };
    match state.qe_r_ref.handle_idmaccountunixauth(m_obj).await {
        Ok(r) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn account_put_id_unix_credential(
    (obj, path, session, state): (
        Json<SingleStringRequest>,
        Path<String>,
        Session,
        Data<AppState>,
    ),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let id = path.into_inner();
    let (eventid, hvalue) = new_eventid!();
    let m_obj = IdmAccountUnixSetCredMessage {
        uat,
        uuid_or_name: id,
        cred: obj.into_inner().value,
        eventid,
    };
    match state.qe_w_ref.handle_idmaccountunixsetcred(m_obj).await {
        Ok(()) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Err(e) => operation_error_to_response(e, hvalue),
    }
    /*
    match state.qe_w.send(m_obj).await {
        Ok(Ok(())) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
    }
    */
}

pub async fn account_delete_id_unix_credential(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let id = path.into_inner();

    let (eventid, hvalue) = new_eventid!();
    let obj = PurgeAttributeMessage {
        uat,
        uuid_or_name: id,
        attr: "unix_password".to_string(),
        filter: filter_all!(f_eq("class", PartialValue::new_class("posixaccount"))),
        eventid,
    };

    match state.qe_w_ref.handle_purgeattribute(obj).await {
        Ok(()) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn group_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get(session, state, filter, None).await
}

pub async fn group_post(
    (obj, session, state): (Json<ProtoEntry>, Session, Data<AppState>),
) -> HttpResponse {
    let classes = vec!["group".to_string(), "object".to_string()];
    json_rest_event_post(obj.into_inner(), session, state, classes).await
}

pub async fn group_id_get(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get_id(path, session, state, filter, None).await
}

pub async fn group_id_get_attr(
    (path, session, state): (Path<(String, String)>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get_id_attr(path, session, state, filter).await
}

// Matches actix-web styles
#[allow(clippy::type_complexity)]
pub async fn group_id_post_attr(
    (values, path, session, state): (
        Json<Vec<String>>,
        Path<(String, String)>,
        Session,
        Data<AppState>,
    ),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_post_id_attr(path, session, state, filter, values.into_inner()).await
}

pub async fn group_id_delete_attr(
    (path, session, state): (Path<(String, String)>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_delete_id_attr(path, session, state, filter).await
}

// Matches actix-web styles
#[allow(clippy::type_complexity)]
pub async fn group_id_put_attr(
    (values, path, session, state): (
        Json<Vec<String>>,
        Path<(String, String)>,
        Session,
        Data<AppState>,
    ),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_put_id_attr(path, session, state, filter, values.into_inner()).await
}

pub async fn group_id_delete(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_delete_id(path, session, state, filter).await
}

pub async fn group_post_id_unix(
    (obj, path, session, state): (Json<GroupUnixExtend>, Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let id = path.into_inner();
    let (eventid, hvalue) = new_eventid!();
    let m_obj = IdmGroupUnixExtendMessage::new(uat, id, &obj, eventid);
    match state.qe_w_ref.handle_idmgroupunixextend(m_obj).await {
        Ok(()) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn group_get_id_unix_token(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let id = path.into_inner();

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalUnixGroupTokenReadMessage {
        uat,
        uuid_or_name: id,
        eventid,
    };

    match state.qe_r_ref.handle_internalunixgrouptokenread(obj).await {
        Ok(r) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn domain_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_get(session, state, filter, None).await
}

pub async fn domain_id_get(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_get_id(path, session, state, filter, None).await
}

pub async fn domain_id_get_attr(
    (path, session, state): (Path<(String, String)>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_get_id_attr(path, session, state, filter).await
}

// Matches actix-web styles
#[allow(clippy::type_complexity)]
pub async fn domain_id_put_attr(
    (values, path, session, state): (
        Json<Vec<String>>,
        Path<(String, String)>,
        Session,
        Data<AppState>,
    ),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_put_id_attr(path, session, state, filter, values.into_inner()).await
}

pub async fn recycle_bin_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
    let filter = filter_all!(f_pres("class"));
    let uat = get_current_user(&session);
    let attrs = None;

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalSearchRecycledMessage {
        uat,
        filter,
        attrs,
        eventid,
    };

    match state.qe_r_ref.handle_internalsearchrecycled(obj).await {
        Ok(r) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn recycle_bin_id_get(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let filter = filter_all!(f_id(path.as_str()));
    let attrs = None;

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalSearchRecycledMessage {
        uat,
        filter,
        attrs,
        eventid,
    };

    match state.qe_r_ref.handle_internalsearchrecycled(obj).await {
        Ok(mut r) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(r.pop()),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn recycle_bin_revive_id_post(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let filter = filter_all!(f_id(path.as_str()));

    let (eventid, hvalue) = new_eventid!();
    let m_obj = ReviveRecycledMessage {
        uat,
        filter,
        eventid,
    };
    match state.qe_w_ref.handle_reviverecycled(m_obj).await {
        Ok(()) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(()),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

pub async fn do_nothing(_req: tide::Request<AppState>) -> tide::Result {
    let mut res = tide::Response::new(200);
    res.set_body("did nothing");
    Ok(res)
}

// We probably need an extract auth or similar to handle the different
// types (cookie, bearer), and to generic this over get/post.

pub async fn auth(mut req: tide::Request<AppState>) -> tide::Result {
    // AuthRequest

    // First, deal with some state management.
    // Do anything here first that's needed like getting the session details
    // out of the req cookie.

    // From the actix source errors here
    // seems to be related to the serde_json deserialise of the cookie
    // content, and because we control it's get/set it SHOULD be fine
    // provided we use secure cookies. But we can't always trust that ...
    let (eventid, hvalue) = new_eventid!();
    let maybe_sessionid = req.session().get::<Uuid>("auth-session-id");

    let obj: AuthRequest = req.body_json().await?;

    let auth_msg = AuthMessage::new(obj, maybe_sessionid, eventid);

    // We probably need to know if we allocate the cookie, that this is a
    // new session, and in that case, anything *except* authrequest init is
    // invalid.
    let res = req
        .state()
        // This may change in the future ...
        .qe_r_ref
        .handle_auth(auth_msg)
        .await
        .and_then(|ar| {
            // Do some response/state management.
            match &ar.state {
                AuthState::Success(uat) => {
                    let msession = req.session_mut();
                    // Remove the auth-session-id
                    msession.remove("auth-session-id");
                    // Set the uat into the cookie
                    msession
                        .insert("uat", uat)
                        // .map(|_| ())
                        .map_err(|_| OperationError::InvalidSessionState)
                }
                AuthState::Denied(_) => {
                    let msession = req.session_mut();
                    // Remove the auth-session-id
                    msession.remove("auth-session-id");
                    Err(OperationError::AccessDenied)
                }
                AuthState::Continue(_) => {
                    let msession = req.session_mut();
                    // Ensure the auth-session-id is set
                    msession
                        .insert("auth-session-id", ar.sessionid)
                        // .map(|_| ())
                        .map_err(|_| OperationError::InvalidSessionState)
                }
            }
            // And put the auth result back in.
            .map(|()| ar)
        });
    to_tide_response(res, hvalue)
}

pub async fn idm_account_set_password(
    (req, session, state): (Json<SingleStringRequest>, Session, Data<AppState>),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let (eventid, hvalue) = new_eventid!();
    let m_obj = IdmAccountSetPasswordMessage::new(uat, req.into_inner(), eventid);
    match state.qe_w_ref.handle_idmaccountsetpassword(m_obj).await {
        Ok(r) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Err(e) => operation_error_to_response(e, hvalue),
    }
}

// == Status

pub async fn status(req: tide::Request<AppState>) -> tide::Result {
    // We ignore the body in this req
    let (eventid, hvalue) = new_eventid!();
    let r = req
        .state()
        .status_ref
        .handle_request(StatusRequestEvent { eventid })
        .await;
    let mut res = tide::Response::new(tide::StatusCode::Ok);
    res.insert_header("X-KANIDM-OPID", hvalue);
    res.set_body(tide::Body::from_json(&r)?);
    Ok(res)
}

struct TlsListener {
    address: String,
    tls_params: &'static SslAcceptor,
}

impl TlsListener {
    fn new(address: String, tls_params: &'static SslAcceptor) -> Self {
        Self {
            address,
            tls_params,
        }
    }
}

impl std::fmt::Debug for TlsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TlsListener {{}}")
    }
}

impl std::fmt::Display for TlsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TlsListener {{}}")
    }
}

impl<State: Clone + Send + Sync + 'static> tide::listener::ToListener<State> for TlsListener {
    type Listener = TlsListener;

    fn to_listener(self) -> std::io::Result<Self::Listener> {
        Ok(self)
    }
}

fn handle_client<State: Clone + Send + Sync + 'static>(
    app: tide::Server<State>,
    stream: tokio_openssl::SslStream<tokio::net::TcpStream>,
    local_addr: std::net::SocketAddr,
    peer_addr: std::net::SocketAddr,
) {
    /*
    tokio::spawn(async move {
        let fut = async_h1::accept(stream, |mut req| async {
            req.set_local_addr(Some(local_addr));
            req.set_peer_addr(Some(peer_addr));
            app.respond(req).await
        });

        if let Err(error) = fut.await {
            // Do nothing
            // log::error!("async-h1 error", { error: error.to_string() });
        }
    });
    */
    unimplemented!();
}

#[async_trait::async_trait]
impl<State: Clone + Send + Sync + 'static> tide::listener::Listener<State> for TlsListener {
    async fn listen(&mut self, app: tide::Server<State>) -> io::Result<()> {
        let addr = net::SocketAddr::from_str(&self.address).map_err(|e| {
            eprintln!(
                "Could not parse https server address {} -> {:?}",
                self.address, e
            );
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Could not parse https server address",
            )
        })?;

        let mut listener = TcpListener::bind(&addr).await?;

        let tls_params = self.tls_params;

        loop {
            match listener.accept().await {
                Ok((tcpstream, paddr)) => {
                    let iapp = app.clone();
                    tokio::spawn(async move {
                        let res = tokio_openssl::accept(tls_params, tcpstream).await;
                        match res {
                            Ok(tlsstream) => {
                                handle_client(iapp, tlsstream, addr, paddr);
                            }
                            Err(e) => {
                                error!("tcp handshake error, continuing -> {:?}", e);
                            }
                        };
                    });
                }
                Err(e) => {
                    error!("acceptor error, continuing -> {:?}", e);
                }
            }
        }
    }
}

// TODO: Add request limits.
pub fn create_https_server(
    address: String,
    opt_tls_params: Option<SslAcceptorBuilder>,
    cookie_key: &[u8; 32],
    status_ref: &'static StatusActor,
    qe_w_ref: &'static QueryServerWriteV1,
    qe_r_ref: &'static QueryServerReadV1,
) -> () {
    let mut tserver = tide::Server::with_state(AppState {
        status_ref,
        qe_w_ref,
        qe_r_ref,
    });

    // Add middleware?
    tserver.with(tide::log::LogMiddleware::new()).with(
        tide::sessions::SessionMiddleware::new(tide::sessions::MemoryStore::new(), cookie_key)
            .with_cookie_name("kanidm-session")
            .with_same_site_policy(tide::http::cookies::SameSite::Strict)
            .with_session_ttl(Some(Duration::from_secs(3600))),
    );

    // Add routes
    tserver.at("/status").get(self::status);

    let mut raw_route = tserver.at("/v1/raw");
    raw_route.at("/create").post(create);
    raw_route.at("/modify").post(modify);
    raw_route.at("/delete").post(delete);
    raw_route.at("/search").post(search);

    tserver.at("/v1/auth").post(auth);

    let mut schema_route = tserver.at("/v1/schema");
    schema_route.at("").get(|req| async { Ok("schema") });
    schema_route.at("/").get(|req| async { Ok("schema") });
    schema_route
        .at("/attributetype")
        .get(|req| async { Ok("schema") })
        .post(do_nothing);
    schema_route
        .at("/attributetype/:id")
        .get(|req: tide::Request<AppState>| async move {
            Ok(format!(
                "{}",
                req.param("id").unwrap_or("missing".to_owned())
            ))
        })
        .put(do_nothing)
        .patch(do_nothing);

    schema_route
        .at("/classtype")
        .get(|req| async { Ok("schema") })
        .post(do_nothing);
    schema_route
        .at("/classtype/:id")
        .get(|req: tide::Request<AppState>| async move {
            Ok(format!(
                "{}",
                req.param("id").unwrap_or("missing".to_owned())
            ))
        })
        .put(do_nothing)
        .patch(do_nothing);

    let mut self_route = tserver.at("/v1/self");
    self_route.at("").get(whoami);
    self_route.at("/").get(whoami);

    self_route.at("/_attr/:attr").get(do_nothing);
    self_route.at("/_credential").get(do_nothing);

    self_route
        .at("/_credential/primary/set_password")
        .post(|req| async { Ok("self") });
    self_route.at("/_credential/:cid/_lock").get(do_nothing);

    self_route
        .at("/_radius")
        .get(do_nothing)
        .delete(do_nothing)
        .post(do_nothing);

    self_route.at("/_radius/_config").post(do_nothing);
    self_route.at("/_radius/_config/:token").get(do_nothing);
    self_route
        .at("/_radius/_config/:token/apple")
        .get(do_nothing);

    let mut person_route = tserver.at("/v1/person");
    person_route
        .at("")
        .get(|req| async { Ok("person") })
        .post(|req| async { Ok("person") });

    let mut account_route = tserver.at("/v1/account");

    account_route
        .at("")
        .get(|req| async { Ok("account") })
        .post(|req| async { Ok("account") });
    account_route
        .at("/:id")
        .get(|req| async { Ok("account") })
        .delete(|req| async { Ok("account") });
    account_route
        .at("/:id/_attr/:attr")
        .get(|req| async { Ok("account") })
        .put(|req| async { Ok("account") })
        .post(|req| async { Ok("account") })
        .delete(|req| async { Ok("account") });
    account_route
        .at("/:id/_person/_extend")
        .post(|req| async { Ok("account") });
    account_route.at("/:id/_lock").get(do_nothing);

    account_route.at("/:id/_credential").get(do_nothing);
    account_route
        .at("/:id/_credential/primary")
        .put(|req| async { Ok("account") });
    account_route
        .at("/:id/_credential/:cid/_lock")
        .get(do_nothing);

    account_route
        .at("/:id/_ssh_pubkeys")
        .get(|req| async { Ok("account") })
        .post(|req| async { Ok("account") });

    account_route
        .at("/:id/_ssh_pubkeys/:tag")
        .get(|req| async { Ok("account") })
        .delete(|req| async { Ok("account") });

    account_route
        .at("/:id/_radius")
        .get(|req| async { Ok("account") })
        .post(|req| async { Ok("account") })
        .delete(|req| async { Ok("account") });

    account_route
        .at("/:id/_radius/_token")
        .get(|req| async { Ok("account") });

    account_route
        .at("/:id/_unix")
        .post(|req| async { Ok("account") });
    account_route
        .at("/:id/_unix/_token")
        .get(|req| async { Ok("account") });
    account_route
        .at("/:id/_unix/_auth")
        .post(|req| async { Ok("account") });
    account_route
        .at("/:id/_unix/_credential")
        .put(|req| async { Ok("account") })
        .delete(|req| async { Ok("account") });

    let mut group_route = tserver.at("/v1/group");
    group_route
        .at("")
        .get(|req| async { Ok("group") })
        .post(|req| async { Ok("group") });
    group_route
        .at("/:id")
        .get(|req| async { Ok("group") })
        .delete(|req| async { Ok("group") });
    group_route
        .at("/:id/_attr/:attr")
        .get(|req| async { Ok("group") })
        .put(|req| async { Ok("group") })
        .post(|req| async { Ok("group") })
        .delete(|req| async { Ok("group") });
    group_route
        .at("/:id/_unix")
        .post(|req| async { Ok("group") });
    group_route
        .at("/:id/_unix/_token")
        .get(|req| async { Ok("group") });

    let mut domain_route = tserver.at("/v1/domain");
    domain_route.at("").get(|req| async { Ok("domain") });
    domain_route.at("/:id").get(|req| async { Ok("domain") });
    domain_route
        .at("/:id/_attr/:attr")
        .get(|req| async { Ok("domain") })
        .put(|req| async { Ok("domain") });

    let mut recycle_route = tserver.at("/v1/recycle_bin");
    recycle_route.at("").get(|req| async { Ok("recycle") });
    recycle_route.at("/:id").get(|req| async { Ok("recycle") });
    recycle_route
        .at("/:id/_revive")
        .post(|req| async { Ok("recycle") });

    let mut accessprof_route = tserver.at("/v1/access_profile");
    accessprof_route.at("").get(do_nothing);
    accessprof_route.at("/:id").get(do_nothing);
    accessprof_route.at("/:id/_attr/:attr").get(do_nothing);

    // Create listener?
    match opt_tls_params {
        Some(tls_param) => {
            let x = Box::new(tls_param.build());
            let x_ref = Box::leak(x);
            let tlsl = TlsListener::new(address, x_ref);

            tokio::spawn(async move {
                tserver.listen(tlsl).await.expect("Failed to start server");
            });
        }
        None => {
            // Create without https
            tokio::spawn(async move {
                tserver
                    .listen(address)
                    .await
                    .expect("Failed to start server");
            });
        }
    }
}
