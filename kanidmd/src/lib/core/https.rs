// use actix_files as fs;
use actix::prelude::*;
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

use uuid::Uuid;

pub struct AppState {
    pub qe_r: Addr<QueryServerReadV1>,
    pub qe_w: Addr<QueryServerWriteV1>,
    pub status: &'static StatusActor,
    pub qe_w_ref: &'static QueryServerWriteV1,
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

macro_rules! new_eventid {
    () => {{
        let eventid = Uuid::new_v4();
        let hv = eventid.to_hyphenated().to_string();
        (eventid, hv)
    }};
}

macro_rules! json_event_post {
    ($req:expr, $session:expr, $message_type:ty, $dest:expr) => {{
        // Get auth if any?
        let uat = get_current_user(&$session);
        // Send to the db for handling
        // combine request + uat -> message.
        let (eventid, hvalue) = new_eventid!();
        let m_obj = <$message_type>::new(uat, $req, eventid);
        match $dest.send(m_obj).await {
            Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
            Ok(Err(e)) => operation_error_to_response(e, hvalue),
            Err(_) => HttpResponse::InternalServerError()
                .header("X-KANIDM-OPID", hvalue)
                .json("mailbox failure"),
        }
    }};
}

macro_rules! json_event_get {
    ($session:expr, $state:expr, $message_type:ty) => {{
        // Get current auth data - remember, the QS checks if the
        // none/some is okay, because it's too hard to make it work here
        // with all the async parts.
        let uat = get_current_user(&$session);
        let (eventid, hvalue) = new_eventid!();

        // New event, feed current auth data from the token to it.
        let obj = <$message_type>::new(uat, eventid);

        match $state.qe_r.send(obj).await {
            Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
            Ok(Err(e)) => operation_error_to_response(e, hvalue),
            Err(_) => HttpResponse::InternalServerError()
                .header("X-KANIDM-OPID", hvalue)
                .json("mailbox failure"),
        }
    }};
}

// Handle the various end points we need to expose

pub async fn create(
    (req, session, state): (Json<CreateRequest>, Session, Data<AppState>),
) -> HttpResponse {
    json_event_post!(req.into_inner(), session, CreateMessage, state.qe_w)
}

pub async fn modify(
    (req, session, state): (Json<ModifyRequest>, Session, Data<AppState>),
) -> HttpResponse {
    json_event_post!(req.into_inner(), session, ModifyMessage, state.qe_w)
}

pub async fn delete(
    (req, session, state): (Json<DeleteRequest>, Session, Data<AppState>),
) -> HttpResponse {
    json_event_post!(req.into_inner(), session, DeleteMessage, state.qe_w)
}

pub async fn search(
    (req, session, state): (Json<SearchRequest>, Session, Data<AppState>),
) -> HttpResponse {
    json_event_post!(req.into_inner(), session, SearchMessage, state.qe_r)
}

pub async fn whoami((session, state): (Session, Data<AppState>)) -> HttpResponse {
    json_event_get!(session, state, WhoamiMessage)
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

    match state.qe_r.send(obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_r.send(obj).await {
        Ok(Ok(mut r)) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(r.pop()),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_w.send(obj).await {
        Ok(Ok(())) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_r.send(obj).await {
        Ok(Ok(mut event_result)) => {
            // Only get one result
            let r = event_result.pop().and_then(|mut e| {
                // Only get the attribute as requested.
                e.attrs.remove(&attr)
            });
            // Only send back the first result, or None
            HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r)
        }
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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
    match state.qe_w.send(m_obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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
    match state.qe_w.send(m_obj).await {
        Ok(Ok(())) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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
    match state.qe_w.send(m_obj).await {
        Ok(Ok(())) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_w.send(obj).await {
        Ok(Ok(())) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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
    match state.qe_w.send(m_obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_r.send(obj).await {
        Ok(Ok(mut r)) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(r.pop()),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_r.send(obj).await {
        Ok(Ok(mut r)) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(r.pop()),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_r.send(obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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
    match state.qe_w.send(m_obj).await {
        Ok(Ok(())) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_r.send(obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_w.send(obj).await {
        Ok(Ok(())) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_r.send(obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_w.send(obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_r.send(obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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
    match state.qe_w.send(m_obj).await {
        Ok(Ok(())) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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
    match state.qe_w.send(m_obj).await {
        Ok(Ok(())) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_r.send(obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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
    match state.qe_r.send(m_obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_w.send(obj).await {
        Ok(Ok(())) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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
    match state.qe_w.send(m_obj).await {
        Ok(Ok(())) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_r.send(obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_r.send(obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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

    match state.qe_r.send(obj).await {
        Ok(Ok(mut r)) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(r.pop()),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
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
    match state.qe_w.send(m_obj).await {
        Ok(Ok(())) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(()),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
    }
}

pub async fn do_nothing(_session: Session) -> String {
    "did nothing".to_string()
}

// We probably need an extract auth or similar to handle the different
// types (cookie, bearer), and to generic this over get/post.

pub async fn auth(
    (obj, session, state): (Json<AuthRequest>, Session, Data<AppState>),
) -> HttpResponse {
    // First, deal with some state management.
    // Do anything here first that's needed like getting the session details
    // out of the req cookie.

    // From the actix source errors here
    // seems to be related to the serde_json deserialise of the cookie
    // content, and because we control it's get/set it SHOULD be fine
    // provided we use secure cookies. But we can't always trust that ...
    let (eventid, hvalue) = new_eventid!();
    let maybe_sessionid = match session.get::<Uuid>("auth-session-id") {
        Ok(c) => c,
        Err(_e) => {
            return HttpResponse::InternalServerError()
                .header("X-KANIDM-OPID", hvalue)
                .json(())
        }
    };

    let auth_msg = AuthMessage::new(obj.into_inner(), maybe_sessionid, eventid);

    // We probably need to know if we allocate the cookie, that this is a
    // new session, and in that case, anything *except* authrequest init is
    // invalid.
    match state
        // This may change in the future ...
        .qe_r
        .send(auth_msg)
        .await
    {
        Ok(Ok(ar)) => {
            match &ar.state {
                AuthState::Success(uat) => {
                    // Remove the auth-session-id
                    session.remove("auth-session-id");
                    // Set the uat into the cookie
                    match session.set("uat", uat) {
                        Ok(_) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(ar),
                        Err(_) => HttpResponse::InternalServerError()
                            .header("X-KANIDM-OPID", hvalue)
                            .json(()),
                    }
                }
                AuthState::Denied(_) => {
                    // Remove the auth-session-id
                    session.remove("auth-session-id");
                    HttpResponse::Unauthorized()
                        .header("X-KANIDM-OPID", hvalue)
                        .json(ar)
                }
                AuthState::Continue(_) => {
                    // Ensure the auth-session-id is set
                    match session.set("auth-session-id", ar.sessionid) {
                        Ok(_) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(ar),
                        Err(_) => HttpResponse::InternalServerError()
                            .header("X-KANIDM-OPID", hvalue)
                            .json(()),
                    }
                }
            }
        }
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
    }
}

pub async fn idm_account_set_password(
    (obj, session, state): (Json<SingleStringRequest>, Session, Data<AppState>),
) -> HttpResponse {
    json_event_post!(
        obj.into_inner(),
        session,
        IdmAccountSetPasswordMessage,
        state.qe_w
    )
}

// == Status

pub async fn status((_session, state): (Session, Data<AppState>)) -> HttpResponse {
    let (eventid, hvalue) = new_eventid!();
    let r = state
        .status
        .handle_request(StatusRequestEvent { eventid })
        .await;
    HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r)
}
