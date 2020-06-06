mod ctx;
// use actix_files as fs;
use actix::prelude::*;
use actix_session::{CookieSession, Session};
use actix_web::web::{self, Data, HttpResponse, Json, Path};
use actix_web::{cookie, error, middleware, App, HttpServer};

use crossbeam::channel::unbounded;
use std::sync::Arc;
use std::thread;
use time::Duration;

use crate::config::Configuration;

// SearchResult
use self::ctx::ServerCtx;
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
use crate::async_log;
use crate::audit::AuditScope;
use crate::be::{Backend, BackendTransaction};
use crate::crypto::setup_tls;
use crate::filter::{Filter, FilterInvalid};
use crate::idm::server::IdmServer;
use crate::interval::IntervalActor;
use crate::schema::Schema;
use crate::schema::SchemaTransaction;
use crate::server::QueryServer;
use crate::status::{StatusActor, StatusRequestEvent};
use crate::utils::duration_from_epoch_now;
use crate::value::PartialValue;

use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::{
    AccountUnixExtend, AuthRequest, AuthState, CreateRequest, DeleteRequest, GroupUnixExtend,
    ModifyRequest, SearchRequest, SetCredentialRequest, SingleStringRequest, UserAuthToken,
};

use uuid::Uuid;

struct AppState {
    qe_r: Addr<QueryServerReadV1>,
    qe_w: Addr<QueryServerWriteV1>,
    status: Addr<StatusActor>,
}

fn get_current_user(session: &Session) -> Option<UserAuthToken> {
    match session.get::<UserAuthToken>("uat") {
        Ok(maybe_uat) => maybe_uat,
        Err(_) => None,
    }
}

fn operation_error_to_response(e: OperationError, hvalue: String) -> HttpResponse {
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

async fn create(
    (req, session, state): (Json<CreateRequest>, Session, Data<AppState>),
) -> HttpResponse {
    json_event_post!(req.into_inner(), session, CreateMessage, state.qe_w)
}

async fn modify(
    (req, session, state): (Json<ModifyRequest>, Session, Data<AppState>),
) -> HttpResponse {
    json_event_post!(req.into_inner(), session, ModifyMessage, state.qe_w)
}

async fn delete(
    (req, session, state): (Json<DeleteRequest>, Session, Data<AppState>),
) -> HttpResponse {
    json_event_post!(req.into_inner(), session, DeleteMessage, state.qe_w)
}

async fn search(
    (req, session, state): (Json<SearchRequest>, Session, Data<AppState>),
) -> HttpResponse {
    json_event_post!(req.into_inner(), session, SearchMessage, state.qe_r)
}

async fn whoami((session, state): (Session, Data<AppState>)) -> HttpResponse {
    json_event_get!(session, state, WhoamiMessage)
}

// =============== REST generics ========================

async fn json_rest_event_get(
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
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
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
            // TODO: Check this only has len 1, even though that satte should be impossible.
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
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
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
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
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
    // TODO: Attempt to get an option Vec<String> here?
    let obj = PurgeAttributeMessage {
        uat,
        uuid_or_name: id,
        attr,
        filter,
        eventid,
    };

    match state.qe_w.send(obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
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
//  * a BTreeMap<String, Vec<String>> that we turn into a modlist.
//
// OR
//  * filter of what we are working on (id + class)
//  * a Vec<String> that we are changing
//  * the attr name  (as a param to this in path)
//
// json_rest_event_put_id(path, req, state

async fn schema_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
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

async fn schema_attributetype_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("attributetype")));
    json_rest_event_get(session, state, filter, None).await
}

async fn schema_attributetype_get_id(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    // These can't use get_id because they attribute name and class name aren't ... well name.
    let uat = get_current_user(&session);

    let filter = filter_all!(f_and!([
        f_eq("class", PartialValue::new_class("attributetype")),
        f_eq("attributename", PartialValue::new_iutf8s(path.as_str()))
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

async fn schema_classtype_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("classtype")));
    json_rest_event_get(session, state, filter, None).await
}

async fn schema_classtype_get_id(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    // These can't use get_id because they attribute name and class name aren't ... well name.
    let uat = get_current_user(&session);

    let filter = filter_all!(f_and!([
        f_eq("class", PartialValue::new_class("classtype")),
        f_eq("classname", PartialValue::new_iutf8s(path.as_str()))
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

async fn person_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
    json_rest_event_get(session, state, filter, None).await
}

async fn person_post(
    (obj, session, state): (Json<ProtoEntry>, Session, Data<AppState>),
) -> HttpResponse {
    let classes = vec!["account".to_string(), "object".to_string()];
    json_rest_event_post(obj.into_inner(), session, state, classes).await
}

async fn person_id_get(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
    json_rest_event_get_id(path, session, state, filter, None).await
}

// == account ==

async fn account_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_get(session, state, filter, None).await
}

async fn account_post(
    (obj, session, state): (Json<ProtoEntry>, Session, Data<AppState>),
) -> HttpResponse {
    let classes = vec!["account".to_string(), "object".to_string()];
    json_rest_event_post(obj.into_inner(), session, state, classes).await
}

async fn account_id_get(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_get_id(path, session, state, filter, None).await
}

async fn account_id_get_attr(
    (path, session, state): (Path<(String, String)>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_get_id_attr(path, session, state, filter).await
}

async fn account_id_post_attr(
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

async fn account_id_delete_attr(
    (path, session, state): (Path<(String, String)>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_delete_id_attr(path, session, state, filter).await
}

async fn account_id_put_attr(
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

async fn account_id_delete(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_delete_id(path, session, state, filter).await
}

async fn account_put_id_credential_primary(
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
async fn account_get_id_ssh_pubkeys(
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

async fn account_post_id_ssh_pubkey(
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
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
    }
}

async fn account_get_id_ssh_pubkey_tag(
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

async fn account_delete_id_ssh_pubkey_tag(
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
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
    }
}

// Get and return a single str
async fn account_get_id_radius(
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

async fn account_post_id_radius_regenerate(
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

async fn account_delete_id_radius(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    // We reconstruct path here to keep json_rest_event_delete_id_attr generic.
    let p = Path::from((path.into_inner(), "radius_secret".to_string()));
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_delete_id_attr(p, session, state, filter).await
}

async fn account_get_id_radius_token(
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

async fn account_post_id_person_extend(
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
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
    }
}

async fn account_post_id_unix(
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
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
    }
}

async fn account_get_id_unix_token(
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

async fn account_post_id_unix_auth(
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

async fn account_put_id_unix_credential(
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
    match state.qe_w.send(m_obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
    }
}

async fn account_delete_id_unix_credential(
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
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
    }
}

async fn group_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get(session, state, filter, None).await
}

async fn group_post(
    (obj, session, state): (Json<ProtoEntry>, Session, Data<AppState>),
) -> HttpResponse {
    let classes = vec!["group".to_string(), "object".to_string()];
    json_rest_event_post(obj.into_inner(), session, state, classes).await
}

async fn group_id_get(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get_id(path, session, state, filter, None).await
}

async fn group_id_get_attr(
    (path, session, state): (Path<(String, String)>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get_id_attr(path, session, state, filter).await
}

async fn group_id_post_attr(
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

async fn group_id_delete_attr(
    (path, session, state): (Path<(String, String)>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_delete_id_attr(path, session, state, filter).await
}

async fn group_id_put_attr(
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

async fn group_id_delete(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_delete_id(path, session, state, filter).await
}

async fn group_post_id_unix(
    (obj, path, session, state): (Json<GroupUnixExtend>, Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let uat = get_current_user(&session);
    let id = path.into_inner();
    let (eventid, hvalue) = new_eventid!();
    let m_obj = IdmGroupUnixExtendMessage::new(uat, id, obj.into_inner(), eventid);
    match state.qe_w.send(m_obj).await {
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
    }
}

async fn group_get_id_unix_token(
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

async fn domain_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_get(session, state, filter, None).await
}

async fn domain_id_get(
    (path, session, state): (Path<String>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_get_id(path, session, state, filter, None).await
}

async fn domain_id_get_attr(
    (path, session, state): (Path<(String, String)>, Session, Data<AppState>),
) -> HttpResponse {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_get_id_attr(path, session, state, filter).await
}

async fn domain_id_put_attr(
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

async fn recycle_bin_get((session, state): (Session, Data<AppState>)) -> HttpResponse {
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

async fn recycle_bin_id_get(
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

async fn recycle_bin_revive_id_post(
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
        Ok(Ok(r)) => HttpResponse::Ok().header("X-KANIDM-OPID", hvalue).json(r),
        Ok(Err(e)) => operation_error_to_response(e, hvalue),
        Err(_) => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json("mailbox failure"),
    }
}

async fn do_nothing(_session: Session) -> String {
    "did nothing".to_string()
}

// We probably need an extract auth or similar to handle the different
// types (cookie, bearer), and to generic this over get/post.

async fn auth((obj, session, state): (Json<AuthRequest>, Session, Data<AppState>)) -> HttpResponse {
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

async fn idm_account_set_password(
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

async fn status((_session, state): (Session, Data<AppState>)) -> HttpResponse {
    let (eventid, hvalue) = new_eventid!();
    let r = state.status.send(StatusRequestEvent { eventid }).await;
    match r {
        Ok(true) => HttpResponse::Ok()
            .header("X-KANIDM-OPID", hvalue)
            .json(true),
        _ => HttpResponse::InternalServerError()
            .header("X-KANIDM-OPID", hvalue)
            .json(false),
    }
}

// === internal setup helpers

fn setup_backend(config: &Configuration) -> Result<Backend, OperationError> {
    let mut audit_be = AuditScope::new("backend_setup", uuid::Uuid::new_v4());
    let pool_size: u32 = config.threads as u32;
    let be = Backend::new(&mut audit_be, config.db_path.as_str(), pool_size);
    // debug!
    audit_be.write_log();
    be
}

// TODO #54: We could move most of the be/schema/qs setup and startup
// outside of this call, then pass in "what we need" in a cloneable
// form, this way we could have seperate Idm vs Qs threads, and dedicated
// threads for write vs read
fn setup_qs_idms(
    audit: &mut AuditScope,
    be: Backend,
) -> Result<(QueryServer, IdmServer), OperationError> {
    // Create "just enough" schema for us to be able to load from
    // disk ... Schema loading is one time where we validate the
    // entries as we read them, so we need this here.
    let schema = match Schema::new(audit) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            return Err(e);
        }
    };

    // Create a query_server implementation
    let query_server = QueryServer::new(be, schema);

    // TODO #62: Should the IDM parts be broken out to the IdmServer?
    // What's important about this initial setup here is that it also triggers
    // the schema and acp reload, so they are now configured correctly!
    // Initialise the schema core.
    //
    // Now search for the schema itself, and validate that the system
    // in memory matches the BE on disk, and that it's syntactically correct.
    // Write it out if changes are needed.
    query_server.initialise_helper(audit, duration_from_epoch_now())?;

    // We generate a SINGLE idms only!

    let idms = IdmServer::new(query_server.clone());

    Ok((query_server, idms))
}

pub fn backup_server_core(config: Configuration, dst_path: &str) {
    let be = match setup_backend(&config) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };
    let mut audit = AuditScope::new("backend_backup", uuid::Uuid::new_v4());

    let mut be_ro_txn = be.read();
    let r = be_ro_txn.backup(&mut audit, dst_path);
    audit.write_log();
    match r {
        Ok(_) => info!("Backup success!"),
        Err(e) => {
            error!("Backup failed: {:?}", e);
            std::process::exit(1);
        }
    };
    // Let the txn abort, even on success.
}

pub fn restore_server_core(config: Configuration, dst_path: &str) {
    let be = match setup_backend(&config) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };
    let mut audit = AuditScope::new("backend_restore", uuid::Uuid::new_v4());

    // First, we provide the in-memory schema so that core attrs are indexed correctly.
    let schema = match Schema::new(&mut audit) {
        Ok(s) => s,
        Err(e) => {
            audit.write_log();
            error!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    // Limit the scope of the schema txn.
    let idxmeta = { schema.write().get_idxmeta_set() };

    let mut be_wr_txn = be.write(idxmeta);
    let r = be_wr_txn
        .restore(&mut audit, dst_path)
        .and_then(|_| be_wr_txn.commit(&mut audit));

    if r.is_err() {
        audit.write_log();
        error!("Failed to restore database: {:?}", r);
        std::process::exit(1);
    }
    info!("Database loaded successfully");

    info!("Attempting to init query server ...");

    let (qs, _idms) = match setup_qs_idms(&mut audit, be) {
        Ok(t) => t,
        Err(e) => {
            audit.write_log();
            error!("Unable to setup query server or idm server -> {:?}", e);
            return;
        }
    };
    info!("Success!");

    info!("Start reindex phase ...");

    let mut qs_write = qs.write(duration_from_epoch_now());
    let r = qs_write
        .reindex(&mut audit)
        .and_then(|_| qs_write.commit(&mut audit));

    match r {
        Ok(_) => info!("Reindex Success!"),
        Err(e) => {
            audit.write_log();
            error!("Restore failed: {:?}", e);
            std::process::exit(1);
        }
    };

    info!("✅ Restore Success!");
}

pub fn reindex_server_core(config: Configuration) {
    let be = match setup_backend(&config) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };
    let mut audit = AuditScope::new("server_reindex", uuid::Uuid::new_v4());

    // First, we provide the in-memory schema so that core attrs are indexed correctly.
    let schema = match Schema::new(&mut audit) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    info!("Start Index Phase 1 ...");
    // Limit the scope of the schema txn.
    let idxmeta = { schema.write().get_idxmeta_set() };

    // Reindex only the core schema attributes to bootstrap the process.
    let mut be_wr_txn = be.write(idxmeta);
    let r = be_wr_txn
        .reindex(&mut audit)
        .and_then(|_| be_wr_txn.commit(&mut audit));

    // Now that's done, setup a minimal qs and reindex from that.
    if r.is_err() {
        audit.write_log();
        error!("Failed to reindex database: {:?}", r);
        std::process::exit(1);
    }
    info!("Index Phase 1 Success!");

    info!("Attempting to init query server ...");

    let (qs, _idms) = match setup_qs_idms(&mut audit, be) {
        Ok(t) => t,
        Err(e) => {
            audit.write_log();
            error!("Unable to setup query server or idm server -> {:?}", e);
            return;
        }
    };
    info!("Init Query Server Success!");

    info!("Start Index Phase 2 ...");

    let mut qs_write = qs.write(duration_from_epoch_now());
    let r = qs_write
        .reindex(&mut audit)
        .and_then(|_| qs_write.commit(&mut audit));

    audit.write_log();

    match r {
        Ok(_) => info!("Index Phase 2 Success!"),
        Err(e) => {
            error!("Reindex failed: {:?}", e);
            std::process::exit(1);
        }
    };
}

pub fn domain_rename_core(config: Configuration, new_domain_name: String) {
    let mut audit = AuditScope::new("domain_rename", uuid::Uuid::new_v4());

    // Start the backend.
    let be = match setup_backend(&config) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };
    // setup the qs - *with* init of the migrations and schema.
    let (qs, _idms) = match setup_qs_idms(&mut audit, be) {
        Ok(t) => t,
        Err(e) => {
            audit.write_log();
            error!("Unable to setup query server or idm server -> {:?}", e);
            return;
        }
    };

    let mut qs_write = qs.write(duration_from_epoch_now());
    let r = qs_write
        .domain_rename(&mut audit, new_domain_name.as_str())
        .and_then(|_| qs_write.commit(&mut audit));

    match r {
        Ok(_) => info!("Domain Rename Success!"),
        Err(e) => {
            error!("Domain Rename Failed - Rollback has occured: {:?}", e);
            std::process::exit(1);
        }
    };
}

/*
pub fn reset_sid_core(config: Configuration) {
    let mut audit = AuditScope::new("reset_sid_core", uuid::Uuid::new_v4());
    // Setup the be
    let be = match setup_backend(&config) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };
    let nsid = be.reset_db_s_uuid(&mut audit);
    audit.write_log();
    info!("New Server ID: {:?}", nsid);
}
*/

pub fn verify_server_core(config: Configuration) {
    let mut audit = AuditScope::new("server_verify", uuid::Uuid::new_v4());
    // Setup the be
    let be = match setup_backend(&config) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };
    // setup the qs - without initialise!
    let schema_mem = match Schema::new(&mut audit) {
        Ok(sc) => sc,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            return;
        }
    };
    let server = QueryServer::new(be, schema_mem);

    // Run verifications.
    let r = server.verify(&mut audit);

    audit.write_log();

    if r.is_empty() {
        info!("Verification passed!");
        std::process::exit(0);
    } else {
        for er in r {
            error!("{:?}", er);
        }
        std::process::exit(1);
    }

    // Now add IDM server verifications?
}

pub fn recover_account_core(config: Configuration, name: String, password: String) {
    let mut audit = AuditScope::new("recover_account", uuid::Uuid::new_v4());

    // Start the backend.
    let be = match setup_backend(&config) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };
    // setup the qs - *with* init of the migrations and schema.
    let (_qs, idms) = match setup_qs_idms(&mut audit, be) {
        Ok(t) => t,
        Err(e) => {
            audit.write_log();
            error!("Unable to setup query server or idm server -> {:?}", e);
            return;
        }
    };

    // Run the password change.
    let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
    match idms_prox_write.recover_account(&mut audit, name, password) {
        Ok(_) => {
            idms_prox_write
                .commit(&mut audit)
                .expect("A critical error during commit occured.");
            audit.write_log();
            info!("Password reset!");
        }
        Err(e) => {
            error!("Error during password reset -> {:?}", e);
            audit.write_log();
            // abort the txn
            std::mem::drop(idms_prox_write);
            std::process::exit(1);
        }
    };
}

pub fn create_server_core(config: Configuration) -> Result<ServerCtx, ()> {
    // Until this point, we probably want to write to the log macro fns.

    if config.integration_test_config.is_some() {
        warn!("RUNNING IN INTEGRATION TEST MODE.");
        warn!("IF YOU SEE THIS IN PRODUCTION YOU MUST CONTACT SUPPORT IMMEDIATELY.");
    }

    info!("Starting kanidm with configuration: {}", config);
    // The log server is started on it's own thread, and is contacted
    // asynchronously.

    let (log_tx, log_rx) = unbounded();
    let log_thread = thread::spawn(move || async_log::run(log_rx));

    // Start the status tracking thread
    let status_addr = StatusActor::start(log_tx.clone());

    // Setup TLS (if any)
    let opt_tls_params = match setup_tls(&config) {
        Ok(opt_tls_params) => opt_tls_params,
        Err(e) => {
            error!("Failed to configure TLS parameters -> {:?}", e);
            return Err(());
        }
    };

    // Similar, create a stats thread which aggregates statistics from the
    // server as they come in.

    // Setup the be for the qs.
    let be = match setup_backend(&config) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE -> {:?}", e);
            return Err(());
        }
    };

    let mut audit = AuditScope::new("setup_qs_idms", uuid::Uuid::new_v4());
    // Start the IDM server.
    let (qs, idms) = match setup_qs_idms(&mut audit, be) {
        Ok(t) => t,
        Err(e) => {
            audit.write_log();
            error!("Unable to setup query server or idm server -> {:?}", e);
            return Err(());
        }
    };
    // Any pre-start tasks here.
    match &config.integration_test_config {
        Some(itc) => {
            let mut idms_prox_write = idms.proxy_write(duration_from_epoch_now());
            match idms_prox_write.recover_account(
                &mut audit,
                "admin".to_string(),
                itc.admin_password.clone(),
            ) {
                Ok(_) => {}
                Err(e) => {
                    audit.write_log();
                    error!(
                        "Unable to configure INTERGATION TEST admin account -> {:?}",
                        e
                    );
                    return Err(());
                }
            };
            match idms_prox_write.commit(&mut audit) {
                Ok(_) => {}
                Err(e) => {
                    audit.write_log();
                    error!("Unable to commit INTERGATION TEST setup -> {:?}", e);
                    return Err(());
                }
            }
        }
        None => {}
    }
    log_tx.send(Some(audit)).unwrap_or_else(|_| {
        error!("CRITICAL: UNABLE TO COMMIT LOGS");
    });

    // Arc the idms.
    let idms_arc = Arc::new(idms);

    // Pass it to the actor for threading.
    // Start the read query server with the given be path: future config
    let server_read_addr =
        QueryServerReadV1::start(log_tx.clone(), qs.clone(), idms_arc.clone(), config.threads);
    // Start the write thread
    let server_write_addr = QueryServerWriteV1::start(log_tx.clone(), qs, idms_arc);

    // Setup timed events associated to the write thread
    let _int_addr = IntervalActor::new(server_write_addr.clone()).start();

    // Copy the max size
    let secure_cookies = config.secure_cookies;
    // domain will come from the qs now!
    let cookie_key: [u8; 32] = config.cookie_key;

    // start the web server
    let server = HttpServer::new(move || {
        App::new()
            .data(AppState {
                qe_r: server_read_addr.clone(),
                qe_w: server_write_addr.clone(),
                status: status_addr.clone(),
            })
            .wrap(middleware::Logger::default())
            .wrap(
                // Signed prevents tampering. this 32 byte key MUST
                // be generated (probably a cli option, and it's up to the
                // server process to coordinate these on hosts). IE an RODC
                // could have a different key than our write servers to prevent
                // disclosure of a writeable token in case of compromise. It does
                // mean that you can't load balance between the rodc and the write
                // though, but that's tottaly reasonable.
                CookieSession::signed(&cookie_key)
                    // .path(prefix.as_str())
                    // .domain(domain.as_str())
                    .same_site(cookie::SameSite::Strict)
                    .name("kanidm-session")
                    // if true, only allow to https
                    .secure(secure_cookies)
                    // TODO #63: make this configurable!
                    .max_age_time(Duration::hours(1)),
            )
            // .service(fs::Files::new("/static", "./static"))
            // Even though this says "CreateRequest", it's actually configuring *ALL* json requests.
            // .app_data(web::Json::<CreateRequest>::configure(|cfg| { cfg
            .app_data(
                web::JsonConfig::default()
                    .limit(4096)
                    .error_handler(|err, _req| {
                        let s = format!("{}", err);
                        error::InternalError::from_response(err, HttpResponse::BadRequest().json(s))
                            .into()
                    }),
            )
            .service(web::scope("/status").route("", web::get().to(status)))
            .service(
                web::scope("/v1/raw")
                    .route("/create", web::post().to(create))
                    .route("/modify", web::post().to(modify))
                    .route("/delete", web::post().to(delete))
                    .route("/search", web::post().to(search)),
            )
            .service(web::scope("/v1/auth").route("", web::post().to(auth)))
            .service(
                web::scope("/v1/schema")
                    .route("", web::get().to(schema_get))
                    .route("/attributetype", web::get().to(schema_attributetype_get))
                    .route("/attributetype", web::post().to(do_nothing))
                    .route(
                        "/attributetype/{id}",
                        web::get().to(schema_attributetype_get_id),
                    )
                    .route("/attributetype/{id}", web::put().to(do_nothing))
                    .route("/attributetype/{id}", web::patch().to(do_nothing))
                    .route("/classtype", web::get().to(schema_classtype_get))
                    .route("/classtype", web::post().to(do_nothing))
                    .route("/classtype/{id}", web::get().to(schema_classtype_get_id))
                    .route("/classtype/{id}", web::put().to(do_nothing))
                    .route("/classtype/{id}", web::patch().to(do_nothing)),
            )
            .service(
                web::scope("/v1/self")
                    .route("", web::get().to(whoami))
                    .route("/_attr/{attr}", web::get().to(do_nothing))
                    .route("/_credential", web::get().to(do_nothing))
                    .route(
                        "/_credential/primary/set_password",
                        web::post().to(idm_account_set_password),
                    )
                    .route("/_credential/{cid}/_lock", web::get().to(do_nothing))
                    .route("/_radius", web::get().to(do_nothing))
                    .route("/_radius", web::delete().to(do_nothing))
                    .route("/_radius", web::post().to(do_nothing))
                    .route("/_radius/_config", web::post().to(do_nothing))
                    .route("/_radius/_config/{secret_otp}", web::get().to(do_nothing))
                    .route(
                        "/_radius/_config/{secret_otp}/apple",
                        web::get().to(do_nothing),
                    ),
            )
            .service(
                web::scope("/v1/person")
                    .route("", web::get().to(person_get))
                    .route("", web::post().to(person_post))
                    .route("/{id}", web::get().to(person_id_get)), /*
                                                                   .route("/{id}", web::delete().to(account_id_delete))
                                                                   .route("/{id}/_attr/{attr}", web::get().to(account_id_get_attr))
                                                                   .route("/{id}/_attr/{attr}", web::post().to(account_id_post_attr))
                                                                   .route("/{id}/_attr/{attr}", web::put().to(account_id_put_attr))
                                                                   .route(
                                                                       "/{id}/_attr/{attr}",
                                                                       web::delete().to(account_id_delete_attr),
                                                                   )
                                                                   */
            )
            .service(
                web::scope("/v1/account")
                    .route("", web::get().to(account_get))
                    .route("", web::post().to(account_post))
                    .route("/{id}", web::get().to(account_id_get))
                    .route("/{id}", web::delete().to(account_id_delete))
                    .route("/{id}/_attr/{attr}", web::get().to(account_id_get_attr))
                    .route("/{id}/_attr/{attr}", web::post().to(account_id_post_attr))
                    .route("/{id}/_attr/{attr}", web::put().to(account_id_put_attr))
                    .route(
                        "/{id}/_attr/{attr}",
                        web::delete().to(account_id_delete_attr),
                    )
                    .route(
                        "/{id}/_person/_extend",
                        web::post().to(account_post_id_person_extend),
                    )
                    .route("/{id}/_lock", web::get().to(do_nothing))
                    .route("/{id}/_credential", web::get().to(do_nothing))
                    .route(
                        "/{id}/_credential/primary",
                        web::put().to(account_put_id_credential_primary),
                    )
                    .route("/{id}/_credential/{cid}/_lock", web::get().to(do_nothing))
                    .route(
                        "/{id}/_ssh_pubkeys",
                        web::get().to(account_get_id_ssh_pubkeys),
                    )
                    .route(
                        "/{id}/_ssh_pubkeys",
                        web::post().to(account_post_id_ssh_pubkey),
                    )
                    .route(
                        "/{id}/_ssh_pubkeys/{tag}",
                        web::get().to(account_get_id_ssh_pubkey_tag),
                    )
                    .route(
                        "/{id}/_ssh_pubkeys/{tag}",
                        web::delete().to(account_delete_id_ssh_pubkey_tag),
                    )
                    .route("/{id}/_radius", web::get().to(account_get_id_radius))
                    .route(
                        "/{id}/_radius",
                        web::post().to(account_post_id_radius_regenerate),
                    )
                    .route("/{id}/_radius", web::delete().to(account_delete_id_radius))
                    .route(
                        "/{id}/_radius/_token",
                        web::get().to(account_get_id_radius_token),
                    )
                    .route("/{id}/_unix", web::post().to(account_post_id_unix))
                    .route(
                        "/{id}/_unix/_token",
                        web::get().to(account_get_id_unix_token),
                    )
                    .route(
                        "/{id}/_unix/_auth",
                        web::post().to(account_post_id_unix_auth),
                    )
                    .route(
                        "/{id}/_unix/_credential",
                        web::put().to(account_put_id_unix_credential),
                    )
                    .route(
                        "/{id}/_unix/_credential",
                        web::delete().to(account_delete_id_unix_credential),
                    ),
            )
            .service(
                web::scope("/v1/group")
                    .route("", web::get().to(group_get))
                    .route("", web::post().to(group_post))
                    .route("/{id}", web::get().to(group_id_get))
                    .route("/{id}", web::delete().to(group_id_delete))
                    .route("/{id}/_attr/{attr}", web::get().to(group_id_get_attr))
                    .route("/{id}/_attr/{attr}", web::post().to(group_id_post_attr))
                    .route("/{id}/_attr/{attr}", web::put().to(group_id_put_attr))
                    .route("/{id}/_attr/{attr}", web::delete().to(group_id_delete_attr))
                    .route("/{id}/_unix", web::post().to(group_post_id_unix))
                    .route("/{id}/_unix/_token", web::get().to(group_get_id_unix_token)),
            )
            .service(
                web::scope("/v1/domain")
                    .route("", web::get().to(domain_get))
                    .route("/{id}", web::get().to(domain_id_get))
                    .route("/{id}/_attr/{attr}", web::get().to(domain_id_get_attr))
                    .route("/{id}/_attr/{attr}", web::put().to(domain_id_put_attr)),
            )
            .service(
                web::scope("/v1/recycle_bin")
                    .route("", web::get().to(recycle_bin_get))
                    .route("/{id}", web::get().to(recycle_bin_id_get))
                    .route("/{id}/_revive", web::post().to(recycle_bin_revive_id_post)),
            )
            .service(
                web::scope("/v1/access_profile")
                    .route("", web::get().to(do_nothing))
                    .route("/{id}", web::get().to(do_nothing))
                    .route("/{id}/_attr/{attr}", web::get().to(do_nothing)),
            )
    });

    let server = match opt_tls_params {
        Some(tls_params) => server.bind_openssl(config.address, tls_params),
        None => {
            warn!("Starting WITHOUT TLS parameters. This may cause authentication to fail!");
            server.bind(config.address)
        }
    };

    server.expect("Failed to initialise server!").run();
    info!("ready to rock! 🤘");

    Ok(ServerCtx::new(System::current(), log_tx, log_thread))
}
