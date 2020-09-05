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
use crate::config::TlsConfiguration;
use crate::filter::{Filter, FilterInvalid};
use crate::status::{StatusActor, StatusRequestEvent};
use crate::value::PartialValue;

use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::{
    AccountUnixExtend, AuthRequest, AuthState, CreateRequest, DeleteRequest, GroupUnixExtend,
    ModifyRequest, SearchRequest, SetCredentialRequest, SingleStringRequest, UserAuthToken,
};

use serde::Serialize;
use std::time::Duration;
use uuid::Uuid;

// Temporary
use tide_rustls::TlsListener;
// use openssl::ssl::{SslAcceptor, SslAcceptorBuilder};
// use tokio::net::TcpListener;
// use async_std::io;
// use std::net;
// use std::str::FromStr;

#[derive(Clone)]
pub struct AppState {
    pub status_ref: &'static StatusActor,
    pub qe_w_ref: &'static QueryServerWriteV1,
    pub qe_r_ref: &'static QueryServerReadV1,
}

pub trait RequestExtensions {
    fn get_current_uat(&self) -> Option<UserAuthToken>;

    fn get_url_param(&self, param: &str) -> Result<String, tide::Error>;
}

impl<State> RequestExtensions for tide::Request<State> {
    fn get_current_uat(&self) -> Option<UserAuthToken> {
        self.session().get::<UserAuthToken>("uat")
    }

    fn get_url_param(&self, param: &str) -> Result<String, tide::Error> {
        self.param(param)
            .map_err(|_| tide::Error::from_str(tide::StatusCode::ImATeapot, "teapot"))
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
        Err(e) => {
            let sc = match &e {
                OperationError::NotAuthenticated => tide::StatusCode::Unauthorized,
                OperationError::SystemProtectedObject | OperationError::AccessDenied => {
                    tide::StatusCode::Forbidden
                }
                OperationError::NoMatchingEntries => tide::StatusCode::NotFound,
                OperationError::EmptyRequest | OperationError::SchemaViolation(_) => {
                    tide::StatusCode::BadRequest
                }
                _ => tide::StatusCode::InternalServerError,
            };
            let mut res = tide::Response::new(sc);
            tide::Body::from_json(&e).and_then(|b| {
                res.set_body(b);
                Ok(res)
            })
        }
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

pub async fn whoami(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let (eventid, hvalue) = new_eventid!();
    // New event, feed current auth data from the token to it.
    let m_obj = WhoamiMessage { uat, eventid };

    let res = req.state().qe_r_ref.handle_whoami(m_obj).await;
    to_tide_response(res, hvalue)
}

// =============== REST generics ========================

pub async fn json_rest_event_get(
    req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
    attrs: Option<Vec<String>>,
) -> tide::Result {
    let uat = req.get_current_uat();

    let (eventid, hvalue) = new_eventid!();
    let m_obj = InternalSearchMessage {
        uat,
        filter,
        attrs,
        eventid,
    };

    let res = req.state().qe_r_ref.handle_internalsearch(m_obj).await;
    to_tide_response(res, hvalue)
}

async fn json_rest_event_get_id(
    req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
    attrs: Option<Vec<String>>,
) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));

    let (eventid, hvalue) = new_eventid!();

    let m_obj = InternalSearchMessage {
        uat,
        filter,
        attrs,
        eventid,
    };

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsearch(m_obj)
        .await
        .map(|mut r| r.pop());
    to_tide_response(res, hvalue)
}

async fn json_rest_event_delete_id(
    req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
    let (eventid, hvalue) = new_eventid!();

    let m_obj = InternalDeleteMessage {
        uat,
        filter,
        eventid,
    };

    let res = req
        .state()
        .qe_w_ref
        .handle_internaldelete(m_obj)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

async fn json_rest_event_get_id_attr(
    req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
) -> tide::Result {
    let id = req.get_url_param("id")?;
    let attr = req.get_url_param("attr")?;
    let uat = req.get_current_uat();

    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
    let (eventid, hvalue) = new_eventid!();

    let m_obj = InternalSearchMessage {
        uat,
        filter,
        attrs: Some(vec![attr.clone()]),
        eventid,
    };

    let res: Result<Option<_>, _> = req
        .state()
        .qe_r_ref
        .handle_internalsearch(m_obj)
        .await
        .map(|mut event_result| event_result.pop().and_then(|mut e| e.attrs.remove(&attr)));
    to_tide_response(res, hvalue)
}

async fn json_rest_event_post(
    mut req: tide::Request<AppState>,
    classes: Vec<String>,
) -> tide::Result {
    debug_assert!(classes.len() > 0);
    // Read the json from the wire.
    let uat = req.get_current_uat();
    let mut obj: ProtoEntry = req.body_json().await?;

    obj.attrs.insert("class".to_string(), classes);
    let (eventid, hvalue) = new_eventid!();
    let m_obj = CreateMessage::new_entry(uat, obj, eventid);

    let res = req.state().qe_w_ref.handle_create(m_obj).await;
    to_tide_response(res, hvalue)
}

async fn json_rest_event_post_id_attr(
    mut req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let attr = req.get_url_param("attr")?;
    let values: Vec<String> = req.body_json().await?;

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
    let res = req
        .state()
        .qe_w_ref
        .handle_appendattribute(m_obj)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

async fn json_rest_event_put_id_attr(
    mut req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let attr = req.get_url_param("attr")?;
    let values: Vec<String> = req.body_json().await?;

    let (eventid, hvalue) = new_eventid!();
    let m_obj = SetAttributeMessage {
        uat,
        uuid_or_name: id,
        attr,
        values,
        filter,
        eventid,
    };
    let res = req
        .state()
        .qe_w_ref
        .handle_setattribute(m_obj)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

async fn json_rest_event_delete_id_attr(
    req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
    // Seperate for account_delete_id_radius
    attr: String,
) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();
    // TODO #211: Attempt to get an option Vec<String> here?
    // It's probably better to focus on SCIM instead, it seems richer than this.
    let m_obj = PurgeAttributeMessage {
        uat,
        uuid_or_name: id,
        attr,
        filter,
        eventid,
    };
    let res = req
        .state()
        .qe_w_ref
        .handle_purgeattribute(m_obj)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

async fn json_rest_event_credential_put(
    mut req: tide::Request<AppState>,
    cred_id: Option<String>,
) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let obj: SetCredentialRequest = req.body_json().await?;

    let (eventid, hvalue) = new_eventid!();
    let m_obj = InternalCredentialSetMessage {
        uat,
        uuid_or_name: id,
        appid: cred_id,
        sac: obj,
        eventid,
    };
    let res = req.state().qe_w_ref.handle_credentialset(m_obj).await;
    to_tide_response(res, hvalue)
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

pub async fn schema_get(req: tide::Request<AppState>) -> tide::Result {
    // NOTE: This is filter_all, because from_internal_message will still do the alterations
    // needed to make it safe. This is needed because there may be aci's that block access
    // to the recycle/ts types in the filter, and we need the aci to only eval on this
    // part of the filter!
    let filter = filter_all!(f_or!([
        f_eq("class", PartialValue::new_class("attributetype")),
        f_eq("class", PartialValue::new_class("classtype"))
    ]));
    json_rest_event_get(req, filter, None).await
}

pub async fn schema_attributetype_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("attributetype")));
    json_rest_event_get(req, filter, None).await
}

pub async fn schema_attributetype_get_id(req: tide::Request<AppState>) -> tide::Result {
    // These can't use get_id because they attribute name and class name aren't ... well name.
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let filter = filter_all!(f_and!([
        f_eq("class", PartialValue::new_class("attributetype")),
        f_eq("attributename", PartialValue::new_iutf8(id.as_str()))
    ]));

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalSearchMessage {
        uat,
        filter,
        attrs: None,
        eventid,
    };

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsearch(obj)
        .await
        .map(|mut r| r.pop());
    to_tide_response(res, hvalue)
}

pub async fn schema_classtype_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("classtype")));
    json_rest_event_get(req, filter, None).await
}

pub async fn schema_classtype_get_id(req: tide::Request<AppState>) -> tide::Result {
    // These can't use get_id because they attribute name and class name aren't ... well name.
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let filter = filter_all!(f_and!([
        f_eq("class", PartialValue::new_class("classtype")),
        f_eq("classname", PartialValue::new_iutf8(id.as_str()))
    ]));

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalSearchMessage {
        uat,
        filter,
        attrs: None,
        eventid,
    };

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsearch(obj)
        .await
        .map(|mut r| r.pop());
    to_tide_response(res, hvalue)
}

// == person ==

pub async fn person_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
    json_rest_event_get(req, filter, None).await
}

pub async fn person_post(req: tide::Request<AppState>) -> tide::Result {
    let classes = vec!["account".to_string(), "object".to_string()];
    json_rest_event_post(req, classes).await
}

pub async fn person_id_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
    json_rest_event_get_id(req, filter, None).await
}

// == account ==

pub async fn account_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_get(req, filter, None).await
}

pub async fn account_post(req: tide::Request<AppState>) -> tide::Result {
    let classes = vec!["account".to_string(), "object".to_string()];
    json_rest_event_post(req, classes).await
}

pub async fn account_id_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_get_id(req, filter, None).await
}

pub async fn account_id_get_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_get_id_attr(req, filter).await
}

pub async fn account_id_post_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_post_id_attr(req, filter).await
}

pub async fn account_id_delete_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    let attr = req.get_url_param("attr")?;
    json_rest_event_delete_id_attr(req, filter, attr).await
}

pub async fn account_id_put_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_put_id_attr(req, filter).await
}

pub async fn account_id_delete(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_delete_id(req, filter).await
}

pub async fn account_put_id_credential_primary(req: tide::Request<AppState>) -> tide::Result {
    json_rest_event_credential_put(req, None).await
}

// Return a vec of str
pub async fn account_get_id_ssh_pubkeys(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalSshKeyReadMessage {
        uat,
        uuid_or_name: id,
        eventid,
    };

    let res = req.state().qe_r_ref.handle_internalsshkeyread(obj).await;
    to_tide_response(res, hvalue)
}

pub async fn account_post_id_ssh_pubkey(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let (tag, key): (String, String) = req.body_json().await?;

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
    let res = req
        .state()
        .qe_w_ref
        .handle_sshkeycreate(m_obj)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

pub async fn account_get_id_ssh_pubkey_tag(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let tag = req.get_url_param("tag")?;

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalSshKeyTagReadMessage {
        uat,
        uuid_or_name: id,
        tag,
        eventid,
    };

    let res = req.state().qe_r_ref.handle_internalsshkeytagread(obj).await;
    to_tide_response(res, hvalue)
}

pub async fn account_delete_id_ssh_pubkey_tag(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let tag = req.get_url_param("tag")?;

    let (eventid, hvalue) = new_eventid!();
    let obj = RemoveAttributeValueMessage {
        uat,
        uuid_or_name: id,
        attr: "ssh_publickey".to_string(),
        value: tag,
        filter: filter_all!(f_eq("class", PartialValue::new_class("account"))),
        eventid,
    };

    let res = req
        .state()
        .qe_w_ref
        .handle_removeattributevalue(obj)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

// Get and return a single str
pub async fn account_get_id_radius(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalRadiusReadMessage {
        uat,
        uuid_or_name: id,
        eventid,
    };

    let res = req.state().qe_r_ref.handle_internalradiusread(obj).await;
    to_tide_response(res, hvalue)
}

pub async fn account_post_id_radius_regenerate(req: tide::Request<AppState>) -> tide::Result {
    // Need to to send the regen msg
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalRegenerateRadiusMessage::new(uat, id, eventid);

    let res = req.state().qe_w_ref.handle_regenerateradius(obj).await;
    to_tide_response(res, hvalue)
}

pub async fn account_delete_id_radius(req: tide::Request<AppState>) -> tide::Result {
    let attr = "radius_secret".to_string();
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_delete_id_attr(req, filter, attr).await
}

pub async fn account_get_id_radius_token(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalRadiusTokenReadMessage {
        uat,
        uuid_or_name: id,
        eventid,
    };

    let res = req
        .state()
        .qe_r_ref
        .handle_internalradiustokenread(obj)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_post_id_person_extend(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let (eventid, hvalue) = new_eventid!();
    let m_obj = IdmAccountPersonExtendMessage {
        uat,
        uuid_or_name: id,
        eventid,
    };
    let res = req
        .state()
        .qe_w_ref
        .handle_idmaccountpersonextend(m_obj)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

pub async fn account_post_id_unix(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let obj: AccountUnixExtend = req.body_json().await?;
    let (eventid, hvalue) = new_eventid!();
    let m_obj = IdmAccountUnixExtendMessage::new(uat, id, obj, eventid);
    let res = req
        .state()
        .qe_w_ref
        .handle_idmaccountunixextend(m_obj)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

pub async fn account_get_id_unix_token(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalUnixUserTokenReadMessage {
        uat,
        uuid_or_name: id,
        eventid,
    };

    let res = req
        .state()
        .qe_r_ref
        .handle_internalunixusertokenread(obj)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_post_id_unix_auth(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let obj: SingleStringRequest = req.body_json().await?;
    let (eventid, hvalue) = new_eventid!();
    let m_obj = IdmAccountUnixAuthMessage {
        uat,
        uuid_or_name: id,
        cred: obj.value,
        eventid,
    };
    let res = req.state().qe_r_ref.handle_idmaccountunixauth(m_obj).await;
    to_tide_response(res, hvalue)
}

pub async fn account_put_id_unix_credential(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let obj: SingleStringRequest = req.body_json().await?;
    let (eventid, hvalue) = new_eventid!();
    let m_obj = IdmAccountUnixSetCredMessage {
        uat,
        uuid_or_name: id,
        cred: obj.value,
        eventid,
    };
    let res = req
        .state()
        .qe_w_ref
        .handle_idmaccountunixsetcred(m_obj)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

pub async fn account_delete_id_unix_credential(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();
    let obj = PurgeAttributeMessage {
        uat,
        uuid_or_name: id,
        attr: "unix_password".to_string(),
        filter: filter_all!(f_eq("class", PartialValue::new_class("posixaccount"))),
        eventid,
    };

    let res = req
        .state()
        .qe_w_ref
        .handle_purgeattribute(obj)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

pub async fn group_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get(req, filter, None).await
}

pub async fn group_post(req: tide::Request<AppState>) -> tide::Result {
    let classes = vec!["group".to_string(), "object".to_string()];
    json_rest_event_post(req, classes).await
}

pub async fn group_id_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get_id(req, filter, None).await
}

pub async fn group_id_get_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get_id_attr(req, filter).await
}

pub async fn group_id_post_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_post_id_attr(req, filter).await
}

pub async fn group_id_delete_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    let attr = req.get_url_param("attr")?;
    json_rest_event_delete_id_attr(req, filter, attr).await
}

pub async fn group_id_put_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_put_id_attr(req, filter).await
}

pub async fn group_id_delete(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_delete_id(req, filter).await
}

pub async fn group_post_id_unix(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let obj: GroupUnixExtend = req.body_json().await?;
    let (eventid, hvalue) = new_eventid!();
    let m_obj = IdmGroupUnixExtendMessage::new(uat, id, &obj, eventid);
    let res = req
        .state()
        .qe_w_ref
        .handle_idmgroupunixextend(m_obj)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

pub async fn group_get_id_unix_token(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalUnixGroupTokenReadMessage {
        uat,
        uuid_or_name: id,
        eventid,
    };

    let res = req
        .state()
        .qe_r_ref
        .handle_internalunixgrouptokenread(obj)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn domain_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_get(req, filter, None).await
}

pub async fn domain_id_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_get_id(req, filter, None).await
}

pub async fn domain_id_get_attr(
    req: tide::Request<AppState>,
    // (path, session, state): (Path<(String, String)>, Session, Data<AppState>),
) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_get_id_attr(req, filter).await
}

pub async fn domain_id_put_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_put_id_attr(req, filter).await
}

pub async fn recycle_bin_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_pres("class"));
    let uat = req.get_current_uat();
    let attrs = None;

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalSearchRecycledMessage {
        uat,
        filter,
        attrs,
        eventid,
    };

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsearchrecycled(obj)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn recycle_bin_id_get(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let filter = filter_all!(f_id(id.as_str()));
    let attrs = None;

    let (eventid, hvalue) = new_eventid!();
    let obj = InternalSearchRecycledMessage {
        uat,
        filter,
        attrs,
        eventid,
    };

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsearchrecycled(obj)
        .await
        .map(|mut r| r.pop());
    to_tide_response(res, hvalue)
}

pub async fn recycle_bin_revive_id_post(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let filter = filter_all!(f_id(id.as_str()));

    let (eventid, hvalue) = new_eventid!();
    let m_obj = ReviveRecycledMessage {
        uat,
        filter,
        eventid,
    };
    let res = req
        .state()
        .qe_w_ref
        .handle_reviverecycled(m_obj)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
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

pub async fn idm_account_set_password(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let obj: SingleStringRequest = req.body_json().await?;
    let (eventid, hvalue) = new_eventid!();
    let m_obj = IdmAccountSetPasswordMessage::new(uat, obj, eventid);
    let res = req
        .state()
        .qe_w_ref
        .handle_idmaccountsetpassword(m_obj)
        .await;
    to_tide_response(res, hvalue)
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

/*
// For openssl
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
    _app: tide::Server<State>,
    _stream: tokio_openssl::SslStream<tokio::net::TcpStream>,
    _local_addr: std::net::SocketAddr,
    _peer_addr: std::net::SocketAddr,
) {
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
*/

// TODO: Add request limits.
pub fn create_https_server(
    address: String,
    // opt_tls_params: Option<SslAcceptorBuilder>,
    opt_tls_params: Option<&TlsConfiguration>,
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
    schema_route.at("/").get(schema_get);
    schema_route
        .at("/attributetype")
        .get(schema_attributetype_get)
        .post(do_nothing);
    schema_route
        .at("/attributetype/:id")
        .get(schema_attributetype_get_id)
        .put(do_nothing)
        .patch(do_nothing);

    schema_route
        .at("/classtype")
        .get(schema_classtype_get)
        .post(do_nothing);
    schema_route
        .at("/classtype/:id")
        .get(schema_classtype_get_id)
        .put(do_nothing)
        .patch(do_nothing);

    let mut self_route = tserver.at("/v1/self");
    self_route.at("/").get(whoami);

    self_route.at("/_attr/:attr").get(do_nothing);
    self_route.at("/_credential").get(do_nothing);

    self_route
        .at("/_credential/primary/set_password")
        .post(idm_account_set_password);
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
    person_route.at("/").get(person_get).post(person_post);
    person_route.at("/:id").get(person_id_get);

    let mut account_route = tserver.at("/v1/account");

    account_route.at("/").get(account_get).post(account_post);
    account_route
        .at("/:id")
        .get(account_id_get)
        .delete(account_id_delete);
    account_route
        .at("/:id/_attr/:attr")
        .get(account_id_get_attr)
        .put(account_id_put_attr)
        .post(account_id_post_attr)
        .delete(account_id_delete_attr);
    account_route
        .at("/:id/_person/_extend")
        .post(account_post_id_person_extend);
    account_route.at("/:id/_lock").get(do_nothing);

    account_route.at("/:id/_credential").get(do_nothing);
    account_route
        .at("/:id/_credential/primary")
        .put(account_put_id_credential_primary);
    account_route
        .at("/:id/_credential/:cid/_lock")
        .get(do_nothing);

    account_route
        .at("/:id/_ssh_pubkeys")
        .get(account_get_id_ssh_pubkeys)
        .post(account_post_id_ssh_pubkey);

    account_route
        .at("/:id/_ssh_pubkeys/:tag")
        .get(account_get_id_ssh_pubkey_tag)
        .delete(account_delete_id_ssh_pubkey_tag);

    account_route
        .at("/:id/_radius")
        .get(account_get_id_radius)
        .post(account_post_id_radius_regenerate)
        .delete(account_delete_id_radius);

    account_route
        .at("/:id/_radius/_token")
        .get(account_get_id_radius_token);

    account_route.at("/:id/_unix").post(account_post_id_unix);
    account_route
        .at("/:id/_unix/_token")
        .get(account_get_id_unix_token);
    account_route
        .at("/:id/_unix/_auth")
        .post(account_post_id_unix_auth);
    account_route
        .at("/:id/_unix/_credential")
        .put(account_put_id_unix_credential)
        .delete(account_delete_id_unix_credential);

    let mut group_route = tserver.at("/v1/group");
    group_route.at("/").get(group_get).post(group_post);
    group_route
        .at("/:id")
        .get(group_id_get)
        .delete(group_id_delete);
    group_route
        .at("/:id/_attr/:attr")
        .get(group_id_get_attr)
        .put(group_id_put_attr)
        .post(group_id_post_attr)
        .delete(group_id_delete_attr);
    group_route.at("/:id/_unix").post(group_post_id_unix);
    group_route
        .at("/:id/_unix/_token")
        .get(group_get_id_unix_token);

    let mut domain_route = tserver.at("/v1/domain");
    domain_route.at("/").get(domain_get);
    domain_route.at("/:id").get(domain_id_get);
    domain_route
        .at("/:id/_attr/:attr")
        .get(domain_id_get_attr)
        .put(domain_id_put_attr);

    let mut recycle_route = tserver.at("/v1/recycle_bin");
    recycle_route.at("/").get(recycle_bin_get);
    recycle_route.at("/:id").get(recycle_bin_id_get);
    recycle_route
        .at("/:id/_revive")
        .post(recycle_bin_revive_id_post);

    let mut accessprof_route = tserver.at("/v1/access_profile");
    accessprof_route.at("/").get(do_nothing);
    accessprof_route.at("/:id").get(do_nothing);
    accessprof_route.at("/:id/_attr/:attr").get(do_nothing);

    // Create listener?
    match opt_tls_params {
        Some(tls_param) => {
            let tlsl = TlsListener::build()
                .addrs(address)
                .cert(&tls_param.cert)
                .key(&tls_param.key)
                .finish()
                .expect("Failed to setup tls");
            /*
            let x = Box::new(tls_param.build());
            let x_ref = Box::leak(x);
            let tlsl = TlsListener::new(address, x_ref);
            */

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
