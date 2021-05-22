use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_write::QueryServerWriteV1;
use crate::config::{ServerRole, TlsConfiguration};
use crate::event::AuthResult;
use crate::filter::{Filter, FilterInvalid};
use crate::idm::AuthState;
use crate::status::{StatusActor, StatusRequestEvent};
use crate::value::PartialValue;

use kanidm_proto::v1::Entry as ProtoEntry;
use kanidm_proto::v1::{
    AccountUnixExtend, AuthRequest, AuthResponse, AuthState as ProtoAuthState, CreateRequest,
    DeleteRequest, GroupUnixExtend, ModifyRequest, OperationError, SearchRequest,
    SetCredentialRequest, SingleStringRequest, UserAuthToken,
};

use serde::Serialize;
use std::time::Duration;
use uuid::Uuid;

// Temporary
use tide_rustls::TlsListener;
// use openssl::ssl::{SslAcceptor, SslAcceptorBuilder};
// use tokio::net::TcpListener;
// use async_std::io;
use async_std::task;
// use std::net;
// use std::str::FromStr;

#[derive(Clone)]
pub struct AppState {
    pub status_ref: &'static StatusActor,
    pub qe_w_ref: &'static QueryServerWriteV1,
    pub qe_r_ref: &'static QueryServerReadV1,
    // Store the token management parts.
    pub fernet_handle: fernet::Fernet,
}

pub trait RequestExtensions {
    fn get_current_uat(&self) -> Option<UserAuthToken>;

    fn get_current_auth_session_id(&self) -> Option<Uuid>;

    fn get_url_param(&self, param: &str) -> Result<String, tide::Error>;
}

impl RequestExtensions for tide::Request<AppState> {
    fn get_current_uat(&self) -> Option<UserAuthToken> {
        // Contact the QS to get it to validate wtf is up.
        let kref = &self.state().fernet_handle;
        // self.session().get::<UserAuthToken>("uat")
        self.header(tide::http::headers::AUTHORIZATION)
            .and_then(|hv| {
                // Get the first header value.
                hv.get(0)
            })
            .and_then(|h| {
                // Turn it to a &str, and then check the prefix
                h.as_str().strip_prefix("Bearer ")
            })
            .and_then(|ts| {
                // Take the token str and attempt to decrypt
                // Attempt to re-inflate a UAT from bytes.
                let uat: Option<UserAuthToken> = kref
                    .decrypt_with_ttl(ts, 3600)
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok());
                uat
            })
    }

    fn get_current_auth_session_id(&self) -> Option<Uuid> {
        // We see if there is a signed header copy first.
        let kref = &self.state().fernet_handle;
        self.header("X-KANIDM-AUTH-SESSION-ID")
            .and_then(|hv| {
                // Get the first header value.
                hv.get(0)
            })
            .and_then(|h| {
                // Take the token str and attempt to decrypt
                // Attempt to re-inflate a uuid from bytes.
                let uat: Option<Uuid> = kref
                    .decrypt_with_ttl(h.as_str(), 3600)
                    .ok()
                    .and_then(|b| serde_json::from_slice(&b).ok());
                uat
            })
            // If not there, get from the cookie instead.
            .or_else(|| self.session().get::<Uuid>("auth-session-id"))
    }

    fn get_url_param(&self, param: &str) -> Result<String, tide::Error> {
        self.param(param)
            .map(|s| s.to_string())
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
            tide::Body::from_json(&iv).map(|b| {
                res.set_body(b);
                res
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
            tide::Body::from_json(&e).map(|b| {
                res.set_body(b);
                res
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
async fn index_view(_req: tide::Request<AppState>) -> tide::Result {
    let mut res = tide::Response::new(200);
    res.set_content_type("text/html;charset=utf-8");
    res.set_body(
        r#"
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>Kanidm</title>
        <link rel="stylesheet" href="/pkg/external/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T">
        <script src="/pkg/external/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo"></script>
        <script src="/pkg/external/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1"></script>
        <script src="/pkg/external/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM"></script>
        <script src="/pkg/external/confetti.js"></script>
        <script src="/pkg/bundle.js" defer></script>
    </head>

    <body>
    </body>
</html>
    "#,
    );

    Ok(res)
}

// pub async fn create((req, session, state): (Json<CreateRequest>, Session, Data<AppState>),
pub async fn create(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    // parse the req to a CreateRequest
    let msg: CreateRequest = req.body_json().await?;

    let (eventid, hvalue) = new_eventid!();

    let res = req.state().qe_w_ref.handle_create(uat, msg, eventid).await;
    to_tide_response(res, hvalue)
}

pub async fn modify(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let msg: ModifyRequest = req.body_json().await?;
    let (eventid, hvalue) = new_eventid!();
    let res = req.state().qe_w_ref.handle_modify(uat, msg, eventid).await;
    to_tide_response(res, hvalue)
}

pub async fn delete(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let msg: DeleteRequest = req.body_json().await?;
    let (eventid, hvalue) = new_eventid!();
    let res = req.state().qe_w_ref.handle_delete(uat, msg, eventid).await;
    to_tide_response(res, hvalue)
}

pub async fn search(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let msg: SearchRequest = req.body_json().await?;
    let (eventid, hvalue) = new_eventid!();
    let res = req.state().qe_r_ref.handle_search(uat, msg, eventid).await;
    to_tide_response(res, hvalue)
}

pub async fn whoami(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let (eventid, hvalue) = new_eventid!();
    // New event, feed current auth data from the token to it.
    let res = req.state().qe_r_ref.handle_whoami(uat, eventid).await;
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

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsearch(uat, filter, attrs, eventid)
        .await;
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

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsearch(uat, filter, attrs, eventid)
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

    let res = req
        .state()
        .qe_w_ref
        .handle_internaldelete(uat, filter, eventid)
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

    let attrs = Some(vec![attr.clone()]);

    let res: Result<Option<_>, _> = req
        .state()
        .qe_r_ref
        .handle_internalsearch(uat, filter, attrs, eventid)
        .await
        .map(|mut event_result| event_result.pop().and_then(|mut e| e.attrs.remove(&attr)));
    to_tide_response(res, hvalue)
}

async fn json_rest_event_post(
    mut req: tide::Request<AppState>,
    classes: Vec<String>,
) -> tide::Result {
    debug_assert!(!classes.is_empty());
    let (eventid, hvalue) = new_eventid!();
    // Read the json from the wire.
    let uat = req.get_current_uat();
    let mut obj: ProtoEntry = req.body_json().await?;
    obj.attrs.insert("class".to_string(), classes);
    let msg = CreateRequest { entries: vec![obj] };

    let res = req.state().qe_w_ref.handle_create(uat, msg, eventid).await;
    to_tide_response(res, hvalue)
}

async fn json_rest_event_post_id_attr(
    mut req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let attr = req.get_url_param("attr")?;
    let values: Vec<String> = req.body_json().await?;
    let (eventid, hvalue) = new_eventid!();
    let res = req
        .state()
        .qe_w_ref
        .handle_appendattribute(uat, uuid_or_name, attr, values, filter, eventid)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

async fn json_rest_event_put_id_attr(
    mut req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let attr = req.get_url_param("attr")?;
    let values: Vec<String> = req.body_json().await?;

    let (eventid, hvalue) = new_eventid!();
    let res = req
        .state()
        .qe_w_ref
        .handle_setattribute(uat, uuid_or_name, attr, values, filter, eventid)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

async fn json_rest_event_delete_id_attr(
    mut req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
    // Seperate for account_delete_id_radius
    attr: String,
) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let (eventid, hvalue) = new_eventid!();

    // TODO #211: Attempt to get an option Vec<String> here?
    // It's probably better to focus on SCIM instead, it seems richer than this.
    let body = req.take_body();
    let values: Vec<String> = if body.is_empty().unwrap_or(true) {
        vec![]
    } else {
        // Must now be a valid list.
        body.into_json().await?
    };

    if values.is_empty() {
        let res = req
            .state()
            .qe_w_ref
            .handle_purgeattribute(uat, uuid_or_name, attr, filter, eventid)
            .await
            .map(|()| true);
        to_tide_response(res, hvalue)
    } else {
        let res = req
            .state()
            .qe_w_ref
            .handle_removeattributevalues(uat, uuid_or_name, attr, values, filter, eventid)
            .await
            .map(|()| true);
        to_tide_response(res, hvalue)
    }
}

async fn json_rest_event_credential_put(
    mut req: tide::Request<AppState>,
    appid: Option<String>,
) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let sac: SetCredentialRequest = req.body_json().await?;

    let (eventid, hvalue) = new_eventid!();
    let res = req
        .state()
        .qe_w_ref
        .handle_credentialset(uat, uuid_or_name, appid, sac, eventid)
        .await;
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

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsearch(uat, filter, None, eventid)
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

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsearch(uat, filter, None, eventid)
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

pub async fn account_get_id_credential_status(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();

    let res = req
        .state()
        .qe_r_ref
        .handle_idmcredentialstatus(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

// Return a vec of str
pub async fn account_get_id_ssh_pubkeys(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsshkeyread(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_post_id_ssh_pubkey(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let (tag, key): (String, String) = req.body_json().await?;
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));

    let (eventid, hvalue) = new_eventid!();
    // Add a msg here
    let res = req
        .state()
        .qe_w_ref
        .handle_sshkeycreate(uat, uuid_or_name, tag, key, filter, eventid)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

pub async fn account_get_id_ssh_pubkey_tag(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let tag = req.get_url_param("tag")?;

    let (eventid, hvalue) = new_eventid!();

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsshkeytagread(uat, uuid_or_name, tag, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_delete_id_ssh_pubkey_tag(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let tag = req.get_url_param("tag")?;
    let attr = "ssh_publickey".to_string();
    let values = vec![tag];
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));

    let (eventid, hvalue) = new_eventid!();

    let res = req
        .state()
        .qe_w_ref
        .handle_removeattributevalues(uat, uuid_or_name, attr, values, filter, eventid)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

// Get and return a single str
pub async fn account_get_id_radius(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();

    let res = req
        .state()
        .qe_r_ref
        .handle_internalradiusread(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_post_id_radius_regenerate(req: tide::Request<AppState>) -> tide::Result {
    // Need to to send the regen msg
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();

    let res = req
        .state()
        .qe_w_ref
        .handle_regenerateradius(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_delete_id_radius(req: tide::Request<AppState>) -> tide::Result {
    let attr = "radius_secret".to_string();
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_delete_id_attr(req, filter, attr).await
}

pub async fn account_get_id_radius_token(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();

    let res = req
        .state()
        .qe_r_ref
        .handle_internalradiustokenread(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_post_id_person_extend(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let (eventid, hvalue) = new_eventid!();
    let res = req
        .state()
        .qe_w_ref
        .handle_idmaccountpersonextend(uat, uuid_or_name, eventid)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

pub async fn account_post_id_unix(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let obj: AccountUnixExtend = req.body_json().await?;
    let (eventid, hvalue) = new_eventid!();
    let res = req
        .state()
        .qe_w_ref
        .handle_idmaccountunixextend(uat, uuid_or_name, obj, eventid)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

pub async fn account_get_id_unix_token(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();

    let res = req
        .state()
        .qe_r_ref
        .handle_internalunixusertokenread(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_post_id_unix_auth(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let obj: SingleStringRequest = req.body_json().await?;
    let cred = obj.value;
    let (eventid, hvalue) = new_eventid!();
    let res = req
        .state()
        .qe_r_ref
        .handle_idmaccountunixauth(uat, uuid_or_name, cred, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_put_id_unix_credential(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let obj: SingleStringRequest = req.body_json().await?;
    let cred = obj.value;
    let (eventid, hvalue) = new_eventid!();
    let res = req
        .state()
        .qe_w_ref
        .handle_idmaccountunixsetcred(uat, uuid_or_name, cred, eventid)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

pub async fn account_delete_id_unix_credential(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let attr = "unix_password".to_string();
    let filter = filter_all!(f_eq("class", PartialValue::new_class("posixaccount")));

    let (eventid, hvalue) = new_eventid!();

    let res = req
        .state()
        .qe_w_ref
        .handle_purgeattribute(uat, uuid_or_name, attr, filter, eventid)
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
    let uuid_or_name = req.get_url_param("id")?;
    let obj: GroupUnixExtend = req.body_json().await?;
    let (eventid, hvalue) = new_eventid!();
    let res = req
        .state()
        .qe_w_ref
        .handle_idmgroupunixextend(uat, uuid_or_name, obj, eventid)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

pub async fn group_get_id_unix_token(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = new_eventid!();

    let res = req
        .state()
        .qe_r_ref
        .handle_internalunixgrouptokenread(uat, uuid_or_name, eventid)
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

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsearchrecycled(uat, filter, attrs, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn recycle_bin_id_get(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let filter = filter_all!(f_id(id.as_str()));
    let attrs = None;

    let (eventid, hvalue) = new_eventid!();

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsearchrecycled(uat, filter, attrs, eventid)
        .await
        .map(|mut r| r.pop());
    to_tide_response(res, hvalue)
}

pub async fn recycle_bin_revive_id_post(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;
    let filter = filter_all!(f_id(id.as_str()));

    let (eventid, hvalue) = new_eventid!();
    let res = req
        .state()
        .qe_w_ref
        .handle_reviverecycled(uat, filter, eventid)
        .await
        .map(|()| true);
    to_tide_response(res, hvalue)
}

pub async fn do_nothing(_req: tide::Request<AppState>) -> tide::Result {
    let mut res = tide::Response::new(200);
    res.set_body("did nothing");
    Ok(res)
}

pub async fn auth(mut req: tide::Request<AppState>) -> tide::Result {
    // First, deal with some state management.
    // Do anything here first that's needed like getting the session details
    // out of the req cookie.
    let (eventid, hvalue) = new_eventid!();

    let maybe_sessionid = req.get_current_auth_session_id();
    debug!("🍿 {:?}", maybe_sessionid);

    let obj: AuthRequest = req.body_json().await.map_err(|e| {
        debug!("wat? {:?}", e);
        e
    })?;

    let mut auth_session_id_tok = None;

    // We probably need to know if we allocate the cookie, that this is a
    // new session, and in that case, anything *except* authrequest init is
    // invalid.
    let res: Result<AuthResponse, _> = match req
        .state()
        // This may change in the future ...
        .qe_r_ref
        .handle_auth(maybe_sessionid, obj, eventid)
        .await
    {
        // .and_then(|ar| {
        Ok(ar) => {
            let AuthResult {
                state,
                sessionid,
                delay,
            } = ar;
            // If there is a delay, honour it now.
            if let Some(delay_timer) = delay {
                task::sleep(delay_timer).await;
            }
            // Do some response/state management.
            match state {
                AuthState::Choose(allowed) => {
                    debug!("🧩 -> AuthState::Choose");
                    let msession = req.session_mut();

                    // Ensure the auth-session-id is set
                    msession.remove("auth-session-id");
                    msession
                        .insert("auth-session-id", sessionid)
                        .map_err(|_| OperationError::InvalidSessionState)
                        .and_then(|_| {
                            let kref = &req.state().fernet_handle;
                            // Get the header token ready.
                            serde_json::to_vec(&sessionid)
                                .map(|data| {
                                    auth_session_id_tok = Some(kref.encrypt(&data));
                                })
                                .map_err(|_| OperationError::InvalidSessionState)
                        })
                        .map(|_| ProtoAuthState::Choose(allowed))
                }
                AuthState::Continue(allowed) => {
                    debug!("🧩 -> AuthState::Continue");
                    let msession = req.session_mut();
                    // Ensure the auth-session-id is set
                    msession.remove("auth-session-id");
                    msession
                        .insert("auth-session-id", sessionid)
                        .map_err(|_| OperationError::InvalidSessionState)
                        .and_then(|_| {
                            let kref = &req.state().fernet_handle;
                            // Get the header token ready.
                            serde_json::to_vec(&sessionid)
                                .map(|data| {
                                    auth_session_id_tok = Some(kref.encrypt(&data));
                                })
                                .map_err(|_| OperationError::InvalidSessionState)
                        })
                        .map(|_| ProtoAuthState::Continue(allowed))
                }
                AuthState::Success(uat) => {
                    debug!("🧩 -> AuthState::Success");
                    // Remove the auth-session-id
                    let msession = req.session_mut();
                    msession.remove("auth-session-id");
                    // Create the string "Bearer <token>"
                    let kref = &req.state().fernet_handle;
                    serde_json::to_vec(&uat)
                        .map(|data| {
                            let tok = kref.encrypt(&data);
                            ProtoAuthState::Success(tok)
                        })
                        .map_err(|_| OperationError::InvalidSessionState)
                }
                AuthState::Denied(reason) => {
                    debug!("🧩 -> AuthState::Denied");
                    let msession = req.session_mut();
                    // Remove the auth-session-id
                    msession.remove("auth-session-id");
                    Ok(ProtoAuthState::Denied(reason))
                }
            }
            .map(|state| AuthResponse { sessionid, state })
        }
        Err(e) => Err(e),
    };

    to_tide_response(res, hvalue).map(|mut res| {
        // if the sessionid was injected into our cookie, set it in the
        // header too.
        if let Some(tok) = auth_session_id_tok {
            res.insert_header("X-KANIDM-AUTH-SESSION-ID", tok);
        }
        res
    })
}

pub async fn idm_account_set_password(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let obj: SingleStringRequest = req.body_json().await?;
    let cleartext = obj.value;
    let (eventid, hvalue) = new_eventid!();
    let res = req
        .state()
        .qe_w_ref
        .handle_idmaccountsetpassword(uat, cleartext, eventid)
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
    role: ServerRole,
    cookie_key: &[u8; 32],
    status_ref: &'static StatusActor,
    qe_w_ref: &'static QueryServerWriteV1,
    qe_r_ref: &'static QueryServerReadV1,
) -> Result<(), ()> {
    info!("WEB_UI_PKG_PATH -> {}", env!("KANIDM_WEB_UI_PKG_PATH"));

    // Create the in memory fernet key
    let fernet_handle = fernet::Fernet::new(&fernet::Fernet::generate_key()).ok_or_else(|| {
        error!("Failed to generate fernet key");
    })?;

    let mut tserver = tide::Server::with_state(AppState {
        status_ref,
        qe_w_ref,
        qe_r_ref,
        fernet_handle,
    });

    // Add middleware?
    tserver.with(tide::log::LogMiddleware::new()).with(
        tide::sessions::SessionMiddleware::new(tide::sessions::MemoryStore::new(), cookie_key)
            .with_cookie_name("kanidm-session")
            .with_same_site_policy(tide::http::cookies::SameSite::Strict)
            .with_session_ttl(Some(Duration::from_secs(3600))),
    );

    // Add routes

    // If we are no-ui, we remove this.
    if !matches!(role, ServerRole::WriteReplicaNoUI) {
        tserver.at("/").get(index_view);
        tserver
            .at("/pkg")
            .serve_dir(env!("KANIDM_WEB_UI_PKG_PATH"))
            .map_err(|e| {
                error!(
                    "Failed to serve pkg dir {} -> {:?}",
                    env!("KANIDM_WEB_UI_PKG_PATH"),
                    e
                );
            })?;
    };

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
        .at("/:id/_credential/_status")
        .get(account_get_id_credential_status);
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
        .delete(group_id_delete_attr)
        .get(group_id_get_attr)
        .put(group_id_put_attr)
        .post(group_id_post_attr);
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
                .addrs(&address)
                .cert(&tls_param.chain)
                .key(&tls_param.key)
                .finish()
                .map_err(|e| {
                    error!("Failed to build TLS Listener -> {:?}", e);
                })?;
            /*
            let x = Box::new(tls_param.build());
            let x_ref = Box::leak(x);
            let tlsl = TlsListener::new(address, x_ref);
            */

            tokio::spawn(async move {
                if let Err(e) = tserver.listen(tlsl).await {
                    error!(
                        "Failed to start server listener on address {:?} -> {:?}",
                        &address, e
                    );
                }
            });
        }
        None => {
            // Create without https
            tokio::spawn(async move {
                if let Err(e) = tserver.listen(&address).await {
                    error!(
                        "Failed to start server listener on address {:?} -> {:?}",
                        &address, e,
                    );
                }
            });
        }
    };
    Ok(())
}
