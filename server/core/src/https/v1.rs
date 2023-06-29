use std::str::FromStr;
use std::time::Duration;

use compact_jwt::Jws;
use kanidm_proto::v1::{
    AccountUnixExtend, ApiTokenGenerate, AuthIssueSession, AuthRequest, AuthResponse,
    AuthState as ProtoAuthState, CUIntentToken, CURequest, CUSessionToken, CreateRequest,
    DeleteRequest, Entry as ProtoEntry, GroupUnixExtend, ModifyRequest, OperationError,
    SearchRequest, SingleStringRequest,
};
use kanidmd_lib::filter::{Filter, FilterInvalid};
use kanidmd_lib::idm::event::AuthResult;
use kanidmd_lib::idm::AuthState;
use kanidmd_lib::prelude::*;
use kanidmd_lib::status::StatusRequestEvent;
use serde::{Deserialize, Serialize};

use super::{to_tide_response, AppState, RequestExtensions, RouteMap};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct SessionId {
    pub sessionid: Uuid,
}

pub async fn create(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    // parse the req to a CreateRequest
    let msg: CreateRequest = req.body_json().await?;

    let (eventid, hvalue) = req.new_eventid();

    let res = req.state().qe_w_ref.handle_create(uat, msg, eventid).await;
    to_tide_response(res, hvalue)
}

pub async fn modify(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let msg: ModifyRequest = req.body_json().await?;
    let (eventid, hvalue) = req.new_eventid();
    let res = req.state().qe_w_ref.handle_modify(uat, msg, eventid).await;
    to_tide_response(res, hvalue)
}

pub async fn delete(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let msg: DeleteRequest = req.body_json().await?;
    let (eventid, hvalue) = req.new_eventid();
    let res = req.state().qe_w_ref.handle_delete(uat, msg, eventid).await;
    to_tide_response(res, hvalue)
}

pub async fn search(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let msg: SearchRequest = req.body_json().await?;
    let (eventid, hvalue) = req.new_eventid();
    let res = req.state().qe_r_ref.handle_search(uat, msg, eventid).await;
    to_tide_response(res, hvalue)
}

pub async fn whoami(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let (eventid, hvalue) = req.new_eventid();
    // New event, feed current auth data from the token to it.
    let res = req.state().qe_r_ref.handle_whoami(uat, eventid).await;
    to_tide_response(res, hvalue)
}

pub async fn whoami_uat(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let (eventid, hvalue) = req.new_eventid();
    let res = req.state().qe_r_ref.handle_whoami_uat(uat, eventid).await;
    to_tide_response(res, hvalue)
}

pub async fn logout(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let (eventid, hvalue) = req.new_eventid();

    // Now lets nuke any cookies for the session. We do this before the handle_logout
    // so that if any errors occur, the cookies are still removed.
    let msession = req.session_mut();
    msession.remove("auth-session-id");
    msession.remove("bearer");

    let res = req.state().qe_w_ref.handle_logout(uat, eventid).await;

    to_tide_response(res, hvalue)
}

// =============== REST generics ========================

pub async fn json_rest_event_get(
    req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
    attrs: Option<Vec<String>>,
) -> tide::Result {
    let uat = req.get_current_uat();

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsearch(uat, filter, attrs, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn json_rest_event_get_id(
    req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
    attrs: Option<Vec<String>>,
) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_r_ref
        .handle_internalsearch(uat, filter, attrs, eventid)
        .await
        .map(|mut r| r.pop());
    to_tide_response(res, hvalue)
}

pub async fn json_rest_event_delete_id(
    req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
) -> tide::Result {
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));
    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_internaldelete(uat, filter, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn json_rest_event_get_attr(
    req: tide::Request<AppState>,
    id: &str,
    filter: Filter<FilterInvalid>,
) -> tide::Result {
    let attr = req.get_url_param("attr")?;
    let uat = req.get_current_uat();
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id)));

    let (eventid, hvalue) = req.new_eventid();

    let attrs = Some(vec![attr.clone()]);

    let res: Result<Option<_>, _> = req
        .state()
        .qe_r_ref
        .handle_internalsearch(uat, filter, attrs, eventid)
        .await
        .map(|mut event_result| event_result.pop().and_then(|mut e| e.attrs.remove(&attr)));
    to_tide_response(res, hvalue)
}

pub async fn json_rest_event_get_id_attr(
    req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
) -> tide::Result {
    let id = req.get_url_param("id")?;
    json_rest_event_get_attr(req, id.as_str(), filter).await
}

pub async fn json_rest_event_post(
    mut req: tide::Request<AppState>,
    classes: Vec<String>,
) -> tide::Result {
    debug_assert!(!classes.is_empty());
    let (eventid, hvalue) = req.new_eventid();
    // Read the json from the wire.
    let uat = req.get_current_uat();
    let mut obj: ProtoEntry = req.body_json().await?;
    obj.attrs.insert("class".to_string(), classes);
    let msg = CreateRequest { entries: vec![obj] };

    let res = req.state().qe_w_ref.handle_create(uat, msg, eventid).await;
    to_tide_response(res, hvalue)
}

pub async fn json_rest_event_post_id_attr(
    mut req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let attr = req.get_url_param("attr")?;
    let values: Vec<String> = req.body_json().await?;
    let (eventid, hvalue) = req.new_eventid();
    let res = req
        .state()
        .qe_w_ref
        .handle_appendattribute(uat, uuid_or_name, attr, values, filter, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn json_rest_event_put_attr(
    mut req: tide::Request<AppState>,
    uuid_or_name: String,
    filter: Filter<FilterInvalid>,
) -> tide::Result {
    let uat = req.get_current_uat();
    let attr = req.get_url_param("attr")?;
    let values: Vec<String> = req.body_json().await?;

    let (eventid, hvalue) = req.new_eventid();
    let res = req
        .state()
        .qe_w_ref
        .handle_setattribute(uat, uuid_or_name, attr, values, filter, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn json_rest_event_post_attr(
    mut req: tide::Request<AppState>,
    uuid_or_name: String,
    filter: Filter<FilterInvalid>,
) -> tide::Result {
    let uat = req.get_current_uat();
    let attr = req.get_url_param("attr")?;
    let values: Vec<String> = req.body_json().await?;

    let (eventid, hvalue) = req.new_eventid();
    let res = req
        .state()
        .qe_w_ref
        .handle_appendattribute(uat, uuid_or_name, attr, values, filter, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn json_rest_event_put_id_attr(
    req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
) -> tide::Result {
    let uuid_or_name = req.get_url_param("id")?;
    json_rest_event_put_attr(req, uuid_or_name, filter).await
}

pub async fn json_rest_event_delete_id_attr(
    req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
    attr: String,
) -> tide::Result {
    let uuid_or_name = req.get_url_param("id")?;
    json_rest_event_delete_attr(req, filter, uuid_or_name, attr).await
}

pub async fn json_rest_event_delete_attr(
    mut req: tide::Request<AppState>,
    filter: Filter<FilterInvalid>,
    uuid_or_name: String,
    // Separate for account_delete_id_radius
    attr: String,
) -> tide::Result {
    let uat = req.get_current_uat();
    let (eventid, hvalue) = req.new_eventid();

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
            .await;
        to_tide_response(res, hvalue)
    } else {
        let res = req
            .state()
            .qe_w_ref
            .handle_removeattributevalues(uat, uuid_or_name, attr, values, filter, eventid)
            .await;
        to_tide_response(res, hvalue)
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

    let (eventid, hvalue) = req.new_eventid();

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

    let (eventid, hvalue) = req.new_eventid();

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

// expects the following fields in the attrs field of the req: [name, displayname]
pub async fn person_post(req: tide::Request<AppState>) -> tide::Result {
    let classes = vec![
        "person".to_string(),
        "account".to_string(),
        "object".to_string(),
    ];
    json_rest_event_post(req, classes).await
}

pub async fn person_id_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
    json_rest_event_get_id(req, filter, None).await
}

pub async fn person_account_id_delete(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("person")));
    json_rest_event_delete_id(req, filter).await
}

// == account ==

pub async fn service_account_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("service_account")));
    json_rest_event_get(req, filter, None).await
}

pub async fn service_account_post(req: tide::Request<AppState>) -> tide::Result {
    let classes = vec![
        "service_account".to_string(),
        "account".to_string(),
        "object".to_string(),
    ];
    json_rest_event_post(req, classes).await
}

pub async fn service_account_id_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("service_account")));
    json_rest_event_get_id(req, filter, None).await
}

pub async fn service_account_id_delete(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("service_account")));
    json_rest_event_delete_id(req, filter).await
}

pub async fn service_account_credential_generate(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_service_account_credential_generate(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

// Due to how the migrations work in 6 -> 7, we can accidentally
// mark "accounts" as service accounts when they are persons. This
// allows migrating them to the person type due to it's similarities.
//
// In the future this will be REMOVED!
pub async fn service_account_into_person(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_service_account_into_person(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

// Api Token
pub async fn service_account_api_token_get(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_r_ref
        .handle_service_account_api_token_get(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn service_account_api_token_post(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let ApiTokenGenerate {
        label,
        expiry,
        read_write,
    } = req.body_json().await?;

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_service_account_api_token_generate(
            uat,
            uuid_or_name,
            label,
            expiry,
            read_write,
            eventid,
        )
        .await;
    to_tide_response(res, hvalue)
}

pub async fn service_account_api_token_delete(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let token_id = req.get_url_param_uuid("token_id")?;

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_service_account_api_token_destroy(uat, uuid_or_name, token_id, eventid)
        .await;
    to_tide_response(res, hvalue)
}

// Account stuff
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

pub async fn account_id_patch(mut req: tide::Request<AppState>) -> tide::Result {
    // Update a value / attrs
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let obj: ProtoEntry = req.body_json().await?;

    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_internalpatch(uat, filter, obj, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_get_id_credential_update(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_idmcredentialupdate(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_get_id_credential_update_intent(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let ttl = req
        .param("ttl")
        .ok()
        .and_then(|s| {
            u64::from_str(s)
                .map_err(|_e| {
                    error!("Invalid TTL integer, ignoring.");
                })
                .ok()
        })
        .map(Duration::from_secs);

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_idmcredentialupdateintent(uat, uuid_or_name, ttl, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_get_id_user_auth_token(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_r_ref
        .handle_account_user_auth_token_get(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_user_auth_token_delete(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let token_id = req.get_url_param_uuid("token_id")?;

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_account_user_auth_token_destroy(uat, uuid_or_name, token_id, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn credential_update_exchange_intent(mut req: tide::Request<AppState>) -> tide::Result {
    let (eventid, hvalue) = req.new_eventid();
    let intent_token: CUIntentToken = req.body_json().await?;

    let res = req
        .state()
        .qe_w_ref
        .handle_idmcredentialexchangeintent(intent_token, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn credential_update_status(mut req: tide::Request<AppState>) -> tide::Result {
    let (eventid, hvalue) = req.new_eventid();
    let session_token: CUSessionToken = req.body_json().await?;

    let res = req
        .state()
        .qe_r_ref
        .handle_idmcredentialupdatestatus(session_token, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn credential_update_update(mut req: tide::Request<AppState>) -> tide::Result {
    let (eventid, hvalue) = req.new_eventid();
    let (scr, session_token): (CURequest, CUSessionToken) = req.body_json().await?;

    let res = req
        .state()
        .qe_r_ref
        .handle_idmcredentialupdate(session_token, scr, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn credential_update_commit(mut req: tide::Request<AppState>) -> tide::Result {
    let (eventid, hvalue) = req.new_eventid();
    let session_token: CUSessionToken = req.body_json().await?;

    let res = req
        .state()
        .qe_w_ref
        .handle_idmcredentialupdatecommit(session_token, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn credential_update_cancel(mut req: tide::Request<AppState>) -> tide::Result {
    let (eventid, hvalue) = req.new_eventid();
    let session_token: CUSessionToken = req.body_json().await?;

    let res = req
        .state()
        .qe_w_ref
        .handle_idmcredentialupdatecancel(session_token, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_get_id_credential_status(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = req.new_eventid();

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

    let (eventid, hvalue) = req.new_eventid();

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

    let (eventid, hvalue) = req.new_eventid();
    // Add a msg here
    let res = req
        .state()
        .qe_w_ref
        .handle_sshkeycreate(uat, uuid_or_name, tag, key, filter, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_get_id_ssh_pubkey_tag(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let tag = req.get_url_param("tag")?;

    let (eventid, hvalue) = req.new_eventid();

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

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_removeattributevalues(uat, uuid_or_name, attr, values, filter, eventid)
        .await;
    to_tide_response(res, hvalue)
}

// Get and return a single str
pub async fn account_get_id_radius(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = req.new_eventid();

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

    let (eventid, hvalue) = req.new_eventid();

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

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_r_ref
        .handle_internalradiustokenread(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_post_id_unix(mut req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let obj: AccountUnixExtend = req.body_json().await?;
    let (eventid, hvalue) = req.new_eventid();
    let res = req
        .state()
        .qe_w_ref
        .handle_idmaccountunixextend(uat, uuid_or_name, obj, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_get_id_unix_token(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = req.new_eventid();

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
    let (eventid, hvalue) = req.new_eventid();
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
    let (eventid, hvalue) = req.new_eventid();
    let res = req
        .state()
        .qe_w_ref
        .handle_idmaccountunixsetcred(uat, uuid_or_name, cred, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn account_delete_id_unix_credential(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;
    let attr = "unix_password".to_string();
    let filter = filter_all!(f_eq("class", PartialValue::new_class("posixaccount")));

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_purgeattribute(uat, uuid_or_name, attr, filter, eventid)
        .await;
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
    let (eventid, hvalue) = req.new_eventid();
    let res = req
        .state()
        .qe_w_ref
        .handle_idmgroupunixextend(uat, uuid_or_name, obj, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn group_get_id_unix_token(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_r_ref
        .handle_internalunixgrouptokenread(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn domain_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("uuid", PartialValue::Uuid(UUID_DOMAIN_INFO)));
    json_rest_event_get(req, filter, None).await
}

pub async fn domain_get_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_get_attr(req, STR_UUID_DOMAIN_INFO, filter).await
}

pub async fn domain_put_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    json_rest_event_put_attr(req, STR_UUID_DOMAIN_INFO.to_string(), filter).await
}

pub async fn domain_delete_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("domain_info")));
    let attr = req.get_url_param("attr")?;
    json_rest_event_delete_attr(req, filter, STR_UUID_DOMAIN_INFO.to_string(), attr).await
}

pub async fn system_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("uuid", PartialValue::Uuid(UUID_SYSTEM_CONFIG)));
    json_rest_event_get(req, filter, None).await
}

pub async fn system_get_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("system_config")));
    json_rest_event_get_attr(req, STR_UUID_SYSTEM_CONFIG, filter).await
}

pub async fn system_post_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("system_config")));
    json_rest_event_post_attr(req, STR_UUID_SYSTEM_CONFIG.to_string(), filter).await
}

pub async fn system_delete_attr(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("system_config")));
    let attr = req.get_url_param("attr")?;
    json_rest_event_delete_attr(req, filter, STR_UUID_SYSTEM_CONFIG.to_string(), attr).await
}

pub async fn recycle_bin_get(req: tide::Request<AppState>) -> tide::Result {
    let filter = filter_all!(f_pres("class"));
    let uat = req.get_current_uat();
    let attrs = None;

    let (eventid, hvalue) = req.new_eventid();

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

    let (eventid, hvalue) = req.new_eventid();

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

    let (eventid, hvalue) = req.new_eventid();
    let res = req
        .state()
        .qe_w_ref
        .handle_reviverecycled(uat, filter, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn applinks_get(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let (eventid, hvalue) = req.new_eventid();
    let res = req
        .state()
        .qe_r_ref
        .handle_list_applinks(uat, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn do_routemap(req: tide::Request<RouteMap>) -> tide::Result {
    let mut res = tide::Response::new(200);

    res.set_body(req.state().do_map());
    Ok(res)
}

// pub async fn do_nothing(_req: tide::Request<AppState>) -> tide::Result {
//     let mut res = tide::Response::new(200);
//     res.set_body("did nothing");
//     Ok(res)
// }

pub async fn reauth(mut req: tide::Request<AppState>) -> tide::Result {
    // check that we can get the remote IP address first, since this doesn't touch the backend at all
    let ip_addr = req.get_remote_addr().ok_or_else(|| {
        error!("Unable to get remote addr for auth event, refusing to proceed");
        tide::Error::from_str(
            tide::StatusCode::InternalServerError,
            "unable to validate peer address",
        )
    })?;

    let uat = req.get_current_uat();
    let (eventid, hvalue) = req.new_eventid();

    let obj: AuthIssueSession = req.body_json().await.map_err(|e| {
        debug!("Failed get body JSON? {:?}", e);
        e
    })?;

    let inter = req
        .state()
        // This may change in the future ...
        .qe_r_ref
        .handle_reauth(uat, obj, eventid, ip_addr)
        .await;

    auth_session_state_management(req, inter, hvalue)
}

pub async fn auth(mut req: tide::Request<AppState>) -> tide::Result {
    // check that we can get the remote IP address first, since this doesn't touch the backend at all
    let ip_addr = req.get_remote_addr().ok_or_else(|| {
        error!("Unable to get remote addr for auth event, refusing to proceed");
        tide::Error::from_str(
            tide::StatusCode::InternalServerError,
            "unable to validate peer address",
        )
    })?;
    // First, deal with some state management.
    // Do anything here first that's needed like getting the session details
    // out of the req cookie.
    let (eventid, hvalue) = req.new_eventid();

    let maybe_sessionid: Option<Uuid> = req.get_current_auth_session_id();

    let obj: AuthRequest = req.body_json().await.map_err(|e| {
        debug!("Failed get body JSON? {:?}", e);
        e
    })?;

    // We probably need to know if we allocate the cookie, that this is a
    // new session, and in that case, anything *except* authrequest init is
    // invalid.
    let inter = req
        .state()
        // This may change in the future ...
        .qe_r_ref
        .handle_auth(maybe_sessionid, obj, eventid, ip_addr)
        .await;

    auth_session_state_management(req, inter, hvalue)
}

fn auth_session_state_management(
    mut req: tide::Request<AppState>,
    inter: Result<AuthResult, OperationError>,
    hvalue: String,
) -> tide::Result {
    let mut auth_session_id_tok = None;

    let res: Result<AuthResponse, _> = match inter {
        Ok(AuthResult { state, sessionid }) => {
            // Do some response/state management.
            match state {
                AuthState::Choose(allowed) => {
                    debug!("🧩 -> AuthState::Choose");
                    let msession = req.session_mut();

                    // Ensure the auth-session-id is set
                    msession.remove("auth-session-id");
                    msession
                        .insert("auth-session-id", sessionid)
                        .map_err(|e| {
                            error!(?e);
                            OperationError::InvalidSessionState
                        })
                        .and_then(|_| {
                            let kref = &req.state().jws_signer;

                            let jws = Jws::new(SessionId { sessionid });
                            // Get the header token ready.
                            jws.sign(kref)
                                .map(|jwss| {
                                    auth_session_id_tok = Some(jwss.to_string());
                                })
                                .map_err(|e| {
                                    error!(?e);
                                    OperationError::InvalidSessionState
                                })
                        })
                        .map(|_| ProtoAuthState::Choose(allowed))
                }
                AuthState::Continue(allowed) => {
                    debug!("🧩 -> AuthState::Continue");
                    let msession = req.session_mut();
                    // Ensure the auth-session-id is set
                    msession.remove("auth-session-id");
                    trace!(?sessionid, "🔥  🔥 ");
                    msession
                        .insert("auth-session-id", sessionid)
                        .map_err(|e| {
                            error!(?e);
                            OperationError::InvalidSessionState
                        })
                        .and_then(|_| {
                            let kref = &req.state().jws_signer;
                            // Get the header token ready.
                            let jws = Jws::new(SessionId { sessionid });
                            jws.sign(kref)
                                .map(|jwss| {
                                    auth_session_id_tok = Some(jwss.to_string());
                                })
                                .map_err(|e| {
                                    error!(?e);
                                    OperationError::InvalidSessionState
                                })
                        })
                        .map(|_| ProtoAuthState::Continue(allowed))
                }
                AuthState::Success(token, issue) => {
                    debug!("🧩 -> AuthState::Success");
                    // Remove the auth-session-id
                    let msession = req.session_mut();
                    msession.remove("auth-session-id");
                    // Create a session cookie?
                    msession.remove("bearer");

                    match issue {
                        AuthIssueSession::Cookie => msession
                            .insert("bearer", token)
                            .map_err(|_| OperationError::InvalidSessionState)
                            .map(|_| ProtoAuthState::SuccessCookie),
                        AuthIssueSession::Token => Ok(ProtoAuthState::Success(token)),
                    }
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

pub async fn auth_valid(req: tide::Request<AppState>) -> tide::Result {
    let uat = req.get_current_uat();
    let (eventid, hvalue) = req.new_eventid();
    let res = req.state().qe_r_ref.handle_auth_valid(uat, eventid).await;
    to_tide_response(res, hvalue)
}

// == Status

pub async fn status(req: tide::Request<AppState>) -> tide::Result {
    // We ignore the body in this req
    let (eventid, hvalue) = req.new_eventid();
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
