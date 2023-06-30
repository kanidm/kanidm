use super::routemaps::{RouteMap, RouteMaps};
use super::{to_tide_response, AppState, RequestExtensions};
use kanidm_proto::scim_v1::ScimSyncRequest;
use kanidm_proto::v1::Entry as ProtoEntry;
use kanidmd_lib::prelude::*;

use super::v1::{json_rest_event_get, json_rest_event_get_id, json_rest_event_post};

pub async fn sync_account_get(State(state): State<ServerState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("sync_account")));
    json_rest_event_get(req, filter, None).await
}

pub async fn sync_account_post(State(state): State<ServerState>) -> tide::Result {
    let classes = vec!["sync_account".to_string(), "object".to_string()];
    json_rest_event_post(req, classes).await
}

pub async fn sync_account_id_get(State(state): State<ServerState>) -> tide::Result {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("sync_account")));
    json_rest_event_get_id(req, filter, None).await
}

pub async fn sync_account_id_patch(State(state): State<ServerState>) -> tide::Result {
    // Update a value / attrs
    let uat = req.get_current_uat();
    let id = req.get_url_param("id")?;

    let obj: ProtoEntry = req.body_json().await?;

    let filter = filter_all!(f_eq("class", PartialValue::new_class("sync_account")));
    let filter = Filter::join_parts_and(filter, filter_all!(f_id(id.as_str())));

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_internalpatch(uat, filter, obj, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn sync_account_id_get_finalise(State(state): State<ServerState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_sync_account_finalise(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn sync_account_id_get_terminate(State(state): State<ServerState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_sync_account_terminate(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn sync_account_token_post(State(state): State<ServerState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let label: String = req.body_json().await?;

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_sync_account_token_generate(uat, uuid_or_name, label, eventid)
        .await;
    to_tide_response(res, hvalue)
}

pub async fn sync_account_token_delete(State(state): State<ServerState>) -> tide::Result {
    let uat = req.get_current_uat();
    let uuid_or_name = req.get_url_param("id")?;

    let (eventid, hvalue) = req.new_eventid();

    let res = req
        .state()
        .qe_w_ref
        .handle_sync_account_token_destroy(uat, uuid_or_name, eventid)
        .await;
    to_tide_response(res, hvalue)
}

async fn scim_sync_post(State(state): State<ServerState>) -> tide::Result {
    let (eventid, hvalue) = req.new_eventid();

    // Given the token, and a sync update, apply the changes if any
    let bearer = req.get_auth_bearer();

    // Change this type later.
    let changes: ScimSyncRequest = req.body_json().await?;

    let res = req
        .state()
        .qe_w_ref
        .handle_scim_sync_apply(bearer, changes, eventid)
        .await;
    to_tide_response(res, hvalue)
}

async fn scim_sync_get(State(state): State<ServerState>) -> tide::Result {
    let (eventid, hvalue) = req.new_eventid();

    // Given the token, what is it's connected sync state?
    let bearer = req.get_auth_bearer();
    trace!(?bearer);

    let res = req
        .state()
        .qe_r_ref
        .handle_scim_sync_status(bearer, eventid)
        .await;
    to_tide_response(res, hvalue)
}

async fn scim_sink_get(State(state): State<ServerState>) -> tide::Result {
    let (_, hvalue) = req.new_eventid();
    let mut res = tide::Response::new(200);

    res.insert_header("X-KANIDM-OPID", hvalue);
    res.set_content_type("text/html;charset=utf-8");

    res.set_body(
        r#"
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8"/>
        <meta name="theme-color" content="white" />
        <meta name="viewport" content="width=device-width" />
        <title>Sink!</title>
        <link rel="icon" href="/pkg/img/favicon.png" />
        <link rel="manifest" href="/manifest.webmanifest" />
    </head>
    <body>
        <pre>
                    ___
                  .' _ '.
                 / /` `\ \
                 | |   [__]
                 | |    {{
                 | |    }}
              _  | |  _ {{
  ___________<_>_| |_<_>}}________
      .=======^=(___)=^={{====.
     / .----------------}}---. \
    / /                 {{    \ \
   / /                  }}     \ \
  (  '========================='  )
   '-----------------------------'
        </pre>
    </body>
</html>"#,
    );

    Ok(res)
}

pub fn scim_route_setup(appserver: &mut tide::Route<'_, AppState>, routemap: &mut RouteMap) {
    let mut scim_process = appserver.at("/scim/v1");

    // https://datatracker.ietf.org/doc/html/rfc7644#section-3.2
    //
    //  HTTP   SCIM Usage
    //  Method
    //  ------ --------------------------------------------------------------
    //  GET    Retrieves one or more complete or partial resources.
    //
    //  POST   Depending on the endpoint, creates new resources, creates a
    //         search request, or MAY be used to bulk-modify resources.
    //
    //  PUT    Modifies a resource by replacing existing attributes with a
    //         specified set of replacement attributes (replace).  PUT
    //         MUST NOT be used to create new resources.
    //
    //  PATCH  Modifies a resource with a set of client-specified changes
    //         (partial update).
    //
    //  DELETE Deletes a resource.
    //
    //  Resource Endpoint         Operations             Description
    //  -------- ---------------- ---------------------- --------------------
    //  User     /Users           GET (Section 3.4.1),   Retrieve, add,
    //                            POST (Section 3.3),    modify Users.
    //                            PUT (Section 3.5.1),
    //                            PATCH (Section 3.5.2),
    //                            DELETE (Section 3.6)
    //
    //  Group    /Groups          GET (Section 3.4.1),   Retrieve, add,
    //                            POST (Section 3.3),    modify Groups.
    //                            PUT (Section 3.5.1),
    //                            PATCH (Section 3.5.2),
    //                            DELETE (Section 3.6)
    //
    //  Self     /Me              GET, POST, PUT, PATCH, Alias for operations
    //                            DELETE (Section 3.11)  against a resource
    //                                                   mapped to an
    //                                                   authenticated
    //                                                   subject (e.g.,
    //                                                   User).
    //
    //  Service  /ServiceProvider GET (Section 4)        Retrieve service
    //  provider Config                                  provider's
    //  config.                                          configuration.
    //
    //  Resource /ResourceTypes   GET (Section 4)        Retrieve supported
    //  type                                             resource types.
    //
    //  Schema   /Schemas         GET (Section 4)        Retrieve one or more
    //                                                   supported schemas.
    //
    //  Bulk     /Bulk            POST (Section 3.7)     Bulk updates to one
    //                                                   or more resources.
    //
    //  Search   [prefix]/.search POST (Section 3.4.3)   Search from system
    //                                                   root or within a
    //                                                   resource endpoint
    //                                                   for one or more
    //                                                   resource types using
    //                                                   POST.
    //  -- Kanidm Resources
    //
    //  Sync     /Sync            GET                    Retrieve the current
    //                                                   sync state associated
    //                                                   with the authenticated
    //                                                   session
    //
    //                            POST                   Send a sync update
    //

    scim_process
        .at("/Sync")
        .mapped_post(routemap, scim_sync_post)
        .mapped_get(routemap, scim_sync_get);

    scim_process.at("/Sink").mapped_get(routemap, scim_sink_get);

    let mut sync_account_route = appserver.at("/v1/sync_account");
    sync_account_route
        .at("/")
        .mapped_get(routemap, sync_account_get)
        .mapped_post(routemap, sync_account_post);

    sync_account_route
        .at("/:id")
        .mapped_get(routemap, sync_account_id_get)
        .mapped_patch(routemap, sync_account_id_patch);

    sync_account_route
        .at("/:id/_finalise")
        .mapped_get(routemap, sync_account_id_get_finalise);

    sync_account_route
        .at("/:id/_terminate")
        .mapped_get(routemap, sync_account_id_get_terminate);

    sync_account_route
        .at("/:id/_sync_token")
        // .mapped_get(&mut routemap, sync_account_token_get)
        .mapped_post(routemap, sync_account_token_post)
        .mapped_delete(routemap, sync_account_token_delete);
}
