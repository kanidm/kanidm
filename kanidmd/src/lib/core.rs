// use actix::SystemRunner;
use actix::Actor;
use actix_web::middleware::session::{self, RequestSession};
use actix_web::Path;
use actix_web::{
    error, http, middleware, App, Error, HttpMessage, HttpRequest, HttpResponse, Result, State,
};

use bytes::BytesMut;
use futures::{future, Future, Stream};
use std::sync::Arc;
use time::Duration;

use crate::config::Configuration;

// SearchResult
use crate::actors::v1_read::QueryServerReadV1;
use crate::actors::v1_read::{
    AuthMessage, InternalRadiusReadMessage, InternalRadiusTokenReadMessage, InternalSearchMessage,
    SearchMessage, WhoamiMessage,
};
use crate::actors::v1_write::QueryServerWriteV1;
use crate::actors::v1_write::{
    CreateMessage, DeleteMessage, IdmAccountSetPasswordMessage, InternalCredentialSetMessage,
    InternalRegenerateRadiusMessage, ModifyMessage, PurgeAttributeMessage,
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
use crate::utils::SID;
use crate::value::PartialValue;

use kanidm_proto::v1::OperationError;
use kanidm_proto::v1::{
    AuthRequest, AuthState, CreateRequest, DeleteRequest, ModifyRequest, SearchRequest,
    SetAuthCredential, SingleStringRequest, UserAuthToken,
};

use uuid::Uuid;

struct AppState {
    qe_r: actix::Addr<QueryServerReadV1>,
    qe_w: actix::Addr<QueryServerWriteV1>,
    max_size: usize,
}

fn get_current_user(req: &HttpRequest<AppState>) -> Option<UserAuthToken> {
    match req.session().get::<UserAuthToken>("uat") {
        Ok(maybe_uat) => maybe_uat,
        Err(_) => {
            // return Box::new(future::err(e));
            None
        }
    }
}

fn operation_error_to_response(e: OperationError) -> HttpResponse {
    match e {
        OperationError::NotAuthenticated => HttpResponse::Unauthorized().json(e),
        OperationError::AccessDenied | OperationError::SystemProtectedObject => {
            HttpResponse::Forbidden().json(e)
        }
        OperationError::EmptyRequest
        | OperationError::NoMatchingEntries
        | OperationError::SchemaViolation(_) => HttpResponse::BadRequest().json(e),
        _ => HttpResponse::InternalServerError().json(e),
    }
}

macro_rules! json_event_post {
    ($req:expr, $state:expr, $message_type:ty, $request_type:ty, $dest:expr) => {{
        // This is copied every request. Is there a better way?
        // The issue is the fold move takes ownership of state if
        // we don't copy this here
        let max_size = $state.max_size;

        // Get auth if any?
        let uat = get_current_user(&$req);

        // HttpRequest::payload() is stream of Bytes objects
        $req.payload()
            // `Future::from_err` acts like `?` in that it coerces the error type from
            // the future into the final error type
            .from_err()
            // `fold` will asynchronously read each chunk of the request body and
            // call supplied closure, then it resolves to result of closure
            .fold(BytesMut::new(), move |mut body, chunk| {
                // limit max size of in-memory payload
                if (body.len() + chunk.len()) > max_size {
                    Err(error::ErrorBadRequest("overflow"))
                } else {
                    body.extend_from_slice(&chunk);
                    Ok(body)
                }
            })
            // `Future::and_then` can be used to merge an asynchronous workflow with a
            // synchronous workflow
            .and_then(
                move |body| -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
                    // body is loaded, now we can deserialize serde-json
                    let r_obj = serde_json::from_slice::<$request_type>(&body);

                    // Send to the db for handling
                    match r_obj {
                        Ok(obj) => {
                            // combine request + uat -> message.
                            let m_obj = <($message_type)>::new(uat, obj);
                            let res = $dest
                                .send(m_obj)
                                // What is from_err?
                                .from_err()
                                .and_then(|res| match res {
                                    Ok(event_result) => Ok(HttpResponse::Ok().json(event_result)),
                                    Err(e) => Ok(operation_error_to_response(e)),
                                });

                            Box::new(res)
                        }
                        Err(e) => Box::new(future::err(error::ErrorBadRequest(format!(
                            "Json Decode Failed: {:?}",
                            e
                        )))),
                    } // end match
                }, // end closure
            ) // end and_then
    }};
}

macro_rules! json_event_get {
    ($req:expr, $state:expr, $message_type:ty) => {{
        // Get current auth data - remember, the QS checks if the
        // none/some is okay, because it's too hard to make it work here
        // with all the async parts.
        let uat = get_current_user(&$req);

        // New event, feed current auth data from the token to it.
        let obj = <($message_type)>::new(uat);

        let res = $state.qe_r.send(obj).from_err().and_then(|res| match res {
            Ok(event_result) => Ok(HttpResponse::Ok().json(event_result)),
            Err(e) => Ok(operation_error_to_response(e)),
        });

        Box::new(res)
    }};
}

// Handle the various end points we need to expose

fn create(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_event_post!(req, state, CreateMessage, CreateRequest, state.qe_w)
}

fn modify(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_event_post!(req, state, ModifyMessage, ModifyRequest, state.qe_w)
}

fn delete(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_event_post!(req, state, DeleteMessage, DeleteRequest, state.qe_w)
}

fn search(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_event_post!(req, state, SearchMessage, SearchRequest, state.qe_r)
}

fn whoami(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_event_get!(req, state, WhoamiMessage)
}

// =============== REST generics ========================

fn json_rest_event_get(
    req: HttpRequest<AppState>,
    state: State<AppState>,
    filter: Filter<FilterInvalid>,
    attrs: Option<Vec<String>>,
) -> impl Future<Item = HttpResponse, Error = Error> {
    let uat = get_current_user(&req);

    // TODO: I think we'll need to change this to take an internal filter
    // type that we send to the qs.
    let obj = InternalSearchMessage {
        uat: uat,
        filter: filter,
        attrs: attrs,
    };

    let res = state.qe_r.send(obj).from_err().and_then(|res| match res {
        Ok(event_result) => Ok(HttpResponse::Ok().json(event_result)),
        Err(e) => Ok(operation_error_to_response(e)),
    });

    Box::new(res)
}

fn json_rest_event_get_id(
    path: Path<String>,
    req: HttpRequest<AppState>,
    state: State<AppState>,
    filter: Filter<FilterInvalid>,
    attrs: Option<Vec<String>>,
) -> impl Future<Item = HttpResponse, Error = Error> {
    let uat = get_current_user(&req);

    let filter = Filter::join_parts_and(filter, filter_all!(f_id(path.as_str())));

    let obj = InternalSearchMessage {
        uat: uat,
        filter: filter,
        attrs: attrs,
    };

    let res = state.qe_r.send(obj).from_err().and_then(|res| match res {
        Ok(mut event_result) => {
            // Only send back the first result, or None
            Ok(HttpResponse::Ok().json(event_result.pop()))
        }
        Err(e) => Ok(operation_error_to_response(e)),
    });

    Box::new(res)
}

fn json_rest_event_get_id_attr(
    path: Path<String>,
    req: HttpRequest<AppState>,
    state: State<AppState>,
    filter: Filter<FilterInvalid>,
    attr: String,
) -> impl Future<Item = HttpResponse, Error = Error> {
    let uat = get_current_user(&req);

    let filter = Filter::join_parts_and(filter, filter_all!(f_id(path.as_str())));

    let obj = InternalSearchMessage {
        uat: uat,
        filter: filter,
        attrs: Some(vec![attr.clone()]),
    };

    let res = state
        .qe_r
        .send(obj)
        .from_err()
        .and_then(move |res| match res {
            Ok(mut event_result) => {
                // TODO: Check this only has len 1, even though that satte should be impossible.
                // Only get one result
                let r = event_result.pop().and_then(|mut e| {
                    // Only get the attribute as requested.
                    e.attrs.remove(&attr)
                });
                debug!("final json result {:?}", r);
                // Only send back the first result, or None
                Ok(HttpResponse::Ok().json(r))
            }
            Err(e) => Ok(operation_error_to_response(e)),
        });

    Box::new(res)
}

fn json_rest_event_delete_id_attr(
    path: Path<String>,
    req: HttpRequest<AppState>,
    state: State<AppState>,
    attr: String,
) -> impl Future<Item = HttpResponse, Error = Error> {
    let uat = get_current_user(&req);
    let id = path.into_inner();

    let obj = PurgeAttributeMessage {
        uat: uat,
        uuid_or_name: id,
        attr: attr,
    };

    let res = state.qe_w.send(obj).from_err().and_then(|res| match res {
        Ok(event_result) => {
            // Only send back the first result, or None
            Ok(HttpResponse::Ok().json(event_result))
        }
        Err(e) => Ok(operation_error_to_response(e)),
    });

    Box::new(res)
}

fn json_rest_event_credential_put(
    id: String,
    cred_id: Option<String>,
    req: HttpRequest<AppState>,
    state: State<AppState>,
) -> impl Future<Item = HttpResponse, Error = Error> {
    // what do we need here?
    //  * a filter of the id to match + class
    //  * the id of the credential
    //  * The SetAuthCredential
    //    * turn into a modlist

    // Copy the max size since we move it.
    let max_size = state.max_size;
    let uat = get_current_user(&req);

    req.payload()
        .from_err()
        .fold(BytesMut::new(), move |mut body, chunk| {
            // limit max size of in-memory payload
            if (body.len() + chunk.len()) > max_size {
                Err(error::ErrorBadRequest("overflow"))
            } else {
                body.extend_from_slice(&chunk);
                Ok(body)
            }
        })
        // `Future::and_then` can be used to merge an asynchronous workflow with a
        // synchronous workflow
        .and_then(
            move |body| -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
                let r_obj = serde_json::from_slice::<SetAuthCredential>(&body);

                match r_obj {
                    Ok(obj) => {
                        let m_obj = InternalCredentialSetMessage::new(uat, id, cred_id, obj);
                        let res = state.qe_w.send(m_obj).from_err().and_then(|res| match res {
                            Ok(event_result) => Ok(HttpResponse::Ok().json(event_result)),
                            Err(e) => Ok(operation_error_to_response(e)),
                        });

                        Box::new(res)
                    }
                    Err(e) => Box::new(future::err(error::ErrorBadRequest(format!(
                        "Json Decode Failed: {:?}",
                        e
                    )))),
                } // end match
            },
        ) // end and_then
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

fn schema_get(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    // NOTE: This is filter_all, because from_internal_message will still do the alterations
    // needed to make it safe. This is needed because there may be aci's that block access
    // to the recycle/ts types in the filter, and we need the aci to only eval on this
    // part of the filter!
    let filter = filter_all!(f_or!([
        f_eq("class", PartialValue::new_class("attributetype")),
        f_eq("class", PartialValue::new_class("classtype"))
    ]));
    json_rest_event_get(req, state, filter, None)
}

fn schema_attributetype_get(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("attributetype")));
    json_rest_event_get(req, state, filter, None)
}

fn schema_attributetype_get_id(
    (path, req, state): (Path<String>, HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    // These can't use get_id because they attribute name and class name aren't ... well name.
    let uat = get_current_user(&req);

    let filter = filter_all!(f_and!([
        f_eq("class", PartialValue::new_class("attributetype")),
        f_eq("attributename", PartialValue::new_iutf8s(path.as_str()))
    ]));

    let obj = InternalSearchMessage {
        uat: uat,
        filter: filter,
        attrs: None,
    };

    let res = state.qe_r.send(obj).from_err().and_then(|res| match res {
        Ok(mut event_result) => {
            // Only send back the first result, or None
            Ok(HttpResponse::Ok().json(event_result.pop()))
        }
        Err(e) => Ok(operation_error_to_response(e)),
    });

    Box::new(res)
}

fn schema_classtype_get(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("classtype")));
    json_rest_event_get(req, state, filter, None)
}

fn schema_classtype_get_id(
    (path, req, state): (Path<String>, HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    // These can't use get_id because they attribute name and class name aren't ... well name.
    let uat = get_current_user(&req);

    let filter = filter_all!(f_and!([
        f_eq("class", PartialValue::new_class("classtype")),
        f_eq("classname", PartialValue::new_iutf8s(path.as_str()))
    ]));

    let obj = InternalSearchMessage {
        uat: uat,
        filter: filter,
        attrs: None,
    };

    let res = state.qe_r.send(obj).from_err().and_then(|res| match res {
        Ok(mut event_result) => {
            // Only send back the first result, or None
            Ok(HttpResponse::Ok().json(event_result.pop()))
        }
        Err(e) => Ok(operation_error_to_response(e)),
    });

    Box::new(res)
}

fn account_get(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_get(req, state, filter, None)
}

fn account_get_id(
    (path, req, state): (Path<String>, HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("account")));
    json_rest_event_get_id(path, req, state, filter, None)
}

fn account_put_id_credential_primary(
    (path, req, state): (Path<String>, HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    let id = path.into_inner();
    json_rest_event_credential_put(id, None, req, state)
}

// Get and return a single str
fn account_get_id_radius(
    (path, req, state): (Path<String>, HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    let uat = get_current_user(&req);
    let id = path.into_inner();

    let obj = InternalRadiusReadMessage {
        uat: uat,
        uuid_or_name: id,
    };

    let res = state.qe_r.send(obj).from_err().and_then(|res| match res {
        Ok(event_result) => {
            // Only send back the first result, or None
            Ok(HttpResponse::Ok().json(event_result))
        }
        Err(e) => Ok(operation_error_to_response(e)),
    });

    Box::new(res)
}

fn account_post_id_radius_regenerate(
    (path, req, state): (Path<String>, HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    // Need to to send the regen msg
    let uat = get_current_user(&req);
    let id = path.into_inner();

    let obj = InternalRegenerateRadiusMessage::new(uat, id);

    let res = state.qe_w.send(obj).from_err().and_then(|res| match res {
        Ok(event_result) => {
            // Only send back the first result, or None
            Ok(HttpResponse::Ok().json(event_result))
        }
        Err(e) => Ok(operation_error_to_response(e)),
    });

    Box::new(res)
}

fn account_delete_id_radius(
    (path, req, state): (Path<String>, HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_rest_event_delete_id_attr(path, req, state, "radius_secret".to_string())
}

fn account_get_id_radius_token(
    (path, req, state): (Path<String>, HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    let uat = get_current_user(&req);
    let id = path.into_inner();

    let obj = InternalRadiusTokenReadMessage {
        uat: uat,
        uuid_or_name: id,
    };

    let res = state.qe_r.send(obj).from_err().and_then(|res| match res {
        Ok(event_result) => {
            // Only send back the first result, or None
            Ok(HttpResponse::Ok().json(event_result))
        }
        Err(e) => Ok(operation_error_to_response(e)),
    });

    Box::new(res)
}

fn group_get(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get(req, state, filter, None)
}

fn group_id_get(
    (path, req, state): (Path<String>, HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    let filter = filter_all!(f_eq("class", PartialValue::new_class("group")));
    json_rest_event_get_id(path, req, state, filter, None)
}

fn do_nothing((_req, _state): (HttpRequest<AppState>, State<AppState>)) -> String {
    "did nothing".to_string()
}

// We probably need an extract auth or similar to handle the different
// types (cookie, bearer), and to generic this over get/post.

fn auth(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    let max_size = state.max_size;

    req.payload()
        .from_err()
        .fold(BytesMut::new(), move |mut body, chunk| {
            // limit max size of in-memory payload
            if (body.len() + chunk.len()) > max_size {
                Err(error::ErrorBadRequest("overflow"))
            } else {
                body.extend_from_slice(&chunk);
                Ok(body)
            }
        })
        .and_then(
            move |body| -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
                let r_obj = serde_json::from_slice::<AuthRequest>(&body);

                // Send to the db for action
                match r_obj {
                    Ok(obj) => {
                        // First, deal with some state management.
                        // Do anything here first that's needed like getting the session details
                        // out of the req cookie.

                        // From the actix source errors here
                        // seems to be related to the serde_json deserialise of the cookie
                        // content, and because we control it's get/set it SHOULD be fine
                        // provided we use secure cookies. But we can't always trust that ...
                        let maybe_sessionid = match req.session().get::<Uuid>("auth-session-id") {
                            Ok(c) => c,
                            Err(e) => {
                                return Box::new(future::err(e));
                            }
                        };

                        let auth_msg = AuthMessage::new(obj, maybe_sessionid);

                        // We probably need to know if we allocate the cookie, that this is a
                        // new session, and in that case, anything *except* authrequest init is
                        // invalid.
                        let res = state
                            // This may change in the future ...
                            .qe_r
                            .send(auth_msg)
                            .from_err()
                            .and_then(move |res| match res {
                                Ok(ar) => {
                                    match &ar.state {
                                        AuthState::Success(uat) => {
                                            // Remove the auth-session-id
                                            req.session().remove("auth-session-id");
                                            // Set the uat into the cookie
                                            match req.session().set("uat", uat) {
                                                Ok(_) => Ok(HttpResponse::Ok().json(ar)),
                                                Err(_) => {
                                                    Ok(HttpResponse::InternalServerError().json(()))
                                                }
                                            }
                                        }
                                        AuthState::Denied(_) => {
                                            // Remove the auth-session-id
                                            req.session().remove("auth-session-id");
                                            Ok(HttpResponse::Unauthorized().json(ar))
                                        }
                                        AuthState::Continue(_) => {
                                            // Ensure the auth-session-id is set
                                            match req.session().set("auth-session-id", ar.sessionid)
                                            {
                                                Ok(_) => Ok(HttpResponse::Ok().json(ar)),
                                                Err(_) => {
                                                    Ok(HttpResponse::InternalServerError().json(()))
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => Ok(operation_error_to_response(e)),
                            });
                        Box::new(res)
                    }
                    Err(e) => Box::new(future::err(error::ErrorBadRequest(format!(
                        "Json Decode Failed: {:?}",
                        e
                    )))),
                }
            },
        )
}

fn idm_account_set_password(
    (req, state): (HttpRequest<AppState>, State<AppState>),
) -> impl Future<Item = HttpResponse, Error = Error> {
    json_event_post!(
        req,
        state,
        IdmAccountSetPasswordMessage,
        SingleStringRequest,
        state.qe_w
    )
}

/*
fn test_resource(
    (class, _req, _state): (Path<String>, HttpRequest<AppState> ,State<AppState>),
) -> String {
    format!("Hello {:?}!", class)
}

// https://actix.rs/docs/extractors/
#[derive(Deserialize)]
struct RestResource {
    class: String,
    id: String,
}
fn test_resource_id(
    (r, _req, _state): (Path<RestResource>, HttpRequest<AppState> ,State<AppState>),
) -> String {
    format!("Hello {:?}/{:?}!", r.class, r.id)
}
*/

// === internal setup helpers

fn setup_backend(config: &Configuration) -> Result<Backend, OperationError> {
    let mut audit_be = AuditScope::new("backend_setup");
    let pool_size: u32 = config.threads as u32;
    let be = Backend::new(&mut audit_be, config.db_path.as_str(), pool_size);
    // debug!
    debug!("{}", audit_be);
    be
}

// TODO #54: We could move most of the be/schema/qs setup and startup
// outside of this call, then pass in "what we need" in a cloneable
// form, this way we could have seperate Idm vs Qs threads, and dedicated
// threads for write vs read
fn setup_qs_idms(
    audit: &mut AuditScope,
    be: Backend,
    sid: SID,
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
    query_server.initialise_helper(audit)?;

    // We generate a SINGLE idms only!

    let idms = IdmServer::new(query_server.clone(), sid);

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
    let mut audit = AuditScope::new("backend_backup");

    let be_ro_txn = be.read();
    let r = be_ro_txn.backup(&mut audit, dst_path);
    debug!("{}", audit);
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
    let mut audit = AuditScope::new("backend_restore");

    // First, we provide the in-memory schema so that core attrs are indexed correctly.
    let schema = match Schema::new(&mut audit) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    // Limit the scope of the schema txn.
    let idxmeta = { schema.write().get_idxmeta() };

    let mut be_wr_txn = be.write(idxmeta);
    let r = be_wr_txn
        .restore(&mut audit, dst_path)
        .and_then(|_| be_wr_txn.commit(&mut audit));

    if r.is_err() {
        debug!("{}", audit);
        error!("Failed to restore database: {:?}", r);
        std::process::exit(1);
    }
    info!("Restore Success!");

    info!("Attempting to init query server ...");
    let server_id = be.get_db_sid();

    let (qs, _idms) = match setup_qs_idms(&mut audit, be, server_id) {
        Ok(t) => t,
        Err(e) => {
            debug!("{}", audit);
            error!("Unable to setup query server or idm server -> {:?}", e);
            return;
        }
    };
    info!("Success!");

    info!("Start reindex phase ...");

    let qs_write = qs.write();
    let r = qs_write
        .reindex(&mut audit)
        .and_then(|_| qs_write.commit(&mut audit));

    match r {
        Ok(_) => info!("Reindex Success!"),
        Err(e) => {
            error!("Restore failed: {:?}", e);
            std::process::exit(1);
        }
    };
}

pub fn reset_sid_core(config: Configuration) {
    let mut audit = AuditScope::new("reset_sid_core");
    // Setup the be
    let be = match setup_backend(&config) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };
    let nsid = be.reset_db_sid(&mut audit);
    debug!("{}", audit);
    info!("New Server ID: {:?}", nsid);
}

pub fn verify_server_core(config: Configuration) {
    let mut audit = AuditScope::new("server_verify");
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

    debug!("{}", audit);

    if r.len() == 0 {
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
    let mut audit = AuditScope::new("recover_account");

    // Start the backend.
    let be = match setup_backend(&config) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };
    let server_id = be.get_db_sid();
    // setup the qs - *with* init of the migrations and schema.
    let (_qs, idms) = match setup_qs_idms(&mut audit, be, server_id) {
        Ok(t) => t,
        Err(e) => {
            debug!("{}", audit);
            error!("Unable to setup query server or idm server -> {:?}", e);
            return;
        }
    };

    // Run the password change.
    let mut idms_prox_write = idms.proxy_write();
    match idms_prox_write.recover_account(&mut audit, name, password) {
        Ok(_) => {
            idms_prox_write
                .commit(&mut audit)
                .expect("A critical error during commit occured.");
            debug!("{}", audit);
            info!("Password reset!");
        }
        Err(e) => {
            error!("Error during password reset -> {:?}", e);
            debug!("{}", audit);
            // abort the txn
            std::mem::drop(idms_prox_write);
            std::process::exit(1);
        }
    };
}

pub fn create_server_core(config: Configuration) {
    // Until this point, we probably want to write to the log macro fns.

    if config.integration_test_config.is_some() {
        warn!("RUNNING IN INTEGRATION TEST MODE.");
        warn!("IF YOU SEE THIS IN PRODUCTION YOU MUST CONTACT SUPPORT IMMEDIATELY.");
    }

    info!("Starting kanidm with configuration: {}", config);
    // The log server is started on it's own thread, and is contacted
    // asynchronously.
    let log_addr = async_log::start();

    // Setup TLS (if any)
    let opt_tls_params = match setup_tls(&config) {
        Ok(opt_tls_params) => opt_tls_params,
        Err(e) => {
            error!("Failed to configure TLS parameters -> {:?}", e);
            return;
        }
    };

    // Similar, create a stats thread which aggregates statistics from the
    // server as they come in.

    // Setup the be for the qs.
    let be = match setup_backend(&config) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE -> {:?}", e);
            return;
        }
    };

    let server_id = be.get_db_sid();
    info!("Server ID -> {:?}", server_id);

    let mut audit = AuditScope::new("setup_qs_idms");
    // Start the IDM server.
    let (qs, idms) = match setup_qs_idms(&mut audit, be, server_id) {
        Ok(t) => t,
        Err(e) => {
            debug!("{}", audit);
            error!("Unable to setup query server or idm server -> {:?}", e);
            return;
        }
    };
    // Any pre-start tasks here.
    match &config.integration_test_config {
        Some(itc) => {
            let mut idms_prox_write = idms.proxy_write();
            match idms_prox_write.recover_account(
                &mut audit,
                "admin".to_string(),
                itc.admin_password.clone(),
            ) {
                Ok(_) => {}
                Err(e) => {
                    debug!("{}", audit);
                    error!(
                        "Unable to configure INTERGATION TEST admin account -> {:?}",
                        e
                    );
                    return;
                }
            };
            match idms_prox_write.commit(&mut audit) {
                Ok(_) => {}
                Err(e) => {
                    debug!("{}", audit);
                    error!("Unable to commit INTERGATION TEST setup -> {:?}", e);
                    return;
                }
            }
        }
        None => {}
    }
    log_addr.do_send(audit);

    // Arc the idms.
    let idms_arc = Arc::new(idms);

    // Pass it to the actor for threading.
    // Start the read query server with the given be path: future config
    let server_read_addr = QueryServerReadV1::start(
        log_addr.clone(),
        qs.clone(),
        idms_arc.clone(),
        config.threads,
    );
    // Start the write thread
    let server_write_addr =
        QueryServerWriteV1::start(log_addr.clone(), qs.clone(), idms_arc.clone());

    // Setup timed events associated to the write thread
    let _int_addr = IntervalActor::new(server_write_addr.clone()).start();

    // Copy the max size
    let max_size = config.maximum_request;
    let secure_cookies = config.secure_cookies;
    // let domain = config.domain.clone();
    let cookie_key: [u8; 32] = config.cookie_key.clone();

    // start the web server
    let aws_builder = actix_web::server::new(move || {
        App::with_state(AppState {
            qe_r: server_read_addr.clone(),
            qe_w: server_write_addr.clone(),
            max_size: max_size,
        })
        // Connect all our end points here.
        .middleware(middleware::Logger::default())
        .middleware(session::SessionStorage::new(
            // Signed prevents tampering. this 32 byte key MUST
            // be generated (probably a cli option, and it's up to the
            // server process to coordinate these on hosts). IE an RODC
            // could have a different key than our write servers to prevent
            // disclosure of a writeable token in case of compromise. It does
            // mean that you can't load balance between the rodc and the write
            // though, but that's tottaly reasonable.
            session::CookieSessionBackend::signed(&cookie_key)
                // Limit to path?
                // .path("/")
                // TODO #63: make this configurable!
                .max_age(Duration::hours(1))
                // .domain(domain.as_str())
                .same_site(cookie::SameSite::Strict) // constrain to the domain
                // Disallow from js and ...?
                .http_only(false)
                .name("kanidm-session")
                // This forces https only if true
                .secure(secure_cookies),
        ))
        .resource("/v1/raw/create", |r| {
            r.method(http::Method::POST).with_async(create)
        })
        .resource("/v1/raw/modify", |r| {
            r.method(http::Method::POST).with_async(modify)
        })
        .resource("/v1/raw/delete", |r| {
            r.method(http::Method::POST).with_async(delete)
        })
        .resource("/v1/raw/search", |r| {
            r.method(http::Method::POST).with_async(search)
        })
        .resource("/v1/auth", |r| {
            r.method(http::Method::POST).with_async(auth)
        })
        // QS rest resources
        .resource("/v1/schema", |r| {
            r.method(http::Method::GET).with_async(schema_get)
        })
        //   attributetype
        .resource("/v1/schema/attributetype", |r| {
            r.method(http::Method::GET)
                .with_async(schema_attributetype_get)
        })
        .resource("/v1/schema/attributetype", |r| {
            r.method(http::Method::POST).with(do_nothing)
        })
        //   attributetype/{id}
        .resource("/v1/schema/attributetype/{id}", |r| {
            r.method(http::Method::GET)
                .with_async(schema_attributetype_get_id)
        })
        .resource("/v1/schema/attributetype/{id}", |r| {
            r.method(http::Method::PUT).with(do_nothing)
        })
        .resource("/v1/schema/attributetype/{id}", |r| {
            r.method(http::Method::PATCH).with(do_nothing)
        })
        //   classtype
        .resource("/v1/schema/classtype", |r| {
            r.method(http::Method::GET).with_async(schema_classtype_get)
        })
        .resource("/v1/schema/classtype", |r| {
            r.method(http::Method::POST).with(do_nothing)
        })
        //    classtype/{id}
        .resource("/v1/schema/classtype/{id}", |r| {
            r.method(http::Method::GET)
                .with_async(schema_classtype_get_id)
        })
        .resource("/v1/schema/classtype/{id}", |r| {
            r.method(http::Method::PUT).with(do_nothing)
        })
        .resource("/v1/schema/classtype/{id}", |r| {
            r.method(http::Method::PATCH).with(do_nothing)
        })
        // Start IDM resources. We'll probably add more restful types later.
        // Self (specialisation of account I guess)
        .resource("/v1/self", |r| {
            r.method(http::Method::GET).with_async(whoami)
        })
        .resource("/v1/self/_attr/{attr}", |r| {
            r.method(http::Method::GET).with(do_nothing)
            // add put post delete
        })
        .resource("/v1/self/_credential", |r| {
            r.method(http::Method::GET).with(do_nothing)
        })
        .resource("/v1/self/_credential/primary/set_password", |r| {
            r.method(http::Method::POST)
                .with_async(idm_account_set_password)
        })
        .resource("/v1/self/_credential/{cid}/_lock", |r| {
            r.method(http::Method::GET).with(do_nothing)
            // Check if a cred is locked.
            // Can we self lock?
        })
        .resource("/v1/self/_radius", |r| {
            // Get our radius secret for manual configuration
            r.method(http::Method::GET).with(do_nothing)
        })
        .resource("/v1/self/_radius", |r| {
            // delete our radius secret
            r.method(http::Method::DELETE).with(do_nothing)
        })
        .resource("/v1/self/_radius", |r| {
            // regenerate our radius secret
            r.method(http::Method::POST).with(do_nothing)
        })
        .resource("/v1/self/_radius/_config", |r| {
            // Create new secret_otp for client configuration
            r.method(http::Method::POST).with(do_nothing)
        })
        .resource("/v1/self/_radius/_config/{secret_otp}", |r| {
            // Get the params
            r.method(http::Method::GET).with(do_nothing)
        })
        .resource("/v1/self/_radius/_config/{secret_otp}/apple", |r| {
            // Get an ios/macos configuration profile
            r.method(http::Method::GET).with(do_nothing)
        })
        // Accounts
        .resource("/v1/account", |r| {
            r.method(http::Method::GET).with_async(account_get)
            // Add post
        })
        .resource("/v1/account/{id}", |r| {
            r.method(http::Method::GET).with_async(account_get_id)
            // add put, patch, delete
        })
        .resource("/v1/account/{id}/_attr/{attr}", |r| {
            r.method(http::Method::GET).with(do_nothing)
            // add put post delete
        })
        .resource("/v1/account/{id}/_lock", |r| {
            r.method(http::Method::GET).with(do_nothing)
            // add post, delete
        })
        .resource("/v1/account/{id}/_credential", |r| {
            r.method(http::Method::GET).with(do_nothing)
            // add delete
        })
        .resource("/v1/account/{id}/_credential/primary", |r| {
            // Set a new primary credential value.
            // in future this will tie in to claims.
            r.method(http::Method::PUT)
                .with_async(account_put_id_credential_primary)
        })
        .resource("/v1/account/{id}/_credential/{cid}/_lock", |r| {
            r.method(http::Method::GET).with(do_nothing)
            // add post, delete
        })
        .resource("/v1/account/{id}/_radius", |r| {
            r.method(http::Method::GET)
                .with_async(account_get_id_radius);
            r.method(http::Method::POST)
                .with_async(account_post_id_radius_regenerate);
            r.method(http::Method::DELETE)
                .with_async(account_delete_id_radius);
        })
        // This is how the radius server views a json blob about the ID and radius creds.
        .resource("/v1/account/{id}/_radius/_token", |r| {
            r.method(http::Method::GET)
                .with_async(account_get_id_radius_token)
        })
        // Groups
        .resource("/v1/group", |r| {
            r.method(http::Method::GET).with_async(group_get)
            // Add post
        })
        .resource("/v1/group/{id}", |r| {
            r.method(http::Method::GET).with_async(group_id_get)
            // add put, patch, delete
        })
        .resource("/v1/group/{id}/_attr/{attr}", |r| {
            r.method(http::Method::GET).with(do_nothing)
            // add put post delete
        })
        // Claims
        // TBD
        // Recycle Bin
        .resource("/v1/recycle_bin", |r| {
            r.method(http::Method::GET).with(do_nothing)
        })
        .resource("/v1/recycle_bin/{id}", |r| {
            r.method(http::Method::GET).with(do_nothing)
        })
        .resource("/v1/recycle_bin/{id}/_restore", |r| {
            r.method(http::Method::POST).with(do_nothing)
        })
        // ACPs
        .resource("/v1/access_profile", |r| {
            r.method(http::Method::GET).with(do_nothing)
            // Add post
        })
        .resource("/v1/access_profile/{id}", |r| {
            r.method(http::Method::GET).with(do_nothing)
            // add put, patch, delete
        })
        .resource("/v1/access_profile/{id}/_attr/{attr}", |r| {
            r.method(http::Method::GET).with(do_nothing)
            // add put post delete
        })
    });

    let tls_aws_builder = match opt_tls_params {
        Some(tls_params) => aws_builder.bind_ssl(config.address, tls_params),
        None => {
            warn!("Starting WITHOUT TLS parameters. This may cause authentication to fail!");
            aws_builder.bind(config.address)
        }
    };

    tls_aws_builder
        .expect("Failed to initialise server!")
        .start();
}
