use constants::CONTENT_TYPE;
use error::FetchError;
use gloo::console;

use kanidm_proto::constants::{APPLICATION_JSON, KSESSIONID};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, RequestMode, Response};

use gloo::storage::{
    LocalStorage as PersistentStorage, SessionStorage as TemporaryStorage, Storage,
};
use yew::{html, Html};

pub mod constants;
pub mod error;
#[macro_use]
pub mod macros;
pub mod models;
pub mod utils;

pub fn pop_auth_session_id() -> Option<String> {
    let l: Result<String, _> = TemporaryStorage::get("auth_session_id");
    #[cfg(debug_assertions)]
    console::debug!(format!("auth_session_id -> {:?}", l).as_str());
    TemporaryStorage::delete("auth_session_id");
    l.ok()
}

pub fn set_bearer_token(r: String) {
    PersistentStorage::set("bearer_token", r).expect_throw("failed to set bearer_token");
}

pub fn get_bearer_token() -> Option<String> {
    let l: Result<String, _> = PersistentStorage::get("bearer_token");
    #[cfg(debug_assertions)]
    console::debug!(format!(
        "login_hint::get_login_remember_me -> present={:?}",
        l.is_ok()
    )
    .as_str());
    l.ok()
}

pub fn clear_bearer_token() {
    PersistentStorage::delete("bearer_token");
}

pub fn push_auth_session_id(r: String) {
    TemporaryStorage::set("auth_session_id", r)
        .expect_throw("failed to set auth_session_id in temporary storage");
}

/// Build and send a request to the backend, with some standard headers and pull back
/// (kopid, status, json, headers)
pub async fn do_request(
    uri: &str,
    method: RequestMethod,
    body: Option<JsValue>,
) -> Result<(Option<String>, u16, JsValue, Headers), FetchError> {
    let mut opts = RequestInit::new();
    opts.method(&method.to_string());
    opts.mode(RequestMode::SameOrigin);
    opts.credentials(web_sys::RequestCredentials::SameOrigin);

    if let Some(body) = body {
        #[cfg(debug_assertions)]
        if method == RequestMethod::GET {
            gloo::console::debug!("This seems odd, you've supplied a body with a GET request?")
        }
        opts.body(Some(&body));
    }

    let request = Request::new_with_str_and_init(uri, &opts)?;
    request
        .headers()
        .set(CONTENT_TYPE, APPLICATION_JSON)
        .expect_throw("failed to set content-type header");

    if let Some(sessionid) = pop_auth_session_id() {
        request
            .headers()
            .set(KSESSIONID, &sessionid)
            .expect_throw("failed to set auth session id header");
    }

    if let Some(bearer_token) = get_bearer_token() {
        request
            .headers()
            .set("authorization", &bearer_token)
            .expect_throw("failed to set authorisation header");
    }

    let window = utils::window();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
    let status = resp.status();
    let headers: Headers = resp.headers();

    if let Some(sessionid) = headers.get(KSESSIONID).ok().flatten() {
        push_auth_session_id(sessionid);
    }

    let kopid = headers.get("x-kanidm-opid").ok().flatten();

    let body = match resp.json() {
        Ok(json_future) => match JsFuture::from(json_future).await {
            Ok(body) => body,
            Err(e) => {
                let e_msg = format!("future json error -> {:?}", e);
                console::error!(e_msg.as_str());
                JsValue::NULL
            }
        },
        Err(e) => {
            let e_msg = format!("response json error -> {:?}", e);
            console::error!(e_msg.as_str());
            JsValue::NULL
        }
    };

    Ok((kopid, status, body, headers))
}

#[derive(Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RequestMethod {
    GET,
    POST,
    PUT,
}

impl ToString for RequestMethod {
    fn to_string(&self) -> String {
        match self {
            RequestMethod::PUT => "PUT".to_string(),
            RequestMethod::POST => "POST".to_string(),
            RequestMethod::GET => "GET".to_string(),
        }
    }
}

/// creates the "Kanidm is alpha" banner
pub fn alpha_warning_banner() -> Html {
    html!(
        <div class="alert alert-warning" role="alert">
        {"🦀 Kanidm is still in early Alpha, this interface is a placeholder! "}
        </div>
    )
}

pub fn do_alert_error(alert_title: &str, alert_message: Option<&str>) -> Html {
    html! {
    <div class="container">
        <div class="row justify-content-md-center">
            <div class="alert alert-danger" role="alert">
                <p><strong>{ alert_title }</strong></p>
                if let Some(value) = alert_message {
                    <p>{ value }</p>
                }
            </div>
        </div>
    </div>
    }
}
