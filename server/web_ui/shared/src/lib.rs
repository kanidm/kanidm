use constants::CONTENT_TYPE;
use error::FetchError;
use gloo::console;

use kanidm_proto::constants::uri::V1_AUTH_VALID;
use kanidm_proto::constants::KOPID;
use kanidm_proto::constants::{APPLICATION_JSON, KSESSIONID};
use models::{clear_bearer_token, get_bearer_token};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, RequestMode, Response};

use gloo::storage::{SessionStorage as TemporaryStorage, Storage};
use yew::{html, Html};

use crate::constants::{CSS_ALERT_WARNING, IMG_LOGO_SQUARE};

pub mod constants;
pub mod error;
#[macro_use]
pub mod macros;
pub mod models;
pub mod ui;
pub mod utils;

const AUTH_SESSION_ID: &str = "auth_session_id";

pub fn pop_auth_session_id() -> Option<String> {
    let l: Result<String, _> = TemporaryStorage::get(AUTH_SESSION_ID);
    #[cfg(debug_assertions)]
    console::debug!(format!("auth_session_id -> {:?}", l).as_str());
    TemporaryStorage::delete(AUTH_SESSION_ID);
    l.ok()
}

pub fn push_auth_session_id(r: String) {
    TemporaryStorage::set(AUTH_SESSION_ID, r).expect_throw(&format!(
        "failed to set {} in temporary storage",
        AUTH_SESSION_ID
    ));
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
            .expect_throw(&format!("failed to set {} header", KSESSIONID));
    }

    if let Some(bearer_token) = get_bearer_token() {
        request
            .headers()
            .set("authorization", &bearer_token)
            .expect_throw("failed to set authorization header");
    }

    let window = utils::window();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
    let status = resp.status();
    let headers: Headers = resp.headers();

    if let Some(sessionid) = headers.get(KSESSIONID).ok().flatten() {
        push_auth_session_id(sessionid);
    }

    let kopid = headers.get(KOPID).ok().flatten();

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
        <div class={CSS_ALERT_WARNING} role="alert">
        {"🦀 Kanidm is still in early Alpha, this interface is a placeholder! "}
        </div>
    )
}

/// Returns a HTML img tag with the Kanidm logo
pub fn logo_img() -> Html {
    html! {
        <img src={IMG_LOGO_SQUARE} alt="Kanidm" class="kanidm_logo"/>
    }
}

pub enum SessionStatus {
    TokenValid,
    LoginRequired,
    Error { emsg: String, kopid: Option<String> },
}

impl ToString for SessionStatus {
    fn to_string(&self) -> String {
        match self {
            SessionStatus::TokenValid => "SessionStatus::TokenValid".to_string(),
            SessionStatus::LoginRequired => "SessionStatus::LoginRequired".to_string(),
            SessionStatus::Error { emsg, kopid } => {
                format!("SessionStatus::Error: {} {:?}", emsg, kopid)
            }
        }
    }
}

/// Validate that the current stored session token is valid
pub async fn fetch_session_valid() -> Result<SessionStatus, FetchError> {
    let (kopid, status, value, _) = do_request(V1_AUTH_VALID, RequestMethod::GET, None).await?;

    if status == 200 {
        Ok(SessionStatus::TokenValid)
    } else if status == 401 {
        #[cfg(debug_assertions)]
        console::debug!("Session token is invalid, clearing it");
        clear_bearer_token();
        Ok(SessionStatus::LoginRequired)
    } else {
        let emsg = value.as_string().unwrap_or_default();
        Ok(SessionStatus::Error { emsg, kopid })
    }
}
