use std::fmt::Display;

use constants::CONTENT_TYPE;
use error::FetchError;
use gloo::console;

use kanidm_proto::constants::uri::V1_AUTH_VALID;
use kanidm_proto::constants::CONTENT_TYPE_JSON;
use kanidm_proto::constants::KOPID;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, RequestMode, Response};

use yew::{html, Html};

use crate::constants::{CSS_ALERT_WARNING, IMG_LOGO_SQUARE};
use crate::models::clear_bearer_token;

pub mod constants;
pub mod error;
#[macro_use]
pub mod macros;
pub mod models;
pub mod ui;
pub mod utils;

/// Build and send a request to the backend, with some standard headers and pull back
/// (kopid, status, json, headers)
pub async fn do_request<JV: AsRef<JsValue>>(
    uri: &str,
    method: RequestMethod,
    body: Option<JV>,
) -> Result<(Option<String>, u16, JsValue, Headers), FetchError> {
    let opts = RequestInit::new();
    opts.set_method(method.as_ref());
    opts.set_mode(RequestMode::SameOrigin);
    opts.set_credentials(web_sys::RequestCredentials::SameOrigin);

    if let Some(body) = body {
        #[cfg(debug_assertions)]
        if method == RequestMethod::GET {
            gloo::console::debug!("This seems odd, you've supplied a body with a GET request?")
        }
        opts.set_body(body.as_ref());
    }

    let request = Request::new_with_str_and_init(uri, &opts)?;
    request
        .headers()
        .set(CONTENT_TYPE, CONTENT_TYPE_JSON)
        .expect_throw("failed to set content-type header");

    let window = utils::window();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
    let status = resp.status();
    let headers: Headers = resp.headers();

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

impl AsRef<str> for RequestMethod {
    fn as_ref(&self) -> &str {
        match self {
            RequestMethod::PUT => "PUT",
            RequestMethod::POST => "POST",
            RequestMethod::GET => "GET",
        }
    }
}

impl Display for RequestMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
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

impl Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&match self {
            SessionStatus::TokenValid => "SessionStatus::TokenValid".to_string(),
            SessionStatus::LoginRequired => "SessionStatus::LoginRequired".to_string(),
            SessionStatus::Error { emsg, kopid } => {
                format!("SessionStatus::Error: {} {:?}", emsg, kopid)
            }
        })
    }
}

/// Validate that the current stored session token is valid
pub async fn fetch_session_valid() -> Result<SessionStatus, FetchError> {
    let (kopid, status, value, _) =
        do_request(V1_AUTH_VALID, RequestMethod::GET, None::<JsValue>).await?;

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
