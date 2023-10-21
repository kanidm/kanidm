use constants::CONTENT_TYPE;
use error::FetchError;
use gloo::console;

use kanidm_proto::constants::{APPLICATION_JSON, KSESSIONID};
use models::clear_bearer_token;
use models::get_bearer_token;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, Request, RequestInit, RequestMode, Response};

use gloo::storage::{SessionStorage as TemporaryStorage, Storage};
use yew::BaseComponent;
use yew::Context;
use yew::{html, Html};

use crate::constants::{CSS_ALERT_WARNING, CSS_NAV_LINK, ID_SIGNOUTMODAL, IMG_LOGO_SQUARE};

pub mod constants;
pub mod error;
#[macro_use]
pub mod macros;
pub mod models;
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

    // TODO: x-kanidm-opid should be a const
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

/// Builds the signout modal dialogue box - the "target" is the Message to send when clicked.
pub fn signout_modal<T, U>(ctx: &Context<T>, target: U) -> Html
where
    T: BaseComponent,
    U: Clone + 'static,
    <T as BaseComponent>::Message: From<U>,
{
    html! {<div class="modal" tabindex="-1" role="dialog" id={ID_SIGNOUTMODAL}>
        <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
            <h5 class="modal-title">{"Confirm Sign out"}</h5>
            </div>
            <div class="modal-body text-center">
            {"Are you sure you'd like to log out?"}<br />
            <img src="/pkg/img/kani-waving.svg" alt="Kani waving goodbye" />
            </div>
            <div class="modal-footer">
            <button type="button" class="btn btn-success"
                data-bs-toggle="modal"
                data-bs-target={["#{}", ID_SIGNOUTMODAL].concat()}
                onclick={ ctx.link().callback(move |_| target.clone()) }>{ "Sign out" }</button>
            <button type="button" class="btn btn-secondary"
                data-bs-dismiss="modal"
                >{"Cancel"}</button>
            </div>
        </div>
        </div>
    </div>}
}

/// returns an a-href link which can trigger the signout flow
pub fn signout_link() -> Html {
    html! {
        <a class={CSS_NAV_LINK} href="#" data-bs-toggle="modal"
        data-bs-target={["#{}", ID_SIGNOUTMODAL].concat()}
        >{"Sign out"}</a>
    }
}

/// does the logout action, calling the api and clearing the local tokens
pub async fn ui_logout() -> Result<(), (String, Option<String>)> {
    let (kopid, status, value, _) = do_request("/v1/logout", RequestMethod::GET, None)
        .await
        .map_err(|e| {
            let emsg = format!("failed to logout -> {:?}", e);
            console::error!(emsg.as_str());
            (emsg, None)
        })?;

    // In both cases - clear the local token to prevent our client thinking we have auth.

    clear_bearer_token();

    if status == 200 {
        Ok(())
    } else {
        let emsg = value.as_string().unwrap_or_default();
        Err((emsg, kopid))
    }
}
