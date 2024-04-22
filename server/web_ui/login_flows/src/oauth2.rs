use gloo::console;
use kanidm_proto::constants::uri::{OAUTH2_AUTHORISE, OAUTH2_AUTHORISE_PERMIT};
use kanidm_proto::constants::{APPLICATION_JSON, KOPID};
pub use kanidm_proto::oauth2::{AuthorisationRequest, AuthorisationResponse};
use kanidmd_web_ui_shared::constants::{CONTENT_TYPE, CSS_ALERT_DANGER, URL_OAUTH2};
use kanidmd_web_ui_shared::utils::{do_alert_error, do_footer, window};
use kanidmd_web_ui_shared::{
    add_body_form_classes, fetch_session_valid, logo_img, remove_body_form_classes, SessionStatus,
};
use wasm_bindgen::{JsCast, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, RequestRedirect, Response};
use yew::prelude::*;
use yew_router::prelude::*;

use super::router::LoginRoute;
use kanidmd_web_ui_shared::models::{
    get_bearer_token, pop_oauth2_authorisation_request, push_login_hint,
    push_oauth2_authorisation_request, push_return_location,
};
use kanidmd_web_ui_shared::{do_request, error::FetchError, utils, RequestMethod};

use serde::Serialize;
use std::collections::BTreeSet;

enum State {
    LoginRequired,
    // We are in the process of checking the auth token to be sure we can proceed.
    TokenCheck,
    // Token check done, lets do it.
    SubmitAuthReq,
    Consent {
        client_name: String,
        #[allow(dead_code)]
        scopes: BTreeSet<String>,
        pii_scopes: BTreeSet<String>,
        consent_token: String,
    },
    ConsentGranted(String),
    AccessDenied(Option<String>),
    ErrInvalidRequest,
}

pub struct Oauth2App {
    state: State,
}

#[derive(Debug)]
pub enum Oauth2Msg {
    LoginRequired,
    LoginProceed,
    ConsentGranted(String),
    TokenValid,
    Consent {
        client_name: String,
        scopes: BTreeSet<String>,
        pii_scopes: BTreeSet<String>,
        consent_token: String,
    },
    Redirect(String),
    AccessDenied {
        kopid: Option<String>,
    },
    Error {
        emsg: String,
        kopid: Option<String>,
    },
}

impl From<FetchError> for Oauth2Msg {
    fn from(fe: FetchError) -> Self {
        Oauth2Msg::Error {
            emsg: fe.as_string(),
            kopid: None,
        }
    }
}

impl From<SessionStatus> for Oauth2Msg {
    fn from(value: SessionStatus) -> Self {
        match value {
            SessionStatus::TokenValid => Oauth2Msg::TokenValid,
            SessionStatus::LoginRequired => Oauth2Msg::LoginRequired,
            SessionStatus::Error { emsg, kopid } => Oauth2Msg::Error { emsg, kopid },
        }
    }
}

impl Oauth2App {
    /// Validate that the current auth token's OK
    async fn fetch_session_valid() -> Result<Oauth2Msg, FetchError> {
        fetch_session_valid().await.map(|v| v.into())
    }

    async fn fetch_authreq(authreq: AuthorisationRequest) -> Result<Oauth2Msg, FetchError> {
        let req_jsvalue_1 = authreq
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .expect("Failed to serialise request");
        let req_jsvalue =
            js_sys::JSON::stringify(&req_jsvalue_1).expect_throw("failed to stringify");

        #[cfg(debug_assertions)]
        console::debug!(&format!("fetch_authreq post {}", req_jsvalue));

        let (kopid, status, value, headers) =
            do_request(OAUTH2_AUTHORISE, RequestMethod::POST, Some(req_jsvalue)).await?;

        #[cfg(debug_assertions)]
        console::debug!(&format!("fetch_authreq result {}", status));

        if status == 200 {
            let state: AuthorisationResponse = serde_wasm_bindgen::from_value(value)
                .map_err(|e| {
                    let e_msg = format!("serde error -> {:?}", e);
                    console::error!(e_msg.as_str());
                })
                .expect_throw("Invalid response type");
            match state {
                AuthorisationResponse::ConsentRequested {
                    client_name,
                    scopes,
                    pii_scopes,
                    consent_token,
                } => Ok(Oauth2Msg::Consent {
                    client_name,
                    scopes,
                    pii_scopes,
                    consent_token,
                }),
                AuthorisationResponse::Permitted => {
                    if let Some(loc) = headers.get("location").ok().flatten() {
                        Ok(Oauth2Msg::Redirect(loc))
                    } else {
                        Ok(Oauth2Msg::Error {
                            emsg: "no location header".to_string(),
                            kopid,
                        })
                    }
                }
            }
        } else if status == 403 {
            Ok(Oauth2Msg::AccessDenied { kopid })
        } else {
            let emsg = value.as_string().unwrap_or_default();
            Ok(Oauth2Msg::Error { emsg, kopid })
        }
    }

    async fn fetch_consent_token(consent_token: String) -> Result<Oauth2Msg, FetchError> {
        let req_jsvalue = consent_token
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .expect("Failed to serialise request");
        let req_jsvalue = js_sys::JSON::stringify(&req_jsvalue).expect_throw("failed to stringify");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.redirect(RequestRedirect::Manual); // can't replace with do_request because of this

        opts.body(Some(&req_jsvalue));

        let request = Request::new_with_str_and_init(OAUTH2_AUTHORISE_PERMIT, &opts)?;

        request
            .headers()
            .set(CONTENT_TYPE, APPLICATION_JSON)
            .expect_throw("failed to set header");

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
        let headers = resp.headers();

        let kopid = headers.get(KOPID).ok().flatten();

        if status == 200 {
            if let Some(loc) = headers.get("location").ok().flatten() {
                Ok(Oauth2Msg::Redirect(loc))
            } else {
                Ok(Oauth2Msg::Error {
                    emsg: "no location header".to_string(),
                    kopid,
                })
            }
        } else {
            let emsg = "Redirect error".to_string();
            Ok(Oauth2Msg::Error { emsg, kopid })
        }
    }
}

impl Component for Oauth2App {
    type Message = Oauth2Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("oauth2::create");

        // Do we have a query here?
        // Did we get sent a valid Oauth2 request?
        let location = ctx
            .link()
            .location()
            .expect_throw("Can't access browser current location");

        let query: Option<AuthorisationRequest> = location
            .query()
            .map_err(|e| {
                let e_msg = format!(
                    "failed to decode authorisation request url parameters -> {:?}",
                    e
                );
                console::error!(e_msg.as_str());
            })
            .ok()
            .or_else(|| {
                console::log!("using previously storage oauth2 authorisation request if possible");
                pop_oauth2_authorisation_request()
            });

        add_body_form_classes!();

        // If we have neither we need to say that we can not proceed at all.
        let query = match query {
            Some(q) => q,
            None => {
                return Oauth2App {
                    state: State::ErrInvalidRequest,
                };
            }
        };
        console::debug!(format!("{query:?}",));

        // In the query, if this is openid there MAY be a hint
        // as to the users name.
        // See: https://openid.net/specs/openid-connect-basic-1_0.html#RequestParameters
        // specifically, login_hint
        if let Some(login_hint) = query.oidc_ext.login_hint.clone() {
            push_login_hint(login_hint)
        }
        // Push the request down. This covers if we move to LoginRequired so we can restore where
        // we were / what we were doing.
        push_oauth2_authorisation_request(query);

        // Start the fetch req.
        // Put the fetch handle into the consent type.
        ctx.link().send_future(async {
            match Self::fetch_session_valid().await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });

        Oauth2App {
            state: State::TokenCheck,
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("oauth2::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!(&format!("oauth2::update {:?}", msg));

        match msg {
            Oauth2Msg::LoginRequired => {
                self.state = State::LoginRequired;
                true
            }
            Oauth2Msg::LoginProceed => {
                let current_loc = window()
                    .location()
                    .as_string()
                    .unwrap_or(URL_OAUTH2.to_string());
                push_return_location(&current_loc);

                ctx.link()
                    .navigator()
                    .expect_throw("failed to read history")
                    .push(&LoginRoute::Login);
                // Don't need to redraw as we are yolo-ing out.
                false
            }
            Oauth2Msg::TokenValid => {
                // Okay we can proceed, pop the query.
                let ar = pop_oauth2_authorisation_request();

                self.state = match (&self.state, ar) {
                    (State::TokenCheck, Some(ar)) => {
                        ctx.link().send_future(async {
                            match Self::fetch_authreq(ar).await {
                                Ok(v) => v,
                                Err(v) => v.into(),
                            }
                        });
                        State::SubmitAuthReq
                    }
                    _ => {
                        console::error!("Invalid state transition");
                        State::ErrInvalidRequest
                    }
                };
                true
            }
            Oauth2Msg::Consent {
                client_name,
                scopes,
                pii_scopes,
                consent_token,
            } => {
                self.state = match &self.state {
                    State::SubmitAuthReq => State::Consent {
                        client_name,
                        scopes,
                        pii_scopes,
                        consent_token,
                    },
                    _ => {
                        console::error!("Invalid state transition");
                        State::ErrInvalidRequest
                    }
                };
                true
            }
            Oauth2Msg::ConsentGranted(_) => {
                self.state = match &self.state {
                    State::Consent {
                        consent_token,
                        client_name,
                        ..
                    } => {
                        let cr_c = consent_token.clone();
                        ctx.link().send_future(async {
                            match Self::fetch_consent_token(cr_c).await {
                                Ok(v) => v,
                                Err(v) => v.into(),
                            }
                        });
                        State::ConsentGranted(client_name.to_string())
                    }
                    _ => {
                        console::error!("Invalid state transition");
                        State::ErrInvalidRequest
                    }
                };
                // We need to send off fetch task here.
                true
            }
            Oauth2Msg::AccessDenied { kopid } => {
                console::error!(format!("opid - {:?}", kopid).as_str());
                self.state = State::AccessDenied(kopid);
                true
            }
            Oauth2Msg::Error { emsg, kopid } => {
                self.state = State::ErrInvalidRequest;
                console::error!(format!("opid - {:?}, msg - {}", kopid, emsg).as_str());
                true
            }
            Oauth2Msg::Redirect(loc) => {
                #[cfg(debug_assertions)]
                console::debug!(format!("Redirecting to {}", loc).as_str());
                // Send the location here, and then update will trigger the redir via
                // https://docs.rs/web-sys/0.3.51/web_sys/struct.Location.html#method.replace
                // see https://developer.mozilla.org/en-US/docs/Web/API/Location/replace

                let location = utils::window().location();

                match location.replace(loc.as_str()) {
                    // No need to redraw, we are leaving.
                    Ok(_) => false,
                    Err(e) => {
                        // Something went bang, oops.
                        console::error!(format!("{:?}", e).as_str());
                        self.state = State::ErrInvalidRequest;
                        true
                    }
                }
            }
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("oauth2::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        #[cfg(debug_assertions)]
        console::debug!("oauth2::view");

        let body_content = match &self.state {
            State::LoginRequired => {
                // <body class="html-body form-body">

                html! {
                    <form
                      onsubmit={ ctx.link().callback(|e: SubmitEvent| {
                          console::debug!("oauth2::view -> LoginRequired - prevent_default()");
                          e.prevent_default();
                          Oauth2Msg::LoginProceed
                      } ) }
                      action="javascript:void(0);"
                    >
                      <h1 class="h3 mb-3 fw-normal">
                        // TODO: include the domain display name here, and the RS display name?
                        {"Sign in to proceed" }
                        </h1>
                      <button autofocus=true class="w-100 btn btn-lg btn-primary" type="submit">
                        { "Sign in" }
                      </button>
                    </form>
                }
            }
            State::Consent {
                client_name,
                scopes: _,
                pii_scopes,
                consent_token: _,
            } => {
                let client_name = client_name.clone();

                let pii_req = if pii_scopes.is_empty() {
                    html! {
                      <div>
                        <p>{ "This site will not have access to your personal information." }</p>
                        <p>{ "If this site requests personal information in the future we will check with you." }</p>
                      </div>
                    }
                } else {
                    html! {
                      <div>
                        <p>{ "This site has requested to see the following personal information." }</p>
                        <ul>
                          {
                            pii_scopes.iter().map(|s| html! { <li>{ s }</li> } ).collect::<Html>()
                          }
                        </ul>
                        <p>{ "If this site requests different personal information in the future we will check with you again." }</p>
                      </div>
                    }
                };

                // <body class="html-body form-body">
                let app_name = client_name.clone();
                html! {
                      <form
                        onsubmit={ ctx.link().callback(move |e: SubmitEvent| {
                            console::debug!("oauth2::view -> Consent - prevent_default()");
                            e.prevent_default();
                            Oauth2Msg::ConsentGranted(client_name.to_string())
                        } ) }
                        action="javascript:void(0);"
                      >
                        <h2 class="h3 mb-3 fw-normal">{"Consent to Proceed to " }{ app_name }</h2>
                        { pii_req }

                        <div class="text-center">
                            <button autofocus=true class="w-100 btn btn-lg btn-primary" type="submit">{ "Proceed" }</button>
                        </div>
                      </form>
                }
            }
            State::ConsentGranted(app_name) => {
                html! {
                    <div class="alert alert-success" role="alert">
                        <h2 class="text-center">{ "Taking you to " }{app_name}{" ... " }</h2>
                    </div>
                }
            }
            State::SubmitAuthReq | State::TokenCheck => {
                html! {
                    <div class="alert alert-light" role="alert">
                        <h2 class="text-center">{ "Processing ... " }</h2>
                    </div>
                }
            }
            State::AccessDenied(kopid) => {
                html! {
                    <div class={CSS_ALERT_DANGER} role="alert">
                        <h1>{ "Access Denied" } </h1>
                        <p>
                        { "You do not have access to the requested resources." }
                        </p>
                        <p>
                        { if let Some(opid) = kopid {
                            format!("Operation ID: {}", opid)
                          } else {
                            "Operation ID: -".to_string()
                          }
                        }
                        </p>
                    </div>
                }
            }
            State::ErrInvalidRequest => do_alert_error(
                "Invalid request",
                Some("Please close this window and try again from the beginning."),
                false,
            ),
        };
        html! {
        <>
            <main class="form-signin">
            <center>
                {logo_img()}
            </center>
            <div class="container">
            { body_content }
            </div>
            </main>
            { do_footer() }
        </>
        }
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        console::debug!("oauth2::destroy");
        remove_body_form_classes!();
    }
}
