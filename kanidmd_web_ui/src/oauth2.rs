// use anyhow::Error;
use gloo::console;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen::UnwrapThrowExt;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, RequestRedirect, Response};
use yew::prelude::*;
use yew_router::prelude::*;

use crate::error::*;
use crate::manager::Route;
use crate::models;
use crate::utils;

pub use kanidm_proto::oauth2::{
    AccessTokenRequest, AccessTokenResponse, AuthorisationRequest, AuthorisationResponse,
    CodeChallengeMethod, ErrorResponse,
};

enum State {
    // We don't have a token, or something is invalid.
    LoginRequired,
    // We are in the process of check the auth token to be sure we can proceed.
    TokenCheck(String),
    // Token check done, lets do it.
    SubmitAuthReq(String),
    Consent {
        token: String,
        client_name: String,
        #[allow(dead_code)]
        scopes: Vec<String>,
        pii_scopes: Vec<String>,
        consent_token: String,
    },
    ConsentGranted(String),
    ErrInvalidRequest,
}

pub struct Oauth2App {
    state: State,
}

pub enum Oauth2Msg {
    LoginProceed,
    ConsentGranted(String),
    TokenValid,
    Consent {
        client_name: String,
        scopes: Vec<String>,
        pii_scopes: Vec<String>,
        consent_token: String,
    },
    Redirect(String),
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

impl Oauth2App {
    async fn fetch_token_valid(token: String) -> Result<Oauth2Msg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::SameOrigin);
        let request = Request::new_with_str_and_init("/v1/auth/valid", &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");
        request
            .headers()
            .set("authorization", format!("Bearer {}", token).as_str())
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
        let status = resp.status();

        if status == 200 {
            Ok(Oauth2Msg::TokenValid)
        } else if status == 401 {
            Ok(Oauth2Msg::LoginProceed)
        } else {
            let headers = resp.headers();
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            // let jsval_json = JsFuture::from(resp.json()?).await?;
            Ok(Oauth2Msg::Error { emsg, kopid })
        }
    }

    async fn fetch_authreq(
        token: String,
        authreq: AuthorisationRequest,
    ) -> Result<Oauth2Msg, FetchError> {
        let authreq_jsvalue = serde_json::to_string(&authreq)
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise authreq");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);

        opts.body(Some(&authreq_jsvalue));

        let request = Request::new_with_str_and_init("/oauth2/authorise", &opts)?;
        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");
        request
            .headers()
            .set("authorization", format!("Bearer {}", token).as_str())
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
        let status = resp.status();
        let headers = resp.headers();
        let kopid = headers.get("x-kanidm-opid").ok().flatten();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let state: AuthorisationResponse = jsval
                .into_serde()
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
        } else {
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(Oauth2Msg::Error { emsg, kopid })
        }
    }

    async fn fetch_consent_token(
        token: String,
        consent_token: String,
    ) -> Result<Oauth2Msg, FetchError> {
        let consentreq_jsvalue = serde_json::to_string(&consent_token)
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise consent_req");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.redirect(RequestRedirect::Manual);

        opts.body(Some(&consentreq_jsvalue));

        let request = Request::new_with_str_and_init("/oauth2/authorise/permit", &opts)?;
        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");
        request
            .headers()
            .set("authorization", format!("Bearer {}", token).as_str())
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
        let status = resp.status();
        let headers = resp.headers();

        let kopid = headers.get("x-kanidm-opid").ok().flatten();

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
        #[cfg(debug)]
        console::debug!("oauth2::create");

        // Do we have a query here?
        // Did we get sent a valid Oauth2 request?
        let location = ctx
            .link()
            .location()
            .expect_throw("Can't access current location");

        let query: Option<AuthorisationRequest> = location
            .query()
            .map_err(|e| {
                let e_msg = format!("lstorage error -> {:?}", e);
                console::error!(e_msg.as_str());
            })
            .ok()
            .or_else(|| {
                console::error!("pop_oauth2_authorisation_request");
                models::pop_oauth2_authorisation_request()
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

        let e_msg = format!("{:?}", query);
        console::error!(e_msg.as_str());

        // In the query, if this is openid there MAY be a hint
        // as to the users name.
        // See: https://openid.net/specs/openid-connect-basic-1_0.html#RequestParameters
        // specifically, login_hint
        if let Some(login_hint) = query.oidc_ext.login_hint.clone() {
            models::push_login_hint(login_hint)
        }
        // Push the request down. This covers if we move to LoginRequired.
        models::push_oauth2_authorisation_request(query);

        match models::get_bearer_token() {
            Some(token) => {
                // Start the fetch req.
                // Put the fetch handle into the consent type.
                let token_c = token.clone();
                ctx.link().send_future(async {
                    match Self::fetch_token_valid(token_c).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                Oauth2App {
                    state: State::TokenCheck(token),
                }
            }
            None => Oauth2App {
                state: State::LoginRequired,
            },
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        #[cfg(debug)]
        console::debug!("oauth2::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug)]
        console::debug!("oauth2::update");

        match msg {
            Oauth2Msg::LoginProceed => {
                models::push_return_location(models::Location::Manager(Route::Oauth2));

                ctx.link()
                    .history()
                    .expect_throw("failed to read history")
                    .push(Route::Login);
                // Don't need to redraw as we are yolo-ing out.
                false
            }
            Oauth2Msg::TokenValid => {
                // Okay we can proceed, pop the query.
                let ar = models::pop_oauth2_authorisation_request();

                self.state = match (&self.state, ar) {
                    (State::TokenCheck(token), Some(ar)) => {
                        let token_c = token.clone();
                        ctx.link().send_future(async {
                            match Self::fetch_authreq(token_c, ar).await {
                                Ok(v) => v,
                                Err(v) => v.into(),
                            }
                        });
                        State::SubmitAuthReq(token.clone())
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
                    State::SubmitAuthReq(token) => State::Consent {
                        token: token.clone(),
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
                        token,
                        consent_token,
                        client_name,
                        ..
                    } => {
                        let token_c = token.clone();
                        let cr_c = consent_token.clone();
                        ctx.link().send_future(async {
                            match Self::fetch_consent_token(token_c, cr_c).await {
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
            Oauth2Msg::Error { emsg, kopid } => {
                self.state = State::ErrInvalidRequest;
                console::error!(format!("{:?}", kopid).as_str());
                console::error!(emsg.as_str());
                true
            }
            Oauth2Msg::Redirect(loc) => {
                #[cfg(debug)]
                console::debug!(format!("Redirecting to {}", loc).as_str());
                // Send the location here, and then update will trigger the redir via
                // https://docs.rs/web-sys/0.3.51/web_sys/struct.Location.html#method.replace
                // see https://developer.mozilla.org/en-US/docs/Web/API/Location/replace

                let location = utils::window().location();

                match location.replace(loc.as_str()) {
                    // No need to redraw, we are leaving.
                    Ok(_) => false,
                    Err(e) => {
                        // Something went bang, opps.
                        console::error!(format!("{:?}", e).as_str());
                        self.state = State::ErrInvalidRequest;
                        true
                    }
                }
            }
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug)]
        console::debug!("oauth2::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        #[cfg(debug)]
        console::debug!("oauth2::view");

        let body_content = match &self.state {
            State::LoginRequired => {
                // <body class="html-body form-body">

                html! {
                    <form
                      onsubmit={ ctx.link().callback(|e: FocusEvent| {
                          console::debug!("oauth2::view -> LoginRequired - prevent_default()");
                          e.prevent_default();
                          Oauth2Msg::LoginProceed
                      } ) }
                      action="javascript:void(0);"
                    >
                      <h1 class="h3 mb-3 fw-normal">
                        // TODO: include the domain display name here
                        {"Sign in to proceed" }
                        </h1>
                      <button autofocus=true class="w-100 btn btn-lg btn-primary" type="submit">
                        { "Sign in" }
                      </button>
                    </form>
                }
            }
            State::Consent {
                token: _,
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
                        onsubmit={ ctx.link().callback(move |e: FocusEvent| {
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
            State::SubmitAuthReq(_) | State::TokenCheck(_) => {
                html! {
                    <div class="alert alert-light" role="alert">
                        <h2 class="text-center">{ "Processing ... " }</h2>
                    </div>
                }
            }
            State::ErrInvalidRequest => {
                html! {
                    <div class="alert alert-danger" role="alert">
                        <h1>{ "Invalid request" } </h1>
                        <p>
                        { "Please close this window and try again again from the beginning." }
                        </p>
                    </div>
                }
            }
        };
        html! {
        <>
            <main class="form-signin">
            <center>
                <img src="/pkg/img/logo-square.svg" alt="Kanidm" class="kanidm_logo"/>
            </center>
            <div class="container">
            { body_content }
            </div>
            </main>
            { crate::utils::do_footer() }
        </>
        }
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        console::debug!("oauth2::destroy");
        remove_body_form_classes!();
    }
}
