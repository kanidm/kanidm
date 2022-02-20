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
    AccessTokenRequest, AccessTokenResponse, AuthorisationRequest, CodeChallengeMethod,
    ConsentRequest, ErrorResponse,
};

enum State {
    // We don't have a token, or something is invalid.
    LoginRequired,
    // We are in the process of check the auth token to be sure we can proceed.
    TokenCheck(String),
    // Token check done, lets do it.
    SubmitAuthReq(String),
    Consent(String, ConsentRequest),
    ConsentGranted,
    ErrInvalidRequest,
}

pub struct Oauth2App {
    state: State,
}

pub enum Oauth2Msg {
    LoginProceed,
    ConsentGranted,
    TokenValid,
    Consent(ConsentRequest),
    Redirect(String),
    Error { emsg: String, kopid: Option<String> },
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

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let state: ConsentRequest = jsval.into_serde().expect_throw("Invalid response type");
            Ok(Oauth2Msg::Consent(state))
        } else {
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(Oauth2Msg::Error { emsg, kopid })
        }
    }

    async fn fetch_consent_token(
        token: String,
        consent_req: ConsentRequest,
    ) -> Result<Oauth2Msg, FetchError> {
        let consentreq_jsvalue = serde_json::to_string(&consent_req.consent_token)
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
        console::log!("oauth2::create");

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
                console::log!(e_msg.as_str());
            })
            .ok()
            .or_else(|| {
                console::log!("pop_oauth2_authorisation_request");
                models::pop_oauth2_authorisation_request()
            });

        if let Err(e) = crate::utils::body().class_list().add_1("form-signin-body") {
            console::log!(format!("class_list add error -> {:?}", e).as_str());
        };

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
        console::log!(e_msg.as_str());

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
        console::log!("oauth2::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::log!("oauth2::update");

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
                        console::log!("Invalid state transition");
                        State::ErrInvalidRequest
                    }
                };
                true
            }
            Oauth2Msg::Consent(consent_req) => {
                self.state = match &self.state {
                    State::SubmitAuthReq(token) => State::Consent(token.clone(), consent_req),
                    _ => {
                        console::log!("Invalid state transition");
                        State::ErrInvalidRequest
                    }
                };
                true
            }
            Oauth2Msg::ConsentGranted => {
                self.state = match &self.state {
                    State::Consent(token, consent_req) => {
                        let token_c = token.clone();
                        let cr_c = (*consent_req).clone();
                        ctx.link().send_future(async {
                            match Self::fetch_consent_token(token_c, cr_c).await {
                                Ok(v) => v,
                                Err(v) => v.into(),
                            }
                        });
                        State::ConsentGranted
                    }
                    _ => {
                        console::log!("Invalid state transition");
                        State::ErrInvalidRequest
                    }
                };
                // We need to send off fetch task here.
                true
            }
            Oauth2Msg::Error { emsg, kopid } => {
                self.state = State::ErrInvalidRequest;
                console::log!(format!("{:?}", kopid).as_str());
                console::log!(emsg.as_str());
                true
            }
            Oauth2Msg::Redirect(loc) => {
                console::log!(format!("Redirecting to {}", loc).as_str());
                // Send the location here, and then update will trigger the redir via
                // https://docs.rs/web-sys/0.3.51/web_sys/struct.Location.html#method.replace
                // see https://developer.mozilla.org/en-US/docs/Web/API/Location/replace

                let location = utils::window().location();

                match location.replace(loc.as_str()) {
                    // No need to redraw, we are leaving.
                    Ok(_) => false,
                    Err(e) => {
                        // Something went bang, opps.
                        console::log!(format!("{:?}", e).as_str());
                        self.state = State::ErrInvalidRequest;
                        true
                    }
                }
            }
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        crate::utils::autofocus();
        console::log!("oauth2::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        console::log!("login::view");
        match &self.state {
            State::LoginRequired => {
                // <body class="html-body form-body">

                html! {
                  <main class="form-signin">
                    <form
                      onsubmit={ ctx.link().callback(|e: FocusEvent| {
                          console::log!("oauth2::view -> LoginRequired - prevent_default()");
                          e.prevent_default();
                          Oauth2Msg::LoginProceed
                      } ) }
                      action="javascript:void(0);"
                    >
                      <h1 class="h3 mb-3 fw-normal">{" Sign in to proceed" }</h1>
                      <button id="autofocus" class="w-100 btn btn-lg btn-primary" type="submit">{ "Sign in" }</button>
                    </form>
                  </main>
                }
            }
            State::Consent(_, query) => {
                let client_name = query.client_name.clone();
                // <body class="html-body form-body">
                html! {
                    <main class="form-signin">
                      <form
                        onsubmit={ ctx.link().callback(|e: FocusEvent| {
                            console::log!("oauth2::view -> Consent - prevent_default()");
                            e.prevent_default();
                            Oauth2Msg::ConsentGranted
                        } ) }
                        action="javascript:void(0);"
                      >
                        <h1 class="h3 mb-3 fw-normal">{"Consent to Proceed to " }{ client_name }</h1>
                        <button id="autofocus" class="w-100 btn btn-lg btn-primary" type="submit">{ "Proceed" }</button>
                      </form>
                    </main>
                }
            }
            State::ConsentGranted | State::SubmitAuthReq(_) | State::TokenCheck(_) => {
                html! { <div> <h1>{ " ... " }</h1>  </div> }
            }
            State::ErrInvalidRequest => {
                html! { <div> <h1>{ " ❌ " }</h1>  </div> }
            }
        }
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        console::log!("oauth2::destroy");
        if let Err(e) = crate::utils::body()
            .class_list()
            .remove_1("form-signin-body")
        {
            console::log!(format!("class_list remove error -> {:?}", e).as_str());
        }
    }
}
