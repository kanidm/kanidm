// use anyhow::Error;
use gloo::console;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{Request, RequestInit, RequestMode, Response};
use yew::prelude::*;
use yew_router::prelude::*;

use crate::error::FetchError;
use crate::models;
use crate::utils;

use kanidm_proto::v1::{
    AuthAllowed, AuthCredential, AuthRequest, AuthResponse, AuthState, AuthStep,
};

use webauthn_rs::proto::PublicKeyCredential;

pub struct LoginApp {
    inputvalue: String,
    session_id: String,
    state: LoginState,
}

#[derive(PartialEq)]
enum TotpState {
    Enabled,
    Disabled,
    Invalid,
}

enum LoginState {
    Init(bool),
    Continue(Vec<AuthAllowed>),
    Password(bool),
    BackupCode(bool),
    Totp(TotpState),
    Webauthn(web_sys::CredentialRequestOptions),
    Error { emsg: String, kopid: Option<String> },
    UnknownUser,
    Denied(String),
    Authenticated,
}

const CLASSES_TO_ADD: &[&str] = &["flex-column", "d-flex", "h-100"];
pub enum LoginAppMsg {
    Input(String),
    Restart,
    Begin,
    PasswordSubmit,
    BackupCodeSubmit,
    TotpSubmit,
    WebauthnSubmit(PublicKeyCredential),
    Start(String, AuthResponse),
    Next(AuthResponse),
    Continue(usize),
    // DoNothing,
    UnknownUser,
    Error { emsg: String, kopid: Option<String> },
}

impl From<FetchError> for LoginAppMsg {
    fn from(fe: FetchError) -> Self {
        LoginAppMsg::Error {
            emsg: fe.as_string(),
            kopid: None,
        }
    }
}

impl LoginApp {
    async fn auth_init(username: String) -> Result<LoginAppMsg, FetchError> {
        let authreq = AuthRequest {
            step: AuthStep::Init(username),
        };
        let authreq_jsvalue = serde_json::to_string(&authreq)
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise authreq");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);

        opts.body(Some(&authreq_jsvalue));

        let request = Request::new_with_str_and_init("/v1/auth", &opts)?;
        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
        let status = resp.status();
        let headers = resp.headers();

        if status == 200 {
            let session_id = headers
                .get("x-kanidm-auth-session-id")
                .ok()
                .flatten()
                .unwrap_or_else(|| "".to_string());
            let jsval = JsFuture::from(resp.json()?).await?;
            let state: AuthResponse = jsval.into_serde().expect_throw("Invalid response type");
            Ok(LoginAppMsg::Start(session_id, state))
        } else if status == 404 {
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            console::log!(format!(
                "User not found: {:?}. Operation ID: {:?}",
                text, kopid
            ));
            Ok(LoginAppMsg::UnknownUser)
        } else {
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(LoginAppMsg::Error { emsg, kopid })
        }
    }

    async fn auth_step(
        authreq: AuthRequest,
        session_id: String,
    ) -> Result<LoginAppMsg, FetchError> {
        let authreq_jsvalue = serde_json::to_string(&authreq)
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise authreq");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);

        opts.body(Some(&authreq_jsvalue));

        let request = Request::new_with_str_and_init("/v1/auth", &opts)?;
        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set content-type header");
        request
            .headers()
            .set("x-kanidm-auth-session-id", session_id.as_str())
            .expect_throw("failed to set x-kanidm-auth-session-id header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
        let status = resp.status();
        let headers = resp.headers();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let state: AuthResponse = jsval.into_serde().expect_throw("Invalid response type.");
            Ok(LoginAppMsg::Next(state))
        } else {
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string()
                .unwrap_or_else(|| "Unhandled error, please report this along with the operation ID below to your administrator. 😔".to_string());
            Ok(LoginAppMsg::Error { emsg, kopid })
        }
    }

    fn render_auth_allowed(&self, ctx: &Context<Self>, idx: usize, allow: &AuthAllowed) -> Html {
        html! {
            <li>
                <button
                    type="button"
                    class="btn btn-dark"
                    onclick={ ctx.link().callback(move |_| LoginAppMsg::Continue(idx)) }
                >{ allow.to_string() }</button>
            </li>
        }
    }

    fn view_state(&self, ctx: &Context<Self>) -> Html {
        let inputvalue = self.inputvalue.clone();
        match &self.state {
            LoginState::Init(enable) => {
                html! {
                    <>
                    <div class="container">
                        <label for="autofocus" class="form-label">{ " Username " }</label>
                        <form
                        onsubmit={ ctx.link().callback(|e: FocusEvent| {
                            console::log!("login::view_state -> Init - prevent_default()".to_string());
                            e.prevent_default();
                            LoginAppMsg::Begin
                        } ) }
                        action="javascript:void(0);"
                        >
                        <div class="input-group mb-3">
                            <input id="autofocus"
                                type="text"
                                class="form-control"
                                value={ inputvalue }
                                disabled={ !enable }
                                oninput={ ctx.link().callback(|e: InputEvent| LoginAppMsg::Input(utils::get_value_from_input_event(e))) }
                            />
                        </div>

                        <div class="input-group mb-3 justify-content-md-center">
                            <button
                                type="submit"
                                class="btn btn-dark"
                                disabled={ !enable }
                            >{" Begin "}</button>
                        </div>
                        </form>
                    </div>
                    </>
                }
            }
            LoginState::Continue(allowed) => {
                html! {
                    <>
                    <div class="container">
                        <p>
                        {" Choose how to proceed: "}
                        </p>
                    </div>
                    <div class="container">
                        <ul class="list-unstyled">
                            { for allowed.iter()
                                .enumerate()
                                .map(|(idx, allow)| self.render_auth_allowed(ctx, idx, allow)) }
                        </ul>
                    </div>
                    </>
                }
            }
            LoginState::Password(enable) => {
                html! {
                    <>
                    <div class="container">
                        <p>
                        {" Password: "}
                        </p>
                    </div>
                    <div class="container">
                        <form class="row g-3"
                            onsubmit={ ctx.link().callback(|e: FocusEvent| {
                                console::log!("login::view_state -> Password - prevent_default()".to_string());
                                e.prevent_default();
                                LoginAppMsg::PasswordSubmit
                            } ) }
                            action="javascript:void(0);"
                        >
                        <div class="col-12">
                            <input
                                id="autofocus"
                                type="password"
                                class="form-control"
                                value={ inputvalue }
                                oninput={ ctx.link().callback(|e: InputEvent| LoginAppMsg::Input(utils::get_value_from_input_event(e))) }
                                disabled={ !enable }
                            />
                            </div>
                            <div class="col-12">
                            <center>
                                <button type="submit" class="btn btn-dark" disabled={ !enable }>{" Submit "}</button>
                            </center>
                            </div>
                        </form>
                    </div>
                    </>
                }
            }
            LoginState::BackupCode(enable) => {
                html! {
                    <>
                    <div class="container">
                        <p>
                        {" Backup Code: "}
                        </p>
                    </div>
                    <div class="container">
                        <form
                            onsubmit={ ctx.link().callback(|e: FocusEvent| {
                                console::log!("login::view_state -> BackupCode - prevent_default()".to_string());
                                e.prevent_default();
                                LoginAppMsg::BackupCodeSubmit
                            } ) }
                            action="javascript:void(0);"
                        >
                            <input
                                id="autofocus"
                                type="text"
                                class="form-control"
                                value={ inputvalue }
                                oninput={ ctx.link().callback(|e: InputEvent| LoginAppMsg::Input(utils::get_value_from_input_event(e))) }
                                disabled={ !enable }
                            />
                            <button type="submit" class="btn btn-dark" disabled={ !enable }>{" Submit "}</button>
                        </form>
                    </div>
                    </>
                }
            }
            LoginState::Totp(state) => {
                html! {
                    <>
                    <div class="container">
                        <p>
                        {" TOTP: "}
                        { if state==&TotpState::Invalid { "can only contain numeric digits" } else { "" } }
                        </p>
                    </div>
                    <div class="container">
                        <form
                            onsubmit={ ctx.link().callback(|e: FocusEvent| {
                                console::log!("login::view_state -> Totp - prevent_default()".to_string());
                                e.prevent_default();
                                LoginAppMsg::TotpSubmit
                            } ) }
                            action="javascript:void(0);"
                        >
                            <input
                                id="autofocus"
                                type="text"
                                class="form-control"
                                value={ inputvalue }
                                oninput={ ctx.link().callback(|e: InputEvent| LoginAppMsg::Input(utils::get_value_from_input_event(e)))}
                                disabled={ state==&TotpState::Disabled }
                            />
                            <button type="submit" class="btn btn-dark" disabled={ state==&TotpState::Disabled }>{" Submit "}</button>
                        </form>
                    </div>
                    </>
                }
            }
            LoginState::Webauthn(challenge) => {
                // Start the navigator parts.
                if let Some(win) = web_sys::window() {
                    let promise = win
                        .navigator()
                        .credentials()
                        .get_with_options(challenge)
                        .expect_throw("Unable to create promise");
                    let fut = JsFuture::from(promise);
                    let linkc = ctx.link().clone();

                    spawn_local(async move {
                        match fut.await {
                            Ok(data) => {
                                let data = PublicKeyCredential::from(
                                    web_sys::PublicKeyCredential::from(data),
                                );
                                linkc.send_message(LoginAppMsg::WebauthnSubmit(data));
                            }
                            Err(e) => {
                                linkc.send_message(LoginAppMsg::Error {
                                    emsg: format!("{:?}", e),
                                    kopid: None,
                                });
                            }
                        }
                    });
                } else {
                    ctx.link().send_message(LoginAppMsg::Error {
                        emsg: "failed to access navigator credentials".to_string(),
                        kopid: None,
                    });
                };

                html! {
                    <div class="container">
                        <p>
                        {" Webauthn "}
                        </p>
                    </div>
                }
            }
            LoginState::Authenticated => {
                let loc = models::pop_return_location();
                // redirect
                console::log!(format!("authenticated, try going to -> {:?}", loc));
                loc.goto(&ctx.link().history().expect_throw("failed to read history"));
                html! {
                    <div class="container">
                        <p>
                            { "Login Success 🎉" }
                        </p>
                    </div>
                }
            }
            LoginState::Denied(msg) => {
                html! {
                <div class="container">
                    <div class="row justify-content-md-center">
                        <div class="alert alert-danger" role="alert">
                            <p><strong>{ "Authentication Denied" }</strong></p>
                            <p>{ msg.as_str() }</p>
                        </div>
                        <div class="col-md-auto">
                          <button type="button" class="btn btn-dark" onclick={ ctx.link().callback(|_| LoginAppMsg::Restart) } >{" Start Again "}</button>
                        </div>
                    </div>
                </div>
                }
            }
            LoginState::UnknownUser => {
                html! {
                    <div class="container">
                        <div class="row justify-content-md-center">
                            <div class="alert alert-danger" role="alert">
                                { "That username was not found. Please try again!" }
                            </div>
                            <div class="col-md-auto">
                                <button type="button"
                                    class="btn btn-dark"
                                    onclick={ ctx.link().callback(|_| LoginAppMsg::Restart) }
                                >
                                {" Start Again "}</button>
                            </div>
                        </div>
                    </div>
                }
            }
            LoginState::Error { emsg, kopid } => {
                html! {
                    <div class="container">
                        <p>
                            { "An error has occured 😔 " }
                        </p>
                        <p>
                            { emsg.as_str() }
                        </p>
                        <p>
                            {
                                if let Some(opid) = kopid.as_ref() {
                                    format!("Operation ID: {}", opid.clone())
                                }
                                else {
                                    "Local Error".to_string() }
                            }
                        </p>
                    </div>
                }
            }
        }
    }
}

impl Component for LoginApp {
    type Message = LoginAppMsg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        console::log!("create".to_string());
        // Assume we are here for a good reason.
        models::clear_bearer_token();
        // Do we have a login hint?
        let inputvalue = models::pop_login_hint().unwrap_or_else(|| "".to_string());
        // Clean any cookies.
        let document = utils::document();

        let html_document = document
            .dyn_into::<web_sys::HtmlDocument>()
            .expect_throw("failed to dyn cast to htmldocument");
        let cookie = html_document
            .cookie()
            .expect_throw("failed to access page cookies");
        console::log!("cookies".to_string());
        console::log!(cookie);

        let state = LoginState::Init(true);
        // startConfetti();

        for x in CLASSES_TO_ADD {
            if let Err(e) = crate::utils::body().class_list().add_1(x) {
                console::log!(format!("class_list add error -> {:?}", e));
            };
        }

        LoginApp {
            inputvalue,
            session_id: "".to_string(),
            state,
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            LoginAppMsg::Input(mut inputvalue) => {
                std::mem::swap(&mut self.inputvalue, &mut inputvalue);
                true
            }
            LoginAppMsg::Restart => {
                // Clear any leftover input
                self.inputvalue = "".to_string();
                self.session_id = "".to_string();
                self.state = LoginState::Init(true);
                true
            }
            LoginAppMsg::Begin => {
                console::log!(format!("begin -> {:?}", self.inputvalue));
                // Disable the button?
                let username = self.inputvalue.clone();
                ctx.link().send_future(async {
                    match Self::auth_init(username).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                self.state = LoginState::Init(false);
                true
            }
            LoginAppMsg::PasswordSubmit => {
                console::log!("At password step".to_string());
                // Disable the button?
                self.state = LoginState::Password(false);
                let authreq = AuthRequest {
                    step: AuthStep::Cred(AuthCredential::Password(self.inputvalue.clone())),
                };
                let session_id = self.session_id.clone();
                ctx.link().send_future(async {
                    match Self::auth_step(authreq, session_id).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                // Clear the password from memory.
                self.inputvalue = "".to_string();
                true
            }
            LoginAppMsg::BackupCodeSubmit => {
                console::log!("backupcode".to_string());
                // Disable the button?
                self.state = LoginState::BackupCode(false);
                let authreq = AuthRequest {
                    step: AuthStep::Cred(AuthCredential::BackupCode(self.inputvalue.clone())),
                };
                let session_id = self.session_id.clone();
                ctx.link().send_future(async {
                    match Self::auth_step(authreq, session_id).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                // Clear the backup code from memory.
                self.inputvalue = "".to_string();
                true
            }
            LoginAppMsg::TotpSubmit => {
                console::log!("totp".to_string());
                // Disable the button?
                match self.inputvalue.parse::<u32>() {
                    Ok(totp) => {
                        self.state = LoginState::Totp(TotpState::Disabled);
                        let authreq = AuthRequest {
                            step: AuthStep::Cred(AuthCredential::Totp(totp)),
                        };
                        let session_id = self.session_id.clone();
                        ctx.link().send_future(async {
                            match Self::auth_step(authreq, session_id).await {
                                Ok(v) => v,
                                Err(v) => v.into(),
                            }
                        });
                    }
                    Err(_) => {
                        self.state = LoginState::Totp(TotpState::Invalid);
                    }
                }

                // Clear the totp from memory.
                self.inputvalue = "".to_string();

                true
            }
            LoginAppMsg::WebauthnSubmit(resp) => {
                console::log!("At webauthn step".to_string());
                let authreq = AuthRequest {
                    step: AuthStep::Cred(AuthCredential::Webauthn(resp)),
                };
                let session_id = self.session_id.clone();
                ctx.link().send_future(async {
                    match Self::auth_step(authreq, session_id).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                // Do not submit here, we need to wait for the next ui transition.
                false
            }
            LoginAppMsg::Start(session_id, resp) => {
                // Clear any leftover input
                self.inputvalue = "".to_string();
                console::log!(format!("start -> {:?} : {:?}", resp, session_id));
                match resp.state {
                    AuthState::Choose(mut mechs) => {
                        self.session_id = session_id;
                        if mechs.len() == 1 {
                            // If it's only one mech, just submit that.
                            let mech = mechs.pop().expect_throw("Memory corruption occured");
                            let authreq = AuthRequest {
                                step: AuthStep::Begin(mech),
                            };
                            let session_id = self.session_id.clone();
                            ctx.link().send_future(async {
                                match Self::auth_step(authreq, session_id).await {
                                    Ok(v) => v,
                                    Err(v) => v.into(),
                                }
                            });
                            // We do NOT need to change state or redraw
                            false
                        } else {
                            // Offer the choices.
                            console::log!("This is currently unimplemented".to_string());
                            self.state = LoginState::Error {
                                emsg: "Unimplemented".to_string(),
                                kopid: None,
                            };
                            true
                        }
                    }
                    AuthState::Denied(reason) => {
                        console::log!(format!("denied -> {:?}", reason));
                        self.state = LoginState::Denied(reason);
                        true
                    }
                    _ => {
                        console::log!("invalid state transition".to_string());
                        self.state = LoginState::Error {
                            emsg: "Invalid UI State Transition".to_string(),
                            kopid: None,
                        };
                        true
                    }
                }
            }
            LoginAppMsg::Next(resp) => {
                // Clear any leftover input
                self.inputvalue = "".to_string();
                console::log!(format!("next -> {:?}", resp));

                // Based on the state we have, we need to chose our steps.
                match resp.state {
                    AuthState::Choose(_mechs) => {
                        console::log!("invalid state transition".to_string());
                        self.state = LoginState::Error {
                            emsg: "Invalid UI State Transition".to_string(),
                            kopid: None,
                        };
                        true
                    }
                    AuthState::Continue(mut allowed) => {
                        if allowed.len() == 1 {
                            // If there is only one, change our state for that input type.
                            match allowed.pop().expect_throw("Memory corruption occured") {
                                AuthAllowed::Anonymous => {
                                    // Just submit this.
                                }
                                AuthAllowed::Password => {
                                    // Go to the password view.
                                    self.state = LoginState::Password(true);
                                }
                                AuthAllowed::BackupCode => {
                                    self.state = LoginState::BackupCode(true);
                                }
                                AuthAllowed::Totp => {
                                    self.state = LoginState::Totp(TotpState::Enabled);
                                }
                                AuthAllowed::Webauthn(challenge) => {
                                    self.state = LoginState::Webauthn(challenge.into())
                                }
                            }
                        } else {
                            // Else, present the options in a choice.
                            console::log!("multiple choices exist".to_string());
                            self.state = LoginState::Continue(allowed);
                        }
                        true
                    }
                    AuthState::Denied(reason) => {
                        console::log!(format!("denied -> {:?}", reason));
                        self.state = LoginState::Denied(reason);
                        true
                    }
                    AuthState::Success(bearer_token) => {
                        // Store the bearer here!
                        models::set_bearer_token(bearer_token);
                        self.state = LoginState::Authenticated;
                        true
                    }
                }
            }
            LoginAppMsg::Continue(idx) => {
                // Are we in the correct internal state?
                console::log!(format!("chose -> {:?}", idx));
                match &self.state {
                    LoginState::Continue(allowed) => {
                        match allowed.get(idx) {
                            Some(AuthAllowed::Anonymous) => {
                                // Just submit this.
                            }
                            Some(AuthAllowed::Password) => {
                                // Go to the password view.
                                self.state = LoginState::Password(true);
                            }
                            Some(AuthAllowed::BackupCode) => {
                                self.state = LoginState::BackupCode(true);
                            }
                            Some(AuthAllowed::Totp) => {
                                self.state = LoginState::Totp(TotpState::Enabled);
                            }
                            Some(AuthAllowed::Webauthn(challenge)) => {
                                self.state = LoginState::Webauthn(challenge.clone().into())
                            }
                            None => {
                                console::log!("invalid allowed mech idx".to_string());
                                self.state = LoginState::Error {
                                    emsg: "Invalid Continue Index".to_string(),
                                    kopid: None,
                                };
                            }
                        }
                    }
                    _ => {
                        console::log!("invalid state transition".to_string());
                        self.state = LoginState::Error {
                            emsg: "Invalid UI State Transition".to_string(),
                            kopid: None,
                        };
                    }
                }
                true
            }
            LoginAppMsg::UnknownUser => {
                // Clear any leftover input
                self.inputvalue = "".to_string();
                console::log!("Unknown user".to_string());
                self.state = LoginState::UnknownUser;
                true
            }
            LoginAppMsg::Error { emsg, kopid } => {
                // Clear any leftover input
                self.inputvalue = "".to_string();
                console::log!(format!("error -> {:?}, {:?}", emsg, kopid));
                self.state = LoginState::Error { emsg, kopid };
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        console::log!("login::view".to_string());
        // How do we add a top level theme?
        /*
        let (width, height): (u32, u32) = if let Some(win) = web_sys::window() {
            let w = win.inner_width().unwrap();
            let h = win.inner_height().unwrap();
            ConsoleService::log(format!("width {:?} {:?}", w, w.as_f64()).as_str());
            ConsoleService::log(format!("height {:?} {:?}", h, h.as_f64()).as_str());
            (w.as_f64().unwrap() as u32, h.as_f64().unwrap() as u32)
        } else {
            ConsoleService::log("Unable to access document window");
            (0, 0)
        };
        let (width, height) = (width.to_string(), height.to_string());
        */

        // <canvas id="confetti-canvas" style="position:absolute" width=width height=height></canvas>

        // May need to set these classes?
        // <body class="html-body form-body">
        // TODO: add the domain_display_name here

        html! {
        <>
        <main class="flex-shrink-0 form-signin">
            <center>
                <img src="/pkg/img/logo-square.svg" alt="Kanidm" class="kanidm_logo"/>
                <h3>{ "Kanidm idm.example.com" } </h3>
            </center>
            { self.view_state(ctx) }
        </main>
        <footer class="footer mt-auto py-3 bg-light text-end">
            <div class="container">
                <span class="text-muted">{ "Powered by "  }<a href="https://kanidm.com">{ "Kanidm" }</a></span>
            </div>
        </footer>
        </>
                }
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        console::log!("login::destroy".to_string());

        for x in CLASSES_TO_ADD {
            if let Err(e) = crate::utils::body().class_list().remove_1(x) {
                console::log!(format!("class_list remove error -> {:?}", e));
            };
        }

        // if let Err(e) = crate::utils::body()
        //     .class_list()
        //     .remove_1("form-signin-body")
        // {
        //     console::log!(format!("class_list remove error -> {:?}", e));
        // }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        crate::utils::autofocus();
        console::log!("login::rendered".to_string());
    }
}
