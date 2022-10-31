// use anyhow::Error;
use gloo::console;
use kanidm_proto::v1::{
    AuthAllowed, AuthCredential, AuthIssueSession, AuthMech, AuthRequest, AuthResponse, AuthState,
    AuthStep,
};
use kanidm_proto::webauthn::PublicKeyCredential;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::{
    CredentialRequestOptions, Request, RequestCredentials, RequestInit, RequestMode, Response,
};
use yew::prelude::*;
use yew::virtual_dom::VNode;
use yew_router::prelude::*;

use crate::constants::{CLASS_BUTTON_DARK, CLASS_DIV_LOGIN_BUTTON, CLASS_DIV_LOGIN_FIELD};
use crate::error::FetchError;
use crate::{models, utils};

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
    // Select between different cred types, either password (and MFA) or Passkey
    Select(Vec<AuthMech>),
    // The choices of authentication mechanism.
    Continue(Vec<AuthAllowed>),
    // The different methods
    Password(bool),
    BackupCode(bool),
    Totp(TotpState),
    Passkey(CredentialRequestOptions),
    SecurityKey(CredentialRequestOptions),
    // Error, state handling.
    Error { emsg: String, kopid: Option<String> },
    UnknownUser,
    Denied(String),
    Authenticated,
}

pub enum LoginAppMsg {
    Input(String),
    Restart,
    Begin,
    PasswordSubmit,
    BackupCodeSubmit,
    TotpSubmit,
    PasskeySubmit(PublicKeyCredential),
    SecurityKeySubmit(PublicKeyCredential),
    Start(String, AuthResponse),
    Next(AuthResponse),
    Continue(usize),
    Select(usize),
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
            step: AuthStep::Init2 {
                username,
                issue: AuthIssueSession::Cookie,
            },
        };
        let authreq_jsvalue = serde_json::to_string(&authreq)
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise authreq");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);
        opts.credentials(RequestCredentials::SameOrigin);

        opts.body(Some(&authreq_jsvalue));

        let request = Request::new_with_str_and_init("/v1/auth", &opts)?;
        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value
            .dyn_into()
            .expect_throw("Invalid response type - auth_init::Response");
        let status = resp.status();
        let headers = resp.headers();

        if status == 200 {
            let session_id = headers
                .get("x-kanidm-auth-session-id")
                .ok()
                .flatten()
                .unwrap_or_else(|| "".to_string());
            let jsval = JsFuture::from(resp.json()?).await?;
            let state: AuthResponse = serde_wasm_bindgen::from_value(jsval)
                .expect_throw("Invalid response type - auth_init::AuthResponse");
            Ok(LoginAppMsg::Start(session_id, state))
        } else if status == 404 {
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            console::error!(format!(
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
        opts.credentials(RequestCredentials::SameOrigin);

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
        let resp: Response = resp_value
            .dyn_into()
            .expect_throw("Invalid response type - auth_step::Response");
        let status = resp.status();
        let headers = resp.headers();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let state: AuthResponse = serde_wasm_bindgen::from_value(jsval)
                .map_err(|e| {
                    console::error!(format!("auth_step::AuthResponse: {:?}", e));
                    e
                })
                .expect_throw("Invalid response type - auth_step::AuthResponse");
            Ok(LoginAppMsg::Next(state))
        } else {
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string()
                .unwrap_or_else(|| "Unhandled error, please report this along with the operation ID below to your administrator. 😔".to_string());
            Ok(LoginAppMsg::Error { emsg, kopid })
        }
    }

    /// Renders the "Start again" button
    fn button_start_again(&self, ctx: &Context<Self>) -> VNode {
        html! {
            <div class="col-md-auto text-center">
                <button type="button" class={CLASS_BUTTON_DARK} onclick={ ctx.link().callback(|_| LoginAppMsg::Restart) } >{" Start Again "}</button>
            </div>
        }
    }

    fn render_auth_allowed(&self, ctx: &Context<Self>, idx: usize, allow: &AuthAllowed) -> Html {
        html! {
            <li class="text-center mb-2">
                <button
                    type="button"
                    class={CLASS_BUTTON_DARK}
                    onclick={ ctx.link().callback(move |_| LoginAppMsg::Continue(idx)) }
                >{ allow.to_string() }</button>
            </li>
        }
    }

    fn render_mech_select(&self, ctx: &Context<Self>, idx: usize, allow: &AuthMech) -> Html {
        html! {
            <li class="text-center mb-2">
                <button
                    type="button"
                    class={CLASS_BUTTON_DARK}
                    onclick={ ctx.link().callback(move |_| LoginAppMsg::Select(idx)) }
                >{ allow.to_string() }</button>
            </li>
        }
    }

    /// shows an error-alert in a bootstrap alert container
    fn do_alert_error(
        &self,
        alert_title: &str,
        alert_message: Option<&str>,
        ctx: &Context<Self>,
    ) -> VNode {
        html! {
        <div class="container">
            <div class="row justify-content-md-center">
                <div class="alert alert-danger" role="alert">
                    <p><strong>{ alert_title }</strong></p>
                    if let Some(value) = alert_message {
                        <p>{ value }</p>
                    }
                </div>
                { self.button_start_again(ctx) }
            </div>
        </div>
        }
    }

    fn view_state(&self, ctx: &Context<Self>) -> Html {
        let inputvalue = self.inputvalue.clone();
        match &self.state {
            LoginState::Init(enable) => {
                html! {
                    <>
                    <div class="container">
                        <label for="username" class="form-label">{ "Username" }</label>
                        <form
                        onsubmit={ ctx.link().callback(|e: FocusEvent| {
                            #[cfg(debug)]
                            console::debug!("login::view_state -> Init - prevent_default()".to_string());
                            e.prevent_default();
                            LoginAppMsg::Begin
                        } ) }
                        >
                        <div class={CLASS_DIV_LOGIN_FIELD}>
                            <input
                                autofocus=true
                                class="autofocus form-control"
                                disabled={ !enable }
                                id="username"
                                name="username"
                                oninput={ ctx.link().callback(|e: InputEvent| LoginAppMsg::Input(utils::get_value_from_input_event(e))) }
                                type="text"
                                value={ inputvalue }
                            />
                        </div>

                        <div class={CLASS_DIV_LOGIN_BUTTON}>
                            <button
                                type="submit"
                                class={CLASS_BUTTON_DARK}
                                disabled={ !enable }
                            >{" Begin "}</button>
                        </div>
                        </form>
                    </div>
                    </>
                }
            }
            // Selecting between password (and MFA) or Passkey
            LoginState::Select(mechs) => {
                html! {
                    <>
                    <div class="container">
                        <p>
                        {" Which credential would you like to use? "}
                        </p>
                    </div>
                    <div class="container">
                        <ul class="list-unstyled">
                            { for mechs.iter()
                                .enumerate()
                                .map(|(idx, mech)| self.render_mech_select(ctx, idx, mech)) }
                        </ul>
                    </div>
                    </>
                }
            }
            LoginState::Continue(allowed) => {
                html! {
                    <>
                    <div class="container">
                        <p>
                        {"Choose how to proceed:"}
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
                        <label for="password" class="form-label">{ "Password" }</label>
                        <form
                            onsubmit={ ctx.link().callback(|e: FocusEvent| {
                                console::debug!("login::view_state -> Password - prevent_default()".to_string());
                                e.prevent_default();
                                LoginAppMsg::PasswordSubmit
                            } ) }
                        >
                        <div class={CLASS_DIV_LOGIN_FIELD}>
                            <input
                                autofocus=true
                                class="autofocus form-control"
                                disabled={ !enable }
                                id="password"
                                name="password"
                                oninput={ ctx.link().callback(|e: InputEvent| LoginAppMsg::Input(utils::get_value_from_input_event(e))) }
                                type="password"
                                value={ inputvalue }
                            />
                            </div>
                            <div class={CLASS_DIV_LOGIN_BUTTON}>
                                <button type="submit" class={CLASS_BUTTON_DARK} disabled={ !enable }>{ "Submit" }</button>
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
                        <label for="backup_code" class="form-label">
                        {"Backup Code"}
                        </label>
                        <form
                            onsubmit={ ctx.link().callback(|e: FocusEvent| {
                                console::debug!("login::view_state -> BackupCode - prevent_default()".to_string());
                                e.prevent_default();
                                LoginAppMsg::BackupCodeSubmit
                            } ) }
                        >
                        <div class={CLASS_DIV_LOGIN_FIELD}>
                            <input
                                autofocus=true
                                class="autofocus form-control"
                                disabled={ !enable }
                                id="backup_code"
                                name="backup_code"
                                oninput={ ctx.link().callback(|e: InputEvent| LoginAppMsg::Input(utils::get_value_from_input_event(e))) }
                                type="text"
                                value={ inputvalue }
                            />
                            </div>
                            <div class={CLASS_DIV_LOGIN_BUTTON}>
                                <button type="submit" class={CLASS_BUTTON_DARK}>{" Submit "}</button>
                            </div>
                        </form>
                    </div>
                    </>
                }
            }
            LoginState::Totp(state) => {
                html! {
                    <>
                    <div class="container">
                        <label for="totp" class="form-label">{"TOTP"}</label>
                        <form
                            onsubmit={ ctx.link().callback(|e: FocusEvent| {
                                console::debug!("login::view_state -> Totp - prevent_default()".to_string());
                                e.prevent_default();
                                LoginAppMsg::TotpSubmit
                            } ) }
                        >
                        <div class={CLASS_DIV_LOGIN_FIELD}>
                        <input
                            autofocus=true
                            class="autofocus form-control"
                            disabled={ state==&TotpState::Disabled }
                            id="totp"
                            name="totp"
                            oninput={ ctx.link().callback(|e: InputEvent| LoginAppMsg::Input(utils::get_value_from_input_event(e)))}
                            type="text"
                            value={ inputvalue }
                            />
                        </div>
                            <div class={CLASS_DIV_LOGIN_BUTTON}>
                            <button type="submit" class={CLASS_BUTTON_DARK} disabled={ state==&TotpState::Disabled }>{" Submit "}</button>
                            </div>
                        </form>
                    </div>
                    </>
                }
            }
            LoginState::SecurityKey(challenge) => {
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
                                linkc.send_message(LoginAppMsg::SecurityKeySubmit(data));
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
                        {"Security Key"}
                        </p>
                    </div>
                }
            }
            LoginState::Passkey(challenge) => {
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
                                linkc.send_message(LoginAppMsg::PasskeySubmit(data));
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
                    <div class="container text-center">
                        <p>
                        {"Prompting for Passkey authentication..."}
                        </p>
                    </div>
                }
            }
            LoginState::Authenticated => {
                let loc = models::pop_return_location();
                // redirect
                #[cfg(debug)]
                console::debug!(format!("authenticated, try going to -> {:?}", loc));
                loc.goto(&ctx.link().history().expect_throw("failed to read history"));
                html! {
                    <div class="alert alert-success">
                        <h3>{ "Login Success 🎉" }</h3>
                    </div>
                }
            }
            LoginState::Denied(msg) => {
                self.do_alert_error("Authentication Denied", Some(msg.as_str()), ctx)
            }
            LoginState::UnknownUser => {
                self.do_alert_error("Username not found", Some("Please try again"), ctx)
            }
            LoginState::Error { emsg, kopid } => self.do_alert_error(
                "An error has occured 😔 ",
                Some(
                    format!(
                        "{}\n\n{}",
                        emsg.as_str(),
                        if let Some(opid) = kopid.as_ref() {
                            format!("Operation ID: {}", opid.clone())
                        } else {
                            "Error occurred client-side.".to_string()
                        }
                    )
                    .as_str(),
                ),
                ctx,
            ),
        }
    }
}

impl Component for LoginApp {
    type Message = LoginAppMsg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        #[cfg(debug)]
        console::debug!("create".to_string());
        // Assume we are here for a good reason.
        // -- clear the bearer to prevent conflict
        models::clear_bearer_token();
        // Do we have a login hint?
        let inputvalue = models::pop_login_hint().unwrap_or_else(|| "".to_string());

        #[cfg(debug)]
        {
            let document = utils::document();
            let html_document = document
                .dyn_into::<web_sys::HtmlDocument>()
                .expect_throw("failed to dyn cast to htmldocument");
            let cookie = html_document
                .cookie()
                .expect_throw("failed to access page cookies");
            console::debug!("cookies".to_string());
            console::debug!(cookie);
        }
        // Clean any cookies.
        // TODO: actually check that it's cleaning the cookies.

        let state = LoginState::Init(true);

        add_body_form_classes!();

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
                #[cfg(debug)]
                console::debug!(format!("begin -> {:?}", self.inputvalue));
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
                #[cfg(debug)]
                console::debug!("At password step".to_string());
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
                #[cfg(debug)]
                console::debug!("backupcode".to_string());
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
                #[cfg(debug)]
                console::debug!("totp".to_string());
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
            LoginAppMsg::SecurityKeySubmit(resp) => {
                #[cfg(debug)]
                console::debug!("At securitykey step".to_string());
                let authreq = AuthRequest {
                    step: AuthStep::Cred(AuthCredential::SecurityKey(resp)),
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
            LoginAppMsg::PasskeySubmit(resp) => {
                #[cfg(debug)]
                console::debug!("At passkey step".to_string());
                let authreq = AuthRequest {
                    step: AuthStep::Cred(AuthCredential::Passkey(resp)),
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
                #[cfg(debug)]
                console::debug!(format!("start -> {:?} : {:?}", resp, session_id));
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
                            #[cfg(debug)]
                            console::debug!("multiple mechs exist".to_string());
                            self.state = LoginState::Select(mechs);
                            true
                        }
                    }
                    AuthState::Denied(reason) => {
                        #[cfg(debug)]
                        console::debug!(format!("denied -> {:?}", reason));
                        self.state = LoginState::Denied(reason);
                        true
                    }
                    _ => {
                        console::error!("invalid state transition".to_string());
                        self.state = LoginState::Error {
                            emsg: "Invalid UI State Transition".to_string(),
                            kopid: None,
                        };
                        true
                    }
                }
            }
            LoginAppMsg::Select(idx) => {
                #[cfg(debug)]
                console::debug!(format!("chose -> {:?}", idx));
                match &self.state {
                    LoginState::Select(allowed) => match allowed.get(idx) {
                        Some(mech) => {
                            let authreq = AuthRequest {
                                step: AuthStep::Begin(mech.clone()),
                            };
                            let session_id = self.session_id.clone();
                            ctx.link().send_future(async {
                                match Self::auth_step(authreq, session_id).await {
                                    Ok(v) => v,
                                    Err(v) => v.into(),
                                }
                            });
                        }
                        None => {
                            console::error!("invalid allowed mech idx".to_string());
                            self.state = LoginState::Error {
                                emsg: "Invalid Continue Index".to_string(),
                                kopid: None,
                            };
                        }
                    },
                    _ => {
                        console::error!("invalid state transition".to_string());
                        self.state = LoginState::Error {
                            emsg: "Invalid UI State Transition".to_string(),
                            kopid: None,
                        };
                    }
                };
                true
            }
            LoginAppMsg::Next(resp) => {
                // Clear any leftover input
                self.inputvalue = "".to_string();
                #[cfg(debug)]
                console::debug!(format!("next -> {:?}", resp));

                // Based on the state we have, we need to chose our steps.
                match resp.state {
                    AuthState::Choose(_mechs) => {
                        console::error!("invalid state transition".to_string());
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
                                AuthAllowed::SecurityKey(challenge) => {
                                    self.state = LoginState::SecurityKey(challenge.into())
                                }
                                AuthAllowed::Passkey(challenge) => {
                                    self.state = LoginState::Passkey(challenge.into())
                                }
                            }
                        } else {
                            // Else, present the options in a choice.
                            #[cfg(debug)]
                            console::debug!("multiple choices exist".to_string());
                            self.state = LoginState::Continue(allowed);
                        }
                        true
                    }
                    AuthState::Denied(reason) => {
                        console::error!(format!("denied -> {:?}", reason));
                        self.state = LoginState::Denied(reason);
                        true
                    }
                    AuthState::Success(_bearer_token) => {
                        // Store the bearer here!
                        /*
                        models::set_bearer_token(bearer_token);
                        self.state = LoginState::Authenticated;
                        true
                        */
                        self.state = LoginState::Error {
                            emsg: "Invalid Issued Session Type, expected cookie".to_string(),
                            kopid: None,
                        };
                        true
                    }
                    AuthState::SuccessCookie => {
                        self.state = LoginState::Authenticated;
                        true
                    }
                }
            }
            LoginAppMsg::Continue(idx) => {
                // Are we in the correct internal state?
                #[cfg(debug)]
                console::debug!(format!("chose -> {:?}", idx));
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
                            Some(AuthAllowed::SecurityKey(challenge)) => {
                                self.state = LoginState::SecurityKey(challenge.clone().into())
                            }
                            Some(AuthAllowed::Passkey(challenge)) => {
                                self.state = LoginState::Passkey(challenge.clone().into())
                            }
                            None => {
                                console::error!("invalid allowed mech idx".to_string());
                                self.state = LoginState::Error {
                                    emsg: "Invalid Continue Index".to_string(),
                                    kopid: None,
                                };
                            }
                        }
                    }
                    _ => {
                        console::error!("invalid state transition".to_string());
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
                console::warn!("Unknown user".to_string());
                self.state = LoginState::UnknownUser;
                true
            }
            LoginAppMsg::Error { emsg, kopid } => {
                // Clear any leftover input
                self.inputvalue = "".to_string();
                console::error!(format!("error -> {:?}, {:?}", emsg, kopid));
                self.state = LoginState::Error { emsg, kopid };
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        #[cfg(debug)]
        console::debug!("login::view".to_string());
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
                // TODO: replace this with a call to domain info
                <h3>{ "Kanidm" }</h3>
            </center>
            { self.view_state(ctx) }
        </main>
        { crate::utils::do_footer() }
        </>
        }
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        #[cfg(debug)]
        console::debug!("login::destroy".to_string());
        remove_body_form_classes!();
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug)]
        console::debug!("login::rendered".to_string());
    }
}
