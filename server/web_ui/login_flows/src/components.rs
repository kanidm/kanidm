//! Login flow components

// use anyhow::Error;
use gloo::console;
use kanidm_proto::v1::{
    AuthAllowed, AuthCredential, AuthIssueSession, AuthMech, AuthRequest, AuthResponse, AuthState,
    AuthStep,
};
use kanidm_proto::webauthn::PublicKeyCredential;
use kanidmd_web_ui_shared::utils::{autofocus, do_footer};
use kanidmd_web_ui_shared::{add_body_form_classes, logo_img, remove_body_form_classes};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_sys::CredentialRequestOptions;
use yew::prelude::*;
use yew::virtual_dom::VNode;

use kanidmd_web_ui_shared::constants::{
    CLASS_BUTTON_DARK, CLASS_DIV_LOGIN_BUTTON, CLASS_DIV_LOGIN_FIELD, CSS_ALERT_DANGER,
};
use kanidmd_web_ui_shared::models::{
    self, clear_bearer_token, get_login_hint, pop_login_hint, pop_login_remember_me,
    pop_return_location, push_login_remember_me, set_bearer_token,
};
use kanidmd_web_ui_shared::{do_request, error::FetchError, utils, RequestMethod};

pub struct LoginApp {
    state: LoginState,
}

impl Default for LoginApp {
    fn default() -> Self {
        Self {
            state: LoginState::InitLogin {
                enable: true,
                remember_me: false,
                username: String::new(),
            },
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum LoginWorkflow {
    Login,
    #[allow(dead_code)]
    Reauth, // TODO: test/implement reauth
}

impl Default for LoginWorkflow {
    fn default() -> Self {
        Self::Login
    }
}

#[derive(PartialEq, Properties, Default)]
pub struct LoginAppProps {
    pub workflow: LoginWorkflow,
}

#[derive(PartialEq)]
enum TotpState {
    Enabled,
    Disabled,
    Invalid,
}

enum LoginState {
    InitLogin {
        enable: bool,
        remember_me: bool,
        username: String,
    },
    InitReauth {
        enable: bool,
        spn: String,
    },
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
    Error {
        emsg: String,
        kopid: Option<String>,
    },
    UnknownUser,
    Denied(String),
    Authenticated,
}

pub enum LoginAppMsg {
    Restart,
    Begin,
    PasswordSubmit,
    BackupCodeSubmit,
    TotpSubmit,
    PasskeySubmit(PublicKeyCredential),
    SecurityKeySubmit(PublicKeyCredential),
    Start(AuthResponse),
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
                issue: AuthIssueSession::Token,
                privileged: false,
            },
        };
        let req_jsvalue = serde_json::to_string(&authreq)
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise authreq");

        let (kopid, status, value, _) =
            do_request("/v1/auth", RequestMethod::POST, Some(req_jsvalue)).await?;

        if status == 200 {
            let state: AuthResponse = serde_wasm_bindgen::from_value(value)
                .expect_throw("Invalid response type - auth_init::AuthResponse");
            Ok(LoginAppMsg::Start(state))
        } else if status == 404 {
            console::error!(format!(
                "User not found: {:?}. Operation ID: {:?}",
                value.as_string().unwrap_or_default(),
                kopid
            ));
            Ok(LoginAppMsg::UnknownUser)
        } else {
            let emsg = value.as_string().unwrap_or_default();
            Ok(LoginAppMsg::Error { emsg, kopid })
        }
    }

    async fn reauth_init() -> Result<LoginAppMsg, FetchError> {
        let issue = AuthIssueSession::Token;
        let authreq_jsvalue = serde_json::to_string(&issue)
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise authreq");
        let url = "/v1/reauth";
        let (kopid, status, value, _) =
            do_request(url, RequestMethod::POST, Some(authreq_jsvalue)).await?;

        if status == 200 {
            let state: AuthResponse = serde_wasm_bindgen::from_value(value)
                .expect_throw("Invalid response type - auth_init::AuthResponse");
            Ok(LoginAppMsg::Next(state))
        } else if status == 404 {
            console::error!(format!(
                "User not found: {:?}. Operation ID: {:?}",
                value.as_string(),
                kopid
            ));
            Ok(LoginAppMsg::UnknownUser)
        } else {
            let emsg = value.as_string().unwrap_or_default();
            Ok(LoginAppMsg::Error { emsg, kopid })
        }
    }

    async fn auth_step(authreq: AuthRequest) -> Result<LoginAppMsg, FetchError> {
        let authreq_jsvalue = serde_json::to_string(&authreq)
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise authreq");

        let (kopid, status, value, _) =
            do_request("/v1/auth", RequestMethod::POST, Some(authreq_jsvalue)).await?;

        if status == 200 {
            let state: AuthResponse = serde_wasm_bindgen::from_value(value)
                .map_err(|e| {
                    console::error!(format!("auth_step::AuthResponse: {:?}", e));
                    e
                })
                .expect_throw("Invalid response type - auth_step::AuthResponse");
            Ok(LoginAppMsg::Next(state))
        } else {
            let emsg = value.as_string()
                .unwrap_or_else(|| "Unhandled error, please report this along with the operation ID below to your administrator. 😔".to_string());
            Ok(LoginAppMsg::Error { emsg, kopid })
        }
    }

    /// Renders the "Start again" button
    fn button_start_again(&self, ctx: &Context<Self>) -> VNode {
        html! {
            <div class="col-md-auto text-center">
                // TODO: this doesn't seem to work if you failed to login
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
                <div class={CSS_ALERT_DANGER} role="alert">
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
        match &self.state {
            LoginState::InitLogin {
                enable,
                remember_me,
                username,
            } => {
                let username = username.clone();

                html! {
                    <>
                    <div class="container">
                        <label for="username" class="form-label">{ "Username" }</label>
                        <form id="login"
                        onsubmit={ ctx.link().callback(|e: SubmitEvent| {
                            #[cfg(debug_assertions)]
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
                                type="text"
                                autocomplete="username"
                                value={ username }
                            />
                        </div>

                        <div class="mb-3 form-check form-switch">
                            <input
                                type="checkbox"
                                class="form-check-input"
                                role="switch"
                                id="remember_me_check"
                                disabled={ !enable }
                                checked={ *remember_me }
                            />
                            <label class="form-check-label" for="remember_me_check">{ "Remember my Username" }</label>
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
            LoginState::InitReauth { enable, spn } => {
                let msg = format!("Reauthenticate as {} to continue", spn);
                html! {
                    <>
                    <div class="container">
                        <p>{ msg }</p>
                        <form id="login"
                        onsubmit={ ctx.link().callback(|e: SubmitEvent| {
                            #[cfg(debug_assertions)]
                            console::debug!("login::view_state -> Init - prevent_default()".to_string());
                            e.prevent_default();
                            LoginAppMsg::Begin
                        } ) }
                        >
                        <div class={CLASS_DIV_LOGIN_BUTTON}>
                            <button
                                type="submit"
                                class="autofocus form-control btn btn-dark"
                                autofocus=true
                                id="begin"
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
                        <form id="login"
                            onsubmit={ ctx.link().callback(|e: SubmitEvent| {
                                console::debug!("login::view_state -> Password - prevent_default()".to_string());
                                e.prevent_default();
                                LoginAppMsg::PasswordSubmit
                            } ) }
                        >
                        <div>
                            <input hidden=true type="text" autocomplete="username" />
                        </div>
                        <div class={CLASS_DIV_LOGIN_FIELD}>
                            <input
                                autofocus=true
                                class="autofocus form-control"
                                disabled={ !enable }
                                id="password"
                                name="password"
                                type="password"
                                autocomplete="current-password"
                                value=""
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
                        <form id="login"
                            onsubmit={ ctx.link().callback(|e: SubmitEvent| {
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
                                type="text"
                                autocomplete="off"
                                value=""
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
                        <form id="login"
                            onsubmit={ ctx.link().callback(|e: SubmitEvent| {
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
                            type="text"
                            autocomplete="off"
                            value=""
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
                let loc = pop_return_location();
                // redirect to the "return location"
                #[cfg(debug_assertions)]
                console::debug!(format!("authenticated, try going to -> {:?}", loc));

                let window = gloo_utils::window();
                window
                    .location()
                    .set_href(&loc)
                    .expect_throw(&format!("failed to set location to {}", loc));
                // this isn't likely to actually render but we might as well...
                html! {
                    <div class="alert alert-success">
                        <h3>{ "Login Success 🎉" }</h3>
                        <a href={loc}>{"Click here to continue if you aren't redirected..."}</a>
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
                "An error has occurred 😔 ",
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
    type Properties = LoginAppProps;

    fn create(ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("login::create".to_string());

        let workflow = &ctx.props().workflow;
        let state = match workflow {
            LoginWorkflow::Login => {
                // Assume we are here for a good reason.
                // -- clear the bearer to prevent conflict
                clear_bearer_token(); // TODO: one day only clear this when it gets a 401 response

                // Do we have a login hint?
                let (username, remember_me) = get_login_hint()
                    .map(|user| (user, false))
                    .or_else(|| models::get_login_remember_me().map(|user| (user, true)))
                    .unwrap_or_default();

                LoginState::InitLogin {
                    enable: true,
                    remember_me,
                    username,
                }
            }
            LoginWorkflow::Reauth => {
                // Unlike login, don't clear tokens or cookies - these are needed during the operation
                // to actually start the reauth as the same user.

                match get_login_hint() {
                    Some(spn) => LoginState::InitReauth { enable: true, spn },
                    None => LoginState::Error {
                        emsg: "Client Error - No login hint available".to_string(),
                        kopid: None,
                    },
                }
            }
        };

        add_body_form_classes!();

        LoginApp { state }
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            LoginAppMsg::Restart => {
                // Clear any leftover input. Reset to the remembered username if any.
                match &ctx.props().workflow {
                    LoginWorkflow::Login => {
                        let (username, remember_me) = get_login_hint()
                            .map(|user| (user, false))
                            .or_else(|| models::get_login_remember_me().map(|user| (user, true)))
                            .unwrap_or_default();

                        self.state = LoginState::InitLogin {
                            enable: true,
                            remember_me,
                            username,
                        };
                    }
                    LoginWorkflow::Reauth => {
                        match get_login_hint() {
                            Some(spn) => LoginState::InitReauth { enable: true, spn },
                            None => LoginState::Error {
                                emsg: "Client Error - No login hint available".to_string(),
                                kopid: None,
                            },
                        };
                    }
                }
                true
            }
            LoginAppMsg::Begin => {
                match &ctx.props().workflow {
                    LoginWorkflow::Login => {
                        // Disable the button?
                        let username =
                            utils::get_value_from_element_id("username").unwrap_or_default();

                        #[cfg(debug_assertions)]
                        console::debug!(format!("begin for username -> {:?}", username));

                        // If the remember-me was checked, stash it here.
                        // If it was false, clear existing data.

                        let remember_me = if utils::get_inputelement_by_id("remember_me_check")
                            .map(|element| element.checked())
                            .unwrap_or(false)
                        {
                            push_login_remember_me(username.clone());
                            true
                        } else {
                            pop_login_remember_me();
                            false
                        };

                        #[cfg(debug_assertions)]
                        console::debug!(format!("begin remember_me -> {:?}", remember_me));

                        let username_clone = username.clone();

                        ctx.link().send_future(async {
                            match Self::auth_init(username_clone).await {
                                Ok(v) => v,
                                Err(v) => v.into(),
                            }
                        });

                        self.state = LoginState::InitLogin {
                            enable: false,
                            remember_me,
                            username,
                        };
                    }
                    LoginWorkflow::Reauth => {
                        ctx.link().send_future(async {
                            match Self::reauth_init().await {
                                Ok(v) => v,
                                Err(v) => v.into(),
                            }
                        });

                        self.state = match get_login_hint() {
                            Some(spn) => LoginState::InitReauth { enable: false, spn },
                            None => LoginState::Error {
                                emsg: "Client Error - No login hint available".to_string(),
                                kopid: None,
                            },
                        };
                    }
                }
                true
            }
            LoginAppMsg::PasswordSubmit => {
                let password = utils::get_value_from_element_id("password").unwrap_or_default();

                #[cfg(debug_assertions)]
                console::debug!("password step".to_string());
                // Disable the button?
                self.state = LoginState::Password(false);
                let authreq = AuthRequest {
                    step: AuthStep::Cred(AuthCredential::Password(password)),
                };
                ctx.link().send_future(async {
                    match Self::auth_step(authreq).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                true
            }
            LoginAppMsg::BackupCodeSubmit => {
                let backup_code =
                    utils::get_value_from_element_id("backup_code").unwrap_or_default();

                #[cfg(debug_assertions)]
                console::debug!("backup_code".to_string());
                // Disable the button?
                self.state = LoginState::BackupCode(false);
                let authreq = AuthRequest {
                    step: AuthStep::Cred(AuthCredential::BackupCode(backup_code)),
                };
                ctx.link().send_future(async {
                    match Self::auth_step(authreq).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                true
            }
            LoginAppMsg::TotpSubmit => {
                let totp_str = utils::get_value_from_element_id("totp").unwrap_or_default();

                #[cfg(debug_assertions)]
                console::debug!("totp".to_string());
                // Disable the button?
                match totp_str.parse::<u32>() {
                    Ok(totp) => {
                        self.state = LoginState::Totp(TotpState::Disabled);
                        let authreq = AuthRequest {
                            step: AuthStep::Cred(AuthCredential::Totp(totp)),
                        };
                        ctx.link().send_future(async {
                            match Self::auth_step(authreq).await {
                                Ok(v) => v,
                                Err(v) => v.into(),
                            }
                        });
                    }
                    Err(_) => {
                        self.state = LoginState::Totp(TotpState::Invalid);
                    }
                }

                true
            }
            LoginAppMsg::SecurityKeySubmit(resp) => {
                #[cfg(debug_assertions)]
                console::debug!("At securitykey step".to_string());
                let authreq = AuthRequest {
                    step: AuthStep::Cred(AuthCredential::SecurityKey(Box::new(resp))),
                };
                ctx.link().send_future(async {
                    match Self::auth_step(authreq).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                // Do not submit here, we need to wait for the next ui transition.
                false
            }
            LoginAppMsg::PasskeySubmit(resp) => {
                #[cfg(debug_assertions)]
                console::debug!("At passkey step".to_string());
                let authreq = AuthRequest {
                    step: AuthStep::Cred(AuthCredential::Passkey(Box::new(resp))),
                };
                ctx.link().send_future(async {
                    match Self::auth_step(authreq).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                // Do not submit here, we need to wait for the next ui transition.
                false
            }
            LoginAppMsg::Start(resp) => {
                // Clear any leftover input
                #[cfg(debug_assertions)]
                console::debug!(format!("start -> {:?}", resp));
                match resp.state {
                    AuthState::Choose(mut mechs) => {
                        if mechs.len() == 1 {
                            // If it's only one mech, just submit that.
                            let mech = mechs.pop().expect_throw("Memory corruption occurred");
                            let authreq = AuthRequest {
                                step: AuthStep::Begin(mech),
                            };
                            ctx.link().send_future(async {
                                match Self::auth_step(authreq).await {
                                    Ok(v) => v,
                                    Err(v) => v.into(),
                                }
                            });
                            // We do NOT need to change state or redraw
                            false
                        } else {
                            #[cfg(debug_assertions)]
                            console::debug!("multiple mechs exist".to_string());
                            self.state = LoginState::Select(mechs);
                            true
                        }
                    }
                    AuthState::Denied(reason) => {
                        #[cfg(debug_assertions)]
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
                #[cfg(debug_assertions)]
                console::debug!(format!("chose -> {:?}", idx));
                match &self.state {
                    LoginState::Select(allowed) => match allowed.get(idx) {
                        Some(mech) => {
                            let authreq = AuthRequest {
                                step: AuthStep::Begin(mech.clone()),
                            };
                            ctx.link().send_future(async {
                                match Self::auth_step(authreq).await {
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
                #[cfg(debug_assertions)]
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
                            match allowed.pop().expect_throw("Memory corruption occurred") {
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
                            #[cfg(debug_assertions)]
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
                    AuthState::Success(bearer_token) => {
                        // Store the bearer here!
                        // We need to format the bearer onto it.
                        let bearer_token = format!("Bearer {}", bearer_token);
                        set_bearer_token(bearer_token);
                        self.state = LoginState::Authenticated;
                        true
                    }
                }
            }
            LoginAppMsg::Continue(idx) => {
                // Are we in the correct internal state?
                #[cfg(debug_assertions)]
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
                console::warn!("Unknown user".to_string());
                self.state = LoginState::UnknownUser;
                true
            }
            LoginAppMsg::Error { emsg, kopid } => {
                // Clear any leftover input
                console::error!(format!("error -> {:?}, {:?}", emsg, kopid));
                self.state = LoginState::Error { emsg, kopid };
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        #[cfg(debug_assertions)]
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
                {logo_img()}
                // TODO: replace this with a call to domain info
                // More likely we should have this passed in from the props when we start.
                <h3>{ "Kanidm" }</h3>
            </center>
            { self.view_state(ctx) }
        </main>
        { do_footer() }
        </>
        }
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        #[cfg(debug_assertions)]
        console::debug!("login::destroy".to_string());

        // Done with this, clear it.
        let _ = pop_login_hint();

        remove_body_form_classes!();
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("login::rendered".to_string());
        // Force autofocus on elements that need it if present.
        autofocus("username");
        autofocus("password");
        autofocus("backup_code");
        autofocus("otp");
        autofocus("begin");
    }
}
