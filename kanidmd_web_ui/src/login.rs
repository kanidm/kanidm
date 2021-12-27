use anyhow::Error;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use yew::format::Json;
use yew::prelude::*;
use yew_services::fetch::{FetchService, FetchTask, Request, Response};
use yew_services::ConsoleService;

use crate::manager::Route;
use crate::models;

use kanidm_proto::v1::{
    AuthAllowed, AuthCredential, AuthRequest, AuthResponse, AuthState, AuthStep,
};

use webauthn_rs::proto::PublicKeyCredential;

#[wasm_bindgen]
extern "C" {
    fn startConfetti();
}

pub struct LoginApp {
    link: ComponentLink<Self>,
    inputvalue: String,
    ft: Option<FetchTask>,
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
    Error(String, Option<String>),
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
    WebauthnSubmit(PublicKeyCredential),
    Start(String, AuthResponse),
    Next(AuthResponse),
    Continue(usize),
    // DoNothing,
    Error(String, Option<String>),
}

impl LoginApp {
    fn auth_init(&mut self) {
        let callback = self.link.callback(
            move |response: Response<Json<Result<AuthResponse, Error>>>| {
                let (parts, body) = response.into_parts();

                let session_id = parts
                    .headers
                    .get("x-kanidm-auth-session-id")
                    .map(|session_id| session_id.to_str().unwrap().to_string())
                    .unwrap_or_else(|| "".to_string());

                match body {
                    Json(Ok(state)) => LoginAppMsg::Start(session_id, state),
                    Json(Err(e)) => LoginAppMsg::Error(
                        format!("{:?}", e),
                        parts
                            .headers
                            .get("x-kanidm-opid")
                            .map(|id| id.to_str().unwrap().to_string()),
                    ),
                }
            },
        );
        let authreq = AuthRequest {
            step: AuthStep::Init(self.inputvalue.clone()),
        };
        self.ft = Request::post("/v1/auth")
            .header("Content-Type", "application/json")
            .body(Json(&authreq))
            .map_err(|_| ())
            .and_then(|request| FetchService::fetch_binary(request, callback).map_err(|_| ()))
            .map(Some)
            .unwrap_or_else(|_e| None);
    }

    fn auth_step(&mut self, authreq: AuthRequest) {
        let callback = self.link.callback(
            move |response: Response<Json<Result<AuthResponse, Error>>>| {
                let (parts, body) = response.into_parts();

                match body {
                    Json(Ok(state)) => LoginAppMsg::Next(state),
                    Json(Err(e)) => LoginAppMsg::Error(
                        format!("{:?}", e),
                        parts
                            .headers
                            .get("x-kanidm-opid")
                            .map(|id| id.to_str().unwrap().to_string()),
                    ),
                }
            },
        );

        self.ft = Request::post("/v1/auth")
            .header("Content-Type", "application/json")
            .header("x-kanidm-auth-session-id", &self.session_id)
            .body(Json(&authreq))
            .map_err(|_| ())
            .and_then(|request| FetchService::fetch_binary(request, callback).map_err(|_| ()))
            .map(Some)
            .unwrap_or_else(|_e| None);
    }

    fn render_auth_allowed(&self, idx: usize, allow: &AuthAllowed) -> Html {
        html! {
            <li>
                <button
                    type="button"
                    class="btn btn-dark"
                    onclick=self.link.callback(move |_| LoginAppMsg::Continue(idx))
                >{ allow.to_string() }</button>
            </li>
        }
    }

    fn view_state(&self) -> Html {
        let inputvalue = self.inputvalue.clone();
        match &self.state {
            LoginState::Init(enable) => {
                html! {
                    <>
                    <div class="container">
                        <p>
                        {" Username: "}
                        </p>
                    </div>
                    <div class="container">
                        <form
                            onsubmit=self.link.callback(|_| LoginAppMsg::Begin)
                            action="javascript:void(0);"
                        >
                            <input id="autofocus"
                                type="text"
                                class="form-control"
                                value=inputvalue
                                disabled=!enable
                                oninput=self.link.callback(|e: InputData| LoginAppMsg::Input(e.value))
                            />
                            <button
                                type="submit"
                                class="btn btn-dark"
                                disabled=!enable
                            >{" Begin "}</button>
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
                        <ul style="list-style-type: none;">
                            { for allowed.iter()
                                .enumerate()
                                .map(|(idx, allow)| self.render_auth_allowed(idx, allow)) }
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
                        <form
                            onsubmit=self.link.callback(|_| LoginAppMsg::PasswordSubmit)
                            action="javascript:void(0);"
                        >
                            <input id="autofocus" type="password" class="form-control" value=inputvalue oninput=self.link.callback(|e: InputData| LoginAppMsg::Input(e.value)) disabled=!enable />
                            <button type="submit" class="btn btn-dark" disabled=!enable >{" Submit "}</button>
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
                            onsubmit=self.link.callback(|_| LoginAppMsg::BackupCodeSubmit)
                            action="javascript:void(0);"
                        >
                            <input id="autofocus" type="text" class="form-control" value=inputvalue oninput=self.link.callback(|e: InputData| LoginAppMsg::Input(e.value)) disabled=!enable />
                            <button type="submit" class="btn btn-dark" disabled=!enable >{" Submit "}</button>
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
                            onsubmit=self.link.callback(|_| LoginAppMsg::TotpSubmit)
                            action="javascript:void(0);"
                        >
                            <input id="autofocus" type="text" class="form-control" value=inputvalue oninput=self.link.callback(|e: InputData| LoginAppMsg::Input(e.value)) disabled=state==&TotpState::Disabled />
                            <button type="submit" class="btn btn-dark" disabled=state==&TotpState::Disabled >{" Submit "}</button>
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
                        .expect("Unable to create promise");
                    let fut = JsFuture::from(promise);
                    let linkc = self.link.clone();

                    spawn_local(async move {
                        match fut.await {
                            Ok(data) => {
                                let data = PublicKeyCredential::from(
                                    web_sys::PublicKeyCredential::from(data),
                                );
                                linkc.send_message(LoginAppMsg::WebauthnSubmit(data));
                            }
                            Err(e) => {
                                linkc.send_message(LoginAppMsg::Error(format!("{:?}", e), None));
                            }
                        }
                    });
                } else {
                    self.link.send_message(LoginAppMsg::Error(
                        "failed to access navigator credentials".to_string(),
                        None,
                    ));
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
                let loc: Route = models::pop_return_location().into();
                // redirect
                yew_router::push_route(loc);
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
                        <p>
                            { "Authentication Denied" }
                        </p>
                        <p>
                            { msg.as_str() }
                        </p>
                        <button type="button" class="btn btn-dark" onclick=self.link.callback(|_| LoginAppMsg::Restart) >{" Start Again "}</button>
                    </div>
                }
            }
            LoginState::Error(msg, last_opid) => {
                html! {
                    <div class="container">
                        <p>
                            { "An error has occured 😔 " }
                        </p>
                        <p>
                            { msg.as_str() }
                        </p>
                        <p>
                            { if let Some(opid) = last_opid.as_ref() { opid.clone() } else { "Local Error".to_string() } }
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

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        ConsoleService::log("create");

        // Assume we are here for a good reason.
        models::clear_bearer_token();
        // Do we have a login hint?
        let inputvalue = models::pop_login_hint().unwrap_or_else(|| "".to_string());
        // Clean any cookies.
        let document = yew::utils::document();
        let html_document = document
            .dyn_into::<web_sys::HtmlDocument>()
            .expect("failed to dyn cast to htmldocument");
        let cookie = html_document
            .cookie()
            .expect("failed to access page cookies");
        ConsoleService::log("cookies");
        ConsoleService::log(cookie.as_str());

        let state = LoginState::Init(true);
        // startConfetti();

        LoginApp {
            link,
            inputvalue,
            ft: None,
            session_id: "".to_string(),
            state,
        }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            LoginAppMsg::Input(mut inputvalue) => {
                std::mem::swap(&mut self.inputvalue, &mut inputvalue);
                true
            }
            LoginAppMsg::Restart => {
                // Clear any leftover input
                self.inputvalue = "".to_string();
                self.ft = None;
                self.session_id = "".to_string();
                self.state = LoginState::Init(true);
                true
            }
            LoginAppMsg::Begin => {
                ConsoleService::log(format!("begin -> {:?}", self.inputvalue).as_str());
                // Disable the button?
                self.state = LoginState::Init(false);
                self.auth_init();
                true
            }
            LoginAppMsg::PasswordSubmit => {
                ConsoleService::log("password");
                // Disable the button?
                self.state = LoginState::Password(false);
                let authreq = AuthRequest {
                    step: AuthStep::Cred(AuthCredential::Password(self.inputvalue.clone())),
                };
                self.auth_step(authreq);
                // Clear the password from memory.
                self.inputvalue = "".to_string();
                true
            }
            LoginAppMsg::BackupCodeSubmit => {
                ConsoleService::log("backupcode");
                // Disable the button?
                self.state = LoginState::BackupCode(false);
                let authreq = AuthRequest {
                    step: AuthStep::Cred(AuthCredential::BackupCode(self.inputvalue.clone())),
                };
                self.auth_step(authreq);
                // Clear the backup code from memory.
                self.inputvalue = "".to_string();
                true
            }
            LoginAppMsg::TotpSubmit => {
                ConsoleService::log("totp");
                // Disable the button?
                match self.inputvalue.parse::<u32>() {
                    Ok(totp) => {
                        self.state = LoginState::Totp(TotpState::Disabled);
                        let authreq = AuthRequest {
                            step: AuthStep::Cred(AuthCredential::Totp(totp)),
                        };
                        self.auth_step(authreq);
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
                ConsoleService::log("webauthn");
                let authreq = AuthRequest {
                    step: AuthStep::Cred(AuthCredential::Webauthn(resp)),
                };
                self.auth_step(authreq);
                // Do not submit here, we need to wait for the next ui transition.
                false
            }
            LoginAppMsg::Start(session_id, resp) => {
                // Clear any leftover input
                self.inputvalue = "".to_string();
                ConsoleService::log(format!("start -> {:?} : {:?}", resp, session_id).as_str());
                match resp.state {
                    AuthState::Choose(mut mechs) => {
                        self.session_id = session_id;
                        if mechs.len() == 1 {
                            // If it's only one mech, just submit that.
                            let mech = mechs.pop().unwrap();

                            let authreq = AuthRequest {
                                step: AuthStep::Begin(mech),
                            };
                            self.auth_step(authreq);
                            // We do NOT need to change state or redraw
                            false
                        } else {
                            // Offer the choices.
                            ConsoleService::log("unimplemented");
                            self.state = LoginState::Error("Unimplemented".to_string(), None);
                            true
                        }
                    }
                    AuthState::Denied(reason) => {
                        ConsoleService::log(format!("denied -> {:?}", reason).as_str());
                        self.state = LoginState::Denied(reason);
                        true
                    }
                    _ => {
                        ConsoleService::log("invalid state transition");
                        self.state =
                            LoginState::Error("Invalid UI State Transition".to_string(), None);
                        true
                    }
                }
            }
            LoginAppMsg::Next(resp) => {
                // Clear any leftover input
                self.inputvalue = "".to_string();
                ConsoleService::log(format!("next -> {:?}", resp).as_str());
                // Based on the state we have, we need to chose our steps.
                match resp.state {
                    AuthState::Choose(_mechs) => {
                        ConsoleService::log("invalid state transition");
                        self.state =
                            LoginState::Error("Invalid UI State Transition".to_string(), None);
                        true
                    }
                    AuthState::Continue(mut allowed) => {
                        if allowed.len() == 1 {
                            // If there is only one, change our state for that input type.
                            match allowed.pop().unwrap() {
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
                            ConsoleService::log("multiple choices exist");
                            self.state = LoginState::Continue(allowed);
                        }
                        true
                    }
                    AuthState::Denied(reason) => {
                        ConsoleService::log(format!("denied -> {:?}", reason).as_str());
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
                ConsoleService::log(format!("chose -> {:?}", idx).as_str());
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
                                ConsoleService::log("invalid allowed mech idx");
                                self.state =
                                    LoginState::Error("Invalid Continue Index".to_string(), None);
                            }
                        }
                    }
                    _ => {
                        ConsoleService::log("invalid state transition");
                        self.state =
                            LoginState::Error("Invalid UI State Transition".to_string(), None);
                    }
                }
                true
            }
            LoginAppMsg::Error(msg, opid) => {
                // Clear any leftover input
                self.inputvalue = "".to_string();
                ConsoleService::log(format!("error -> {:?}, {:?}", msg, opid).as_str());
                self.state = LoginState::Error(msg, opid);
                true
            }
        }
    }

    fn view(&self) -> Html {
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
        html! {
            <body class="html-body form-body">
                <main class="form-signin">
                    <div class="container">
                        <h2>{ "Kanidm Alpha 🦀 " }</h2>
                    </div>
                    { self.view_state() }
                </main>
            </body>
        }
    }

    fn rendered(&mut self, _first_render: bool) {
        crate::utils::autofocus();
        ConsoleService::log("login::rendered");
    }
}
