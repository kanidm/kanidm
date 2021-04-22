use anyhow::Error;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::{spawn_local, JsFuture};
use yew::format::Json;
use yew::prelude::*;
use yew::services::fetch::{FetchService, FetchTask, Request, Response};
use yew::services::{ConsoleService, StorageService};

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
    lstorage: StorageService,
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

    // MechChoice
    // CredChoice
    Password(bool),
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
    TotpSubmit,
    WebauthnSubmit(PublicKeyCredential),
    Start(String, AuthResponse),
    Next(AuthResponse),
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
            .map(|ft| Some(ft))
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
            .map(|ft| Some(ft))
            .unwrap_or_else(|_e| None);
    }

    fn view_state(&self) -> Html {
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
                        <div>
                            <input id="username" type="text" class="form-control" value=self.inputvalue oninput=self.link.callback(|e: InputData| LoginAppMsg::Input(e.value)) disabled=!enable />
                            <button type="button" class="btn btn-dark" onclick=self.link.callback(|_| LoginAppMsg::Begin) disabled=!enable >{" Begin "}</button>
                        </div>
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
                        <div>
                            <input id="password" type="password" class="form-control" value=self.inputvalue oninput=self.link.callback(|e: InputData| LoginAppMsg::Input(e.value)) disabled=!enable />
                            <button type="button" class="btn btn-dark" onclick=self.link.callback(|_| LoginAppMsg::PasswordSubmit) disabled=!enable >{" Submit "}</button>
                        </div>
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
                        <div>
                            <input id="totp" type="text" class="form-control" value=self.inputvalue oninput=self.link.callback(|e: InputData| LoginAppMsg::Input(e.value)) disabled=state==&TotpState::Disabled />
                            <button type="button" class="btn btn-dark" onclick=self.link.callback(|_| LoginAppMsg::TotpSubmit) disabled=state==&TotpState::Disabled >{" Submit "}</button>
                        </div>
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
                        .get_with_options(&challenge)
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
        ConsoleService::log(format!("create").as_str());

        // First we need to work out what state we are in.
        let lstorage = StorageService::new(yew::services::storage::Area::Local).unwrap();

        // Get any previous sessions?
        let prev_session: Result<String, _> = lstorage.restore("kanidm_bearer_token");

        ConsoleService::log(format!("prev_session -> {:?}", prev_session).as_str());

        // Are they still valid?

        LoginApp {
            link,
            inputvalue: "".to_string(),
            lstorage,
            ft: None,
            session_id: "".to_string(),
            state: LoginState::Init(true),
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
            LoginAppMsg::TotpSubmit => {
                ConsoleService::log("totp");
                // Disable the button?
                match u32::from_str_radix(&self.inputvalue, 10) {
                    Ok(totp) => {
                        self.state = LoginState::Totp(TotpState::Disabled);
                        let authreq = AuthRequest {
                            step: AuthStep::Cred(AuthCredential::TOTP(totp)),
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
                    step: AuthStep::Cred(AuthCredential::Webauthn(resp.into())),
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
                            ConsoleService::log(format!("unimplemented").as_str());
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
                        ConsoleService::log(format!("invalid state transition").as_str());
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
                        ConsoleService::log(format!("invalid state transition").as_str());
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
                                AuthAllowed::TOTP => {
                                    self.state = LoginState::Totp(TotpState::Enabled);
                                }
                                AuthAllowed::Webauthn(challenge) => {
                                    self.state = LoginState::Webauthn(challenge.into())
                                }
                            }
                        } else {
                            // Else, present the options in a choice.
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
                        self.lstorage.store("kanidm_bearer_token", Ok(bearer_token));
                        self.state = LoginState::Authenticated;
                        startConfetti();
                        true
                    }
                }
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

        html! {
            <div>
                <canvas id="confetti-canvas" style="position:absolute" width=width height=height></canvas>
                <div id="content" class="container">
                    <div class="row d-flex justify-content-center align-items-center" style="min-height: 100vh;">
                        <div class="col">
                        </div>
                        <div class="col-sm-6">
                            <div class="container">
                                <h2>{ "Kanidm Alpha 🦀 " }</h2>
                            </div>
                            { self.view_state() }
                        </div>
                        <div class="col">
                        </div>
                    </div>
                </div>
            </div>
        }
    }
}
