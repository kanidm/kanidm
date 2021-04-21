use anyhow::Error;
use wasm_bindgen::prelude::*;
use yew::format::{Json, Nothing};
use yew::prelude::*;
use yew::services::fetch::{FetchService, FetchTask, Request, Response};
use yew::services::{ConsoleService, StorageService};

use kanidm_proto::v1::{
    AuthAllowed, AuthCredential, AuthMech, AuthRequest, AuthResponse, AuthState, AuthStep,
};

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

enum LoginState {
    Init(bool),

    // MechChoice
    // CredChoice
    Password(bool),
    // Totp(bool),
    // Webauthn,
    Error,
    Authenticated,
}

pub enum LoginAppMsg {
    Input(String),
    Begin,
    PasswordSubmit,
    Start(String, AuthResponse),
    Next(AuthResponse),
    // DoNothing,
    Error(String),
}

impl LoginApp {
    fn auth_init(&mut self) {
        let callback = self.link.callback(
            move |response: Response<Json<Result<AuthResponse, Error>>>| {
                let (parts, body) = response.into_parts();
                parts
                    .headers
                    .get("x-kanidm-auth-session-id")
                    .map(|session_id| {
                        let session_id = session_id.to_str().unwrap().to_string();
                        match body {
                            Json(Ok(state)) => LoginAppMsg::Start(session_id, state),
                            Json(Err(e)) => LoginAppMsg::Error(format!("{:?}", e)),
                        }
                    })
                    .unwrap_or_else(|| {
                        LoginAppMsg::Error("x-kanidm-auth-session-id not present".to_string())
                    })
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
                let (_parts, body) = response.into_parts();
                match body {
                    Json(Ok(state)) => LoginAppMsg::Next(state),
                    Json(Err(e)) => LoginAppMsg::Error(format!("{:?}", e)),
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
            LoginState::Authenticated => {
                html! {
                    <div class="container">
                        <p>
                            { "Login Success 🎉" }
                        </p>
                    </div>
                }
            }
            LoginState::Error => {
                html! {
                    <div class="container">
                        <p>
                            { "An error has occured :( " }
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
            LoginAppMsg::Begin => {
                ConsoleService::log(format!("begin -> {:?}", self.inputvalue).as_str());
                // Disable the button?
                self.state = LoginState::Init(false);
                self.auth_init();
                true
            }
            LoginAppMsg::PasswordSubmit => {
                ConsoleService::log(format!("password -> {:?}", self.inputvalue).as_str());
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
                            self.state = LoginState::Error;
                            true
                        }
                    }
                    _ => {
                        ConsoleService::log(format!("invalid state transition").as_str());
                        self.state = LoginState::Error;
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
                        self.state = LoginState::Error;
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
                                AuthAllowed::TOTP => {}
                                AuthAllowed::Webauthn(challenge) => {}
                            }
                        } else {
                            // Else, present the options in a choice.
                        }
                        true
                    }
                    AuthState::Denied(reason) => {
                        self.state = LoginState::Error;
                        true
                    }
                    AuthState::Success(bearer_token) => {
                        // Store the bearer here!
                        self.state = LoginState::Authenticated;
                        startConfetti();
                        true
                    }
                }
            }
            LoginAppMsg::Error(msg) => {
                // Clear any leftover input
                self.inputvalue = "".to_string();
                ConsoleService::log(format!("error -> {:?}", msg).as_str());
                false
            }
        }
    }

    fn view(&self) -> Html {
        // How do we add a top level theme?
        html! {
            <div id="content" class="container">
                <canvas id="confetti-canvas" style="position:absolute" width="1920" height="1200"></canvas>
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
        }
    }
}
