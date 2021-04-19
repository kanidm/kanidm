use anyhow::Error;
// use wasm_bindgen::prelude::*;
use yew::format::Json; // , Nothing};
use yew::prelude::*;
use yew::services::fetch::{FetchService, FetchTask, Request, Response};
use yew::services::{ConsoleService, StorageService};

use kanidm_proto::v1::{AuthRequest, AuthState, AuthStep};

pub struct LoginApp {
    link: ComponentLink<Self>,
    username: String,
    lstorage: StorageService,
    ft: Option<FetchTask>,
}

pub enum LoginAppMsg {
    UserNameInput(String),
    Begin,
    Next(AuthState),
    DoNothing,
}

impl LoginApp {
    fn auth_begin(&mut self) {
        //let username_copy = self.username.clone();
        let callback =
            self.link
                .callback(move |response: Response<Json<Result<AuthState, Error>>>| {
                    let (_parts, body) = response.into_parts();
                    match body {
                        Json(Ok(state)) => LoginAppMsg::Next(state),
                        Json(Err(_)) => LoginAppMsg::DoNothing,
                    }
                });
        let authreq = AuthRequest {
            step: AuthStep::Init(self.username.clone()),
        };
        // Setup the auth step::init(username);
        self.ft = Request::post("/v1/auth")
            .header("Content-Type", "application/json")
            .body(Json(&authreq))
            .map_err(|_| ())
            .and_then(|request| FetchService::fetch_binary(request, callback).map_err(|_| ()))
            .map(|ft| Some(ft))
            .unwrap_or_else(|_e| None);
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
            username: "".to_string(),
            lstorage,
            ft: None,
        }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        false
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        match msg {
            LoginAppMsg::UserNameInput(mut username) => {
                std::mem::swap(&mut self.username, &mut username);
                true
            }
            LoginAppMsg::Begin => {
                ConsoleService::log(format!("begin -> {:?}", self.username).as_str());
                // Disable the button?
                self.auth_begin();
                true
            }
            LoginAppMsg::Next(state) => {
                ConsoleService::log(format!("next -> {:?}", state).as_str());
                true
            }
            LoginAppMsg::DoNothing => false,
        }
    }

    fn view(&self) -> Html {
        // How do we add a top level theme?
        html! {
            <div id="content" class="container">
                <div class="row d-flex justify-content-center align-items-center" style="min-height: 100vh;">
                    <div class="col">
                    </div>
                    <div class="col-sm-6">
                        <div class="container">
                            <h2>{ "Kanidm Alpha 🦀 " }</h2>
                            <p>
                            {" Username: "}
                            </p>
                        </div>
                        <div class="container">
                            <div>
                                <input id="username" type="text" class="form-control" value=self.username oninput=self.link.callback(|e: InputData| LoginAppMsg::UserNameInput(e.value)) />
                                <button type="button" class="btn btn-dark" onclick=self.link.callback(|_| LoginAppMsg::Begin)>{" Begin "}</button>
                            </div>
                        </div>
                    </div>
                    <div class="col">
                    </div>
                </div>
            </div>
        }
    }
}
