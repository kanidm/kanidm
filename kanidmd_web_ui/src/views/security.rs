use crate::error::*;
use crate::models;
use crate::utils;

use crate::manager::Route;
use crate::views::{ViewProps, ViewRoute};

use compact_jwt::{Jws, JwsUnverified};
use gloo::console;
use std::str::FromStr;
use yew::prelude::*;
use yew_router::prelude::*;

use kanidm_proto::v1::{CUSessionToken, CUStatus, UserAuthToken};

use wasm_bindgen::{JsCast, JsValue, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

pub enum Msg {
    // Nothing
    RequestCredentialUpdate,
    BeginCredentialUpdate {
        token: CUSessionToken,
        status: CUStatus,
    },
    Error {
        emsg: String,
        kopid: Option<String>,
    },
}

impl From<FetchError> for Msg {
    fn from(fe: FetchError) -> Self {
        Msg::Error {
            emsg: fe.as_string(),
            kopid: None,
        }
    }
}

enum State {
    Init,
    Waiting,
    Error { emsg: String, kopid: Option<String> },
}

pub struct SecurityApp {
    state: State,
}

impl Component for SecurityApp {
    type Message = Msg;
    type Properties = ViewProps;

    fn create(_ctx: &Context<Self>) -> Self {
        console::log!("views::security::create");
        SecurityApp { state: State::Init }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::log!("views::security::changed");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::log!("views::security::update");
        match msg {
            Msg::RequestCredentialUpdate => {
                // Submit a req to init the session.
                // The uuid we want to submit against - hint, it's us.
                let token = ctx.props().token.clone();

                let jwtu =
                    JwsUnverified::from_str(&token).expect_throw("Invalid UAT, unable to parse");

                let uat: Jws<UserAuthToken> = jwtu
                    .unsafe_release_without_verification()
                    .expect_throw("Unvalid UAT, unable to release ");

                let id = uat.inner.uuid.to_string();

                ctx.link().send_future(async {
                    match Self::fetch_token_valid(id, token).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                self.state = State::Waiting;
                true
            }
            Msg::BeginCredentialUpdate { token, status } => {
                // Got the rec, setup.
                models::push_cred_update_session((token, status));
                models::push_return_location(models::Location::Views(ViewRoute::Security));

                ctx.link()
                    .history()
                    .expect_throw("failed to read history")
                    .push(Route::CredentialReset);
                // No need to redraw, or reset state, since this redirect will destroy
                // the state.
                false
            }
            Msg::Error { emsg, kopid } => {
                self.state = State::Error { emsg, kopid };
                true
            }
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        console::log!("views::security::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let submit_enabled = match self.state {
            State::Init | State::Error { .. } => true,
            State::Waiting => false,
        };

        let error = match &self.state {
            State::Error { emsg, kopid } => {
                let message = match kopid {
                    Some(k) => format!("An error occured - {} - {}", emsg, k),
                    None => format!("An error occured - {} - No Operation ID", emsg),
                };
                html! {
                  <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    { message }
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                  </div>
                }
            }
            _ => html! { <></> },
        };

        html! {
            <>
              <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                <h2>{ "Security" }</h2>
              </div>
              { error }
              <div>
                <p>
                   <button type="button" class="btn btn-primary"
                     disabled={ !submit_enabled }
                     onclick={
                        ctx.link().callback(|e| {
                            Msg::RequestCredentialUpdate
                        })
                     }
                   >
                     { "Password and Authentication Settings" }
                   </button>
                </p>
              </div>
            </>
        }
    }
}

impl SecurityApp {
    async fn fetch_token_valid(id: String, token: String) -> Result<Msg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::SameOrigin);

        let uri = format!("/v1/account/{}/_credential/_update", id);

        let request = Request::new_with_str_and_init(uri.as_str(), &opts)?;

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
            let jsval = JsFuture::from(resp.json()?).await?;
            let (token, status): (CUSessionToken, CUStatus) =
                jsval.into_serde().expect_throw("Invalid response type");
            Ok(Msg::BeginCredentialUpdate { token, status })
        } else {
            let headers = resp.headers();
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            // let jsval_json = JsFuture::from(resp.json()?).await?;
            Ok(Msg::Error { emsg, kopid })
        }
    }
}
