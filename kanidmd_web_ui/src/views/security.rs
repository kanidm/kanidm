use crate::error::*;
use crate::models;
use crate::utils;

use crate::manager::Route;
use crate::views::{ViewProps, ViewRoute};

use compact_jwt::{Jws, JwsUnverified};
#[cfg(debug)]
use gloo::console;
use kanidm_proto::v1::SingleStringRequest;
use std::str::FromStr;
use wasm_bindgen::JsValue;
use yew::prelude::*;
use yew_router::prelude::*;

use kanidm_proto::v1::{CUSessionToken, CUStatus, UserAuthToken};

use wasm_bindgen::{JsCast, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

#[allow(clippy::large_enum_variant)]
// Page state
pub enum Msg {
    // Nothing
    RequestCredentialUpdate,
    ChangeUnixPassword,
    UnixPasswordInput(String),
    BeginCredentialUpdate {
        token: CUSessionToken,
        status: CUStatus,
    },
    Success(String),
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
    Success { msg: String },
}

pub struct SecurityApp {
    state: State,
    unix_input_value: String,
}

impl Component for SecurityApp {
    type Message = Msg;
    type Properties = ViewProps;

    fn create(_ctx: &Context<Self>) -> Self {
        #[cfg(debug)]
        console::debug!("views::security::create");
        SecurityApp {
            state: State::Init,
            unix_input_value: "".to_string(),
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        #[cfg(debug)]
        console::debug!("views::security::changed");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug)]
        console::debug!("views::security::update");
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
                self.unix_input_value = "".to_string();
                true
            }
            Msg::Success(msg) => {
                self.state = State::Success { msg };
                self.unix_input_value = "".to_string();
                true
            }
            Msg::ChangeUnixPassword => {
                let token = ctx.props().token.clone();

                let jwtu =
                    JwsUnverified::from_str(&token).expect_throw("Invalid UAT, unable to parse");

                let uat: Jws<UserAuthToken> = jwtu
                    .unsafe_release_without_verification()
                    .expect_throw("Unvalid UAT, unable to release ");

                let id = uat.inner.uuid.to_string();
                let newpw = self.unix_input_value.clone();
                ctx.link().send_future(async {
                    match Self::update_unix_password(id, token, newpw).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                true
            }
            Msg::UnixPasswordInput(mut inputvalue) => {
                std::mem::swap(&mut self.unix_input_value, &mut inputvalue);
                true
            }
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug)]
        console::debug!("views::security::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let submit_enabled = match self.state {
            State::Init | State::Error { .. } | State::Success { .. } => true,
            State::Waiting => false,
        };

        let flash = match &self.state {
            State::Error { emsg, kopid } => {
                let message = match kopid {
                    Some(k) => format!("An error occured - {} - {}", emsg, k),
                    None => format!("An error occured - {} - No Operation ID", emsg),
                };
                html! {
                  <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    { message }
                    <button type="button" class="btn btn-close" data-dismiss="alert" aria-label="Close"></button>
                  </div>
                }
            }
            State::Success { msg } => {
                html! {
                  <div class="alert alert-success alert-dismissible fade show" role="alert">
                    { msg }
                    <button type="button" class="btn btn-close" data-dismiss="alert" aria-label="Close"></button>
                  </div>
                }
            }
            _ => html! { <></> },
        };

        let unix_input_value = self.unix_input_value.clone();

        html! {
            <>
              <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                <h2>{ "Security" }</h2>
              </div>
              { flash }
              <div>
                <p>
                   <button type="button" class="btn btn-primary"
                     disabled={ !submit_enabled }
                     onclick={
                        // TODO: figure out if we need the e here? :)
                        ctx.link().callback(|_e| {
                            Msg::RequestCredentialUpdate
                        })
                     }
                   >
                     { "Password and Authentication Settings" }
                   </button>
                </p>
              </div>
              <hr/>
              <div>
                <p>
                   <button type="button" class="btn btn-primary"
                    data-bs-toggle="modal"
                    data-bs-target={format!("#{}", crate::constants::ID_UNIX_PASSWORDCHANGE)}
                   >
                     { "Update your Unix Password" }
                   </button>
                </p>
              </div>
              <div class="modal" tabindex="-1" role="dialog" id={crate::constants::ID_UNIX_PASSWORDCHANGE}>
                <div class="modal-dialog" role="document">
                    <form
                        onsubmit={ ctx.link().callback(|e: FocusEvent| {
                            e.prevent_default();
                            Msg::ChangeUnixPassword
                        } ) }
                    >
                      <div class="modal-content">
                      <div class="modal-header">
                          <h5 class="modal-title">{"Update your password"}</h5>
                      </div>

                      <div class="modal-body text-center">
                          <input
                              autofocus=true
                              class="autofocus form-control"
                              id="password"
                              name="password"
                              oninput={ ctx.link().callback(|e: InputEvent| Msg::UnixPasswordInput(utils::get_value_from_input_event(e))) }
                              type="password"
                              value={ unix_input_value }
                          />
                      </div>
                      <div class="modal-footer">
                          <button type="submit" class="btn btn-success">{ "Update Password" }</button>
                          <button type="button" class="btn btn-secondary"
                          data-bs-dismiss="modal"
                          >{"Cancel"}</button>
                      </div>
                      </div>
                    </form>
                </div>
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

        let uri = format!("/v1/person/{}/_credential/_update", id);

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
    async fn update_unix_password(
        id: String,
        token: String,
        new_password: String,
    ) -> Result<Msg, FetchError> {
        let changereq_jsvalue = serde_json::to_string(&SingleStringRequest {
            value: new_password,
        })
        .map(|s| JsValue::from(&s))
        .expect_throw("Failed to change request");
        let mut opts = RequestInit::new();
        opts.method("PUT");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&changereq_jsvalue));

        let uri = format!("/v1/person/{}/_unix/_credential", id);

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

        utils::modal_hide_by_id(crate::constants::ID_UNIX_PASSWORDCHANGE);
        if status == 200 {
            Ok(Msg::Success("Password changed successfully".to_string()))
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
