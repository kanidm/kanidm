#[cfg(debug_assertions)]
use gloo::console;
use kanidm_proto::v1::{CUSessionToken, CUStatus, UiHint};
use wasm_bindgen::{JsCast, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestCredentials, RequestInit, RequestMode, Response};
use yew::prelude::*;
use yew_router::prelude::*;

use crate::components::change_unix_password::ChangeUnixPassword;
use crate::constants::CSS_PAGE_HEADER;
use crate::error::*;
use crate::manager::Route;
use crate::views::{ViewProps, ViewRoute};
use crate::{models, utils};

#[allow(clippy::large_enum_variant)]
// Page state
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
    RequestReauth,
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
        #[cfg(debug_assertions)]
        console::debug!("views::security::create");
        SecurityApp { state: State::Init }
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("views::security::changed");
        true
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("views::security::update");
        match msg {
            Msg::RequestCredentialUpdate => {
                // Submit a req to init the session.
                // The uuid we want to submit against - hint, it's us.

                let uat = &ctx.props().current_user_uat;
                let id = uat.uuid.to_string();

                ctx.link().send_future(async {
                    match Self::request_credential_update(id).await {
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
                    .navigator()
                    .expect_throw("failed to read history")
                    .push(&Route::CredentialReset);
                // No need to redraw, or reset state, since this redirect will destroy
                // the state.
                false
            }
            Msg::RequestReauth => {
                models::push_return_location(models::Location::Views(ViewRoute::Security));

                ctx.link()
                    .navigator()
                    .expect_throw("failed to read history")
                    .push(&Route::Reauth);

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
        #[cfg(debug_assertions)]
        console::debug!("views::security::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let uat = ctx.props().current_user_uat.clone();

        let jsdate = js_sys::Date::new_0();
        let isotime: String = jsdate.to_iso_string().into();
        // TODO: Actually check the time of expiry on the uat and have a timer set that
        // re-locks things nicely.
        let time = time::OffsetDateTime::parse(&isotime, time::Format::Rfc3339)
            .map(|odt| odt + time::Duration::new(60, 0))
            .expect_throw("Unable to process time stamp");

        let is_priv_able = uat.purpose_readwrite_active(time);

        let submit_enabled = match self.state {
            State::Init | State::Error { .. } => is_priv_able,
            State::Waiting => false,
        };

        let flash = match &self.state {
            State::Error { emsg, kopid } => {
                let message = match kopid {
                    Some(k) => format!("An error occurred - {} - {}", emsg, k),
                    None => format!("An error occurred - {} - No Operation ID", emsg),
                };
                html! {
                  <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    { message }
                    <button type="button" class="btn btn-close" data-dismiss="alert" aria-label="Close"></button>
                  </div>
                }
            }
            _ => html! { <></> },
        };

        let unlock = if is_priv_able {
            html! {
              <div>
               <button type="button" class="btn btn-primary"
                 disabled=true
               >
                 { "Security Settings Unlocked 🔓" }
               </button>
              </div>
            }
        } else {
            html! {
              <div>
               <button type="button" class="btn btn-primary"
                 onclick={
                    ctx.link().callback(|_e| {
                        Msg::RequestReauth
                    })
                 }
               >
                 { "Unlock Security Settings 🔒" }
               </button>
              </div>
            }
        };

        html! {
            <>
              <div class={CSS_PAGE_HEADER}>
                <h2>{ "Security" }</h2>
              </div>
              { flash }
              { unlock }
              <hr/>
              <div>
                <p>
                   <button type="button" class="btn btn-primary"
                     disabled={ !submit_enabled }
                     onclick={
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
                if uat.ui_hints.contains(&UiHint::PosixAccount) {
                  <div>
                      <p>
                        <ChangeUnixPassword uat={ uat }/>
                      </p>
                  </div>
                }
            </>
        }
    }
}

impl SecurityApp {
    async fn request_credential_update(id: String) -> Result<Msg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::SameOrigin);
        opts.credentials(RequestCredentials::SameOrigin);

        let uri = format!("/v1/person/{}/_credential/_update", id);

        let request = Request::new_with_str_and_init(uri.as_str(), &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
        let status = resp.status();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let (token, status): (CUSessionToken, CUStatus) =
                serde_wasm_bindgen::from_value(jsval).expect_throw("Invalid response type");
            Ok(Msg::BeginCredentialUpdate { token, status })
        } else {
            let headers = resp.headers();
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_default();
            // let jsval_json = JsFuture::from(resp.json()?).await?;
            Ok(Msg::Error { emsg, kopid })
        }
    }
}
