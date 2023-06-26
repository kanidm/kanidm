#[cfg(debug_assertions)]
use gloo::console;
use kanidm_proto::v1::{CUSessionToken, CUStatus, UiHint, UserAuthToken};
use time::format_description::well_known::Rfc3339;
use wasm_bindgen::UnwrapThrowExt;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::components::change_unix_password::ChangeUnixPassword;
use crate::components::create_reset_code::CreateResetCode;
use crate::constants::CSS_PAGE_HEADER;
use crate::error::*;
use crate::manager::Route;
use crate::models;
use crate::views::{ViewProps, ViewRoute};

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

pub struct ProfileApp {
    state: State,
}

impl Component for ProfileApp {
    type Message = Msg;
    type Properties = ViewProps;

    fn create(_ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("views::security::create");
        ProfileApp { state: State::Init }
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
                models::push_return_location(models::Location::Views(ViewRoute::Profile));

                ctx.link()
                    .navigator()
                    .expect_throw("failed to read history")
                    .push(&Route::CredentialReset);
                // No need to redraw, or reset state, since this redirect will destroy
                // the state.
                false
            }
            Msg::RequestReauth => {
                models::push_return_location(models::Location::Views(ViewRoute::Profile));

                let uat = &ctx.props().current_user_uat;
                let spn = uat.spn.to_string();

                // Setup the ui hint.
                models::push_login_hint(spn);

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
        let uat = &ctx.props().current_user_uat;

        let jsdate = js_sys::Date::new_0();
        let isotime: String = jsdate.to_iso_string().into();
        // TODO: Actually check the time of expiry on the uat and have a timer set that
        // re-locks things nicely.
        let time = time::OffsetDateTime::parse(&isotime, &Rfc3339)
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

        let main = if is_priv_able {
            self.view_profile(ctx, submit_enabled, uat.clone())
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
                 { "Unlock Profile Settings 🔒" }
               </button>
              </div>
            }
        };

        html! {
            <>
              <div class={CSS_PAGE_HEADER}>
                <h2>{ "Profile" }</h2>
              </div>
              { flash }
              { main }
            </>
        }
    }
}

impl ProfileApp {
    fn view_profile(&self, ctx: &Context<Self>, submit_enabled: bool, uat: UserAuthToken) -> Html {
        html! {
          <>
            <div>
             <button type="button" class="btn btn-primary"
               disabled=true
             >
               { "Profile Settings Unlocked 🔓" }
             </button>
            </div>
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
            <div>
              <p>
                <CreateResetCode uat={ uat.clone() } enabled={ submit_enabled } />
              </p>
            </div>
            <hr/>
              if uat.ui_hints.contains(&UiHint::PosixAccount) {
                <div>
                    <p>
                      <ChangeUnixPassword uat={ uat } enabled={ submit_enabled } />
                    </p>
                </div>
              }
          </>
        }
    }

    async fn request_credential_update(id: String) -> Result<Msg, FetchError> {
        let uri = format!("/v1/person/{}/_credential/_update", id);
        let (kopid, status, value, _headers) =
            crate::do_request(&uri, crate::RequestMethod::GET, None).await?;

        if status == 200 {
            let (token, status): (CUSessionToken, CUStatus) =
                serde_wasm_bindgen::from_value(value).expect_throw("Invalid response type");
            Ok(Msg::BeginCredentialUpdate { token, status })
        } else {
            let emsg = value.as_string().unwrap_or_default();
            // let jsval_json = JsFuture::from(resp.json()?).await?;
            Ok(Msg::Error { emsg, kopid })
        }
    }
}
