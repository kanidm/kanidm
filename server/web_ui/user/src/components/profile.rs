#[cfg(debug_assertions)]
use gloo::console;
use kanidm_proto::v1::{CUSessionToken, CUStatus, UiHint, UserAuthToken};
use kanidmd_web_ui_shared::models::{
    push_cred_update_session, push_login_hint, push_return_location,
};
use kanidmd_web_ui_shared::utils::do_alert_error;
use kanidmd_web_ui_shared::{do_request, error::FetchError, RequestMethod};
use time::format_description::well_known::Rfc3339;
use wasm_bindgen::UnwrapThrowExt;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::components::change_unix_password::ChangeUnixPassword;
use crate::components::create_reset_code::CreateResetCode;
use crate::manager::Route;
use crate::views::ViewProps;
use kanidmd_web_ui_shared::constants::{CSS_PAGE_HEADER, URL_REAUTH, URL_USER_PROFILE};

#[allow(clippy::large_enum_variant)]
// Page state
pub enum ProfileMessage {
    RequestCredentialUpdate,
    BeginCredentialUpdate {
        token: CUSessionToken,
        status: CUStatus,
    },
    Error {
        emsg: String,
        kopid: Option<String>,
    },
    // User has requested to unlock the profile settings, this redirects to the reauth endpoint
    RequestReauth,
}

impl From<FetchError> for ProfileMessage {
    fn from(fe: FetchError) -> Self {
        ProfileMessage::Error {
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
    type Message = ProfileMessage;
    type Properties = ViewProps;

    fn create(_ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("user::profile::create");
        ProfileApp { state: State::Init }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("user::profile::update");
        match msg {
            ProfileMessage::RequestCredentialUpdate => {
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
            ProfileMessage::BeginCredentialUpdate { token, status } => {
                // Got the rec, setup.
                push_cred_update_session((token, status));
                push_return_location(URL_USER_PROFILE);

                ctx.link()
                    .navigator()
                    .expect_throw("failed to read history")
                    .push(&Route::CredentialReset);
                // No need to redraw, or reset state, since this redirect will destroy
                // the state.
                false
            }
            ProfileMessage::RequestReauth => {
                // store where we're coming back to
                push_return_location(&[URL_USER_PROFILE, "?reauth=1"].concat());

                let uat = &ctx.props().current_user_uat;
                // Setup the ui hint to tell the reauth page what to do.
                push_login_hint(uat.name().to_string());

                let window = gloo_utils::window();
                window
                    .location()
                    .set_href(URL_REAUTH)
                    .expect_throw("Failed to redirect to reauth page!");

                // No need to redraw, or reset state, since this redirect will destroy
                // the state.
                false
            }
            ProfileMessage::Error { emsg, kopid } => {
                self.state = State::Error { emsg, kopid };
                true
            }
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("user::profile::changed");
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        #[cfg(debug_assertions)]
        console::debug!("user::profile::view");
        let uat = &ctx.props().current_user_uat;

        let jsdate = js_sys::Date::new_0();
        let isotime: String = jsdate.to_iso_string().into();
        // TODO: Actually check the time of expiry on the uat and have a timer set that
        // re-locks things nicely.
        let time = time::OffsetDateTime::parse(&isotime, &Rfc3339)
            .map(|odt| odt + time::Duration::new(60, 0))
            .expect_throw("Unable to process time stamp");

        let is_priv_able = uat.purpose_readwrite_active(time);

        let submit_enabled: bool = match self.state {
            State::Init | State::Error { .. } => is_priv_able,
            State::Waiting => false,
        };

        let flash = match &self.state {
            State::Error { emsg, kopid } => {
                let opid_str = match kopid {
                    Some(k) => [" (Operation ID: ", k, ")"].concat(),
                    None => " (Unknown Operation ID)".to_string(),
                };
                do_alert_error(
                    "An error occurred starting the credential update session",
                    Some(&[emsg.to_owned(), opid_str].concat()),
                    true,
                )
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
                        ProfileMessage::RequestReauth
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

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("views::security::rendered");
    }
}

impl ProfileApp {
    fn view_profile(&self, ctx: &Context<Self>, submit_enabled: bool, uat: UserAuthToken) -> Html {
        // Get ui hints.

        // Until we do finegrained updates in the cred update, we disable credupdates for some
        // account classes.

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

              if uat.ui_hints.contains(&UiHint::CredentialUpdate) {
                <div>
                  <p>
                     <button type="button" class="btn btn-primary"
                       disabled={ !submit_enabled }
                       onclick={
                          ctx.link().callback(|_e| {
                              ProfileMessage::RequestCredentialUpdate
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
              }

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

    async fn request_credential_update(id: String) -> Result<ProfileMessage, FetchError> {
        let uri = format!("/v1/person/{}/_credential/_update", id);
        let (kopid, status, value, _headers) = do_request(&uri, RequestMethod::GET, None).await?;

        if status == 200 {
            let (token, status): (CUSessionToken, CUStatus) =
                serde_wasm_bindgen::from_value(value).expect_throw("Invalid response type");
            Ok(ProfileMessage::BeginCredentialUpdate { token, status })
        } else {
            let emsg = value.as_string().unwrap_or_default();
            // let jsval_json = JsFuture::from(resp.json()?).await?;
            Ok(ProfileMessage::Error { emsg, kopid })
        }
    }
}
