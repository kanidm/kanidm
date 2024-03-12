#![allow(clippy::disallowed_types)] // because `Routable` uses a hashmap
#![allow(non_camel_case_types)]
use gloo::console;
use kanidm_proto::constants::uri::V1_AUTH_VALID;
use kanidm_proto::internal::{UiHint, UserAuthToken};
use kanidmd_web_ui_shared::constants::{
    CSS_ALERT_DANGER, CSS_NAVBAR_BRAND, CSS_NAVBAR_LINKS_UL, CSS_NAVBAR_NAV, CSS_NAV_LINK,
    ID_NAVBAR_COLLAPSE, IMG_LOGO_SQUARE, URL_ADMIN, URL_LOGIN,
};
use kanidmd_web_ui_shared::models::push_return_location;
use kanidmd_web_ui_shared::ui::{signout_link, signout_modal, ui_logout};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsValue, UnwrapThrowExt};
use yew::prelude::*;
use yew_router::prelude::*;

use crate::components::profile::ProfileApp;
use crate::manager::Route;
use kanidmd_web_ui_shared::{do_request, error::FetchError, RequestMethod};

mod apps;
pub mod identityverification;

use apps::AppsApp;
use identityverification::IdentityVerificationApp;

#[derive(Routable, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum ViewRoute {
    #[at("/ui/apps")]
    Apps,
    #[at("/ui/profile")]
    Profile,
    #[at("/ui/identity-verification")]
    IdentityVerification,
    #[not_found]
    #[at("/ui/404")]
    NotFound,
}

enum State {
    LoginRequired,
    LoggingOut,
    Verifying,
    Authenticated(UserAuthToken),
    Error { emsg: String, kopid: Option<String> },
}

#[derive(PartialEq, Eq, Properties)]
pub struct ViewProps {
    pub current_user_uat: UserAuthToken,
}

pub struct ViewsApp {
    state: State,
}

#[derive(Clone)]
pub enum ViewsMsg {
    Verified,
    ProfileInfoReceived { uat: UserAuthToken },
    Logout,
    LogoutComplete,
    Error { emsg: String, kopid: Option<String> },
}

impl From<FetchError> for ViewsMsg {
    fn from(fe: FetchError) -> Self {
        ViewsMsg::Error {
            emsg: fe.as_string(),
            kopid: None,
        }
    }
}

impl Component for ViewsApp {
    type Message = ViewsMsg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("views::create");

        // Ensure the token is valid before we proceed. Could be
        // due to a session expiry or something else, but we want to make
        // sure we are really authenticated before we proceed.

        // Send off the validation event.
        ctx.link().send_future(async {
            match Self::check_session_valid().await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });

        let state = State::Verifying;

        ViewsApp { state }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("views::update");
        match msg {
            ViewsMsg::Verified => {
                // Populate the user profile now we know their session is valid.
                ctx.link().send_future(async {
                    match Self::fetch_user_data().await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                true
            }
            ViewsMsg::ProfileInfoReceived { uat } => {
                self.state = State::Authenticated(uat);
                true
            }
            ViewsMsg::Logout => {
                ctx.link().send_future(async {
                    match Self::fetch_logout().await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                self.state = State::LoggingOut;
                true
            }
            ViewsMsg::LogoutComplete => {
                self.state = State::LoginRequired;
                true
            }
            ViewsMsg::Error { emsg, kopid } => {
                self.state = State::Error { emsg, kopid };
                true
            }
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("views::changed");
        false
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.state {
            State::LoginRequired => {
                // Where are we?
                let maybe_loc: Option<ViewRoute> = ctx.link().route();

                if let Some(loc) = maybe_loc {
                    push_return_location(&loc.to_path());
                }

                gloo_utils::window()
                    .location()
                    .set_href(URL_LOGIN)
                    .expect_throw("failed to send the user to the login page?");

                html! { <div>
                  { "Redirecting to login page..." }<br />
                  <a href={URL_LOGIN}>{"Click here if you aren't redirected"}</a>
                </div> }
            }
            State::LoggingOut | State::Verifying => {
                html! {
                  <main class="text-center form-signin h-100">
                    <div class="vert-center">
                      <div class="spinner-border text-dark" role="status">
                        <span class="visually-hidden">{ "Loading..." }</span>
                      </div>
                    </div>
                  </main>
                }
            }
            State::Authenticated(uat) => self.view_authenticated(ctx, uat),
            State::Error { emsg, kopid } => {
                //
                html! {
                  <main class="form-signin">
                    <div class={CSS_ALERT_DANGER} role="alert">
                      <h2>{ "An Error Occurred 🥺" }</h2>
                    <p>{ emsg.to_string() }</p>
                    <p>
                        {
                            if let Some(opid) = kopid.as_ref() {
                                format!("Operation ID: {}", opid)
                            } else {
                                "Error occurred client-side.".to_string()
                            }
                        }
                    </p>
                    </div>
                    <center><a href={URL_LOGIN} class="btn btn-primary">{ "Return to Login" }</a></center>
                  </main>
                }
            }
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("views::rendered");
    }
}

/// TODO: one day work out how to make this some kind of neat generic thing but... routers.
fn make_navbar(links: Vec<Html>) -> Html {
    html! {
      <nav class={CSS_NAVBAR_NAV}>
          <div class="container-fluid">
          <Link<ViewRoute> classes={CSS_NAVBAR_BRAND} to={ViewRoute::Apps}>
            {"Kanidm"}
            </Link<ViewRoute>>
            // this shows a button on mobile devices to open the menu
            <button class="navbar-toggler bg-white" type="button" data-bs-toggle="collapse" data-bs-target={["#", ID_NAVBAR_COLLAPSE].concat()} aria-controls={ID_NAVBAR_COLLAPSE} aria-expanded="false" aria-label="Toggle navigation">
              <img src={IMG_LOGO_SQUARE} alt="Toggle navigation" class="navbar-toggler-img" />
            </button>

            <div class="collapse navbar-collapse" id={ID_NAVBAR_COLLAPSE}>
              <ul class={CSS_NAVBAR_LINKS_UL}>
                { links.into_iter().map(|link| {
                  html!{ <li class="mb-1">
                    { link }
                  </li>
                } }).collect::<Html>()
              }
              </ul>

            </div>
          </div>
        </nav>
    }
}

impl ViewsApp {
    /// The base page for the user dashboard
    fn view_authenticated(&self, ctx: &Context<Self>, uat: &UserAuthToken) -> Html {
        let current_user_uat = uat.clone();
        let ui_hint_experimental = uat.ui_hints.contains(&UiHint::ExperimentalFeatures);
        let credential_update = uat.ui_hints.contains(&UiHint::CredentialUpdate);

        let mut links = vec![
            html! {<Link<ViewRoute> classes={CSS_NAV_LINK} to={ViewRoute::Apps}>
              <span data-feather="file"></span>
              { "Apps" }
            </Link<ViewRoute>>},
        ];

        if credential_update {
            links.push(html! {
              <Link<ViewRoute> classes={CSS_NAV_LINK} to={ViewRoute::Profile}>
                <span data-feather="file"></span>
                { "Profile" }
              </Link<ViewRoute>>

            });
        }

        if ui_hint_experimental {
            links.extend(vec![
                html! {<Link<ViewRoute> classes={CSS_NAV_LINK} to={ViewRoute::IdentityVerification}>
                <span data-feather="file"></span>
                { "Identity verification" }
                </Link<ViewRoute>>},
                html! {<a href={URL_ADMIN} class={CSS_NAV_LINK}>
                <span data-feather="file"></span>
                { "Admin" }
                </a>},
            ])
        };

        links.push(signout_link());
        html! {
          <>
          {make_navbar(links)}

        // sign out modal dialogue box
        {signout_modal(ctx, ViewsMsg::Logout)}

        <main class="p-3 x-auto">
              <Switch<ViewRoute> render={ move |route: ViewRoute| {
                    // safety - can't panic because to get to this location we MUST be authenticated!
                    match route {

                        #[allow(clippy::let_unit_value)]
                        ViewRoute::IdentityVerification => html! { <IdentityVerificationApp current_user_uat={ current_user_uat.clone() } />},
                        ViewRoute::Apps => html! { <AppsApp /> },
                        ViewRoute::Profile => html! { <ProfileApp current_user_uat={ current_user_uat.clone() } /> },
                        ViewRoute::NotFound => html! {
                            <Redirect<Route> to={Route::NotFound}/>
                        },
                    }
              }
            } />
        </main>
        </>
          }
    }

    async fn check_session_valid() -> Result<ViewsMsg, FetchError> {
        let (kopid, status, value, _) =
            do_request(V1_AUTH_VALID, RequestMethod::GET, None::<JsValue>).await?;

        if status == 200 {
            Ok(ViewsMsg::Verified)
        } else if status == 401 {
            Ok(ViewsMsg::LogoutComplete)
        } else {
            let emsg = value.as_string().unwrap_or_default();
            Ok(ViewsMsg::Error { emsg, kopid })
        }
    }

    async fn fetch_user_data() -> Result<ViewsMsg, FetchError> {
        let (kopid, status, value, _) =
            do_request("/v1/self/_uat", RequestMethod::GET, None::<JsValue>).await?;

        if status == 200 {
            let uat: UserAuthToken = serde_wasm_bindgen::from_value(value)
                .map_err(|e| {
                    let e_msg = format!("serde error -> {:?}", e);
                    console::error!(e_msg.as_str());
                })
                .expect_throw("Invalid response type");

            Ok(ViewsMsg::ProfileInfoReceived { uat })
        } else {
            let emsg = value.as_string().unwrap_or_default();
            Ok(ViewsMsg::Error { emsg, kopid })
        }
    }

    async fn fetch_logout() -> Result<ViewsMsg, FetchError> {
        match ui_logout().await {
            Ok(_) => Ok(ViewsMsg::LogoutComplete),
            Err((emsg, kopid)) => Ok(ViewsMsg::Error { emsg, kopid }),
        }
    }
}
