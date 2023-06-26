use gloo::console;
use kanidm_proto::v1::{UiHint, UserAuthToken};
use serde::{Deserialize, Serialize};
use wasm_bindgen::UnwrapThrowExt;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::components::{admin_accounts, admin_groups, admin_menu, admin_oauth2};
use crate::manager::Route;
use crate::models;
use crate::{do_request, error::*, RequestMethod};

mod apps;
mod profile;

use apps::AppsApp;
use profile::ProfileApp;

#[derive(Routable, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum ViewRoute {
    #[at("/ui/admin/*")]
    Admin,

    #[at("/ui/apps")]
    Apps,

    #[at("/ui/profile")]
    Profile,

    #[not_found]
    #[at("/ui/404")]
    NotFound,
}

#[derive(Routable, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum AdminRoute {
    #[at("/ui/admin/menu")]
    AdminMenu,

    #[at("/ui/admin/groups")]
    AdminListGroups,
    #[at("/ui/admin/accounts")]
    AdminListAccounts,
    #[at("/ui/admin/oauth2")]
    AdminListOAuth2,

    #[at("/ui/admin/group/:uuid")]
    ViewGroup { uuid: String },
    #[at("/ui/admin/person/:uuid")]
    ViewPerson { uuid: String },
    #[at("/ui/admin/service_account/:uuid")]
    ViewServiceAccount { uuid: String },
    #[at("/ui/admin/oauth2/:rs_name")]
    ViewOAuth2RP { rs_name: String },

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

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("views::changed");
        false
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

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("views::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.state {
            State::LoginRequired => {
                // Where are we?
                let maybe_loc: Option<ViewRoute> = ctx.link().route();

                if let Some(loc) = maybe_loc {
                    models::push_return_location(models::Location::Views(loc));
                }

                ctx.link()
                    .navigator()
                    .expect_throw("failed to read history")
                    .push(&Route::Login);
                html! { <div></div> }
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
                html! {
                  <main class="form-signin">
                    <div class="alert alert-danger" role="alert">
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

                  </main>
                }
            }
        }
    }
}

impl ViewsApp {
    /// The base page for the user dashboard
    fn view_authenticated(&self, ctx: &Context<Self>, uat: &UserAuthToken) -> Html {
        let current_user_uat = uat.clone();

        let ui_hint_experimental = uat.ui_hints.contains(&UiHint::ExperimentalFeatures);
        let credential_update = uat.ui_hints.contains(&UiHint::CredentialUpdate);

        // WARN set dash-body against body here?
        html! {
          <>
          <nav class="navbar navbar-expand-md navbar-dark bg-dark mb-4">
              <div class="container-fluid">
              <Link<ViewRoute> classes="navbar-brand navbar-dark" to={ViewRoute::Apps}>
                {"Kanidm"}
                </Link<ViewRoute>>
                <button class="navbar-toggler bg-light" type="button" data-bs-toggle="collapse" data-bs-target="#navbarCollapse" aria-controls="navbarCollapse" aria-expanded="false" aria-label="Toggle navigation">
                  <img src="/pkg/img/favicon.png" />
                </button>

                <div class="collapse navbar-collapse" id="navbarCollapse">
                  <ul class="navbar-nav me-auto mb-2 mb-md-0">

                    <li class="mb-1">
                      <Link<ViewRoute> classes="nav-link" to={ViewRoute::Apps}>
                        <span data-feather="file"></span>
                        { "Apps" }
                      </Link<ViewRoute>>
                    </li>

                    if credential_update {
                      <li class="mb-1">
                        <Link<ViewRoute> classes="nav-link" to={ViewRoute::Profile}>
                          <span data-feather="file"></span>
                          { "Profile" }
                        </Link<ViewRoute>>
                      </li>
                    }

                    if ui_hint_experimental {
                      <li class="mb-1">
                        <Link<AdminRoute> classes="nav-link" to={AdminRoute::AdminMenu}>
                          <span data-feather="file"></span>
                          { "Admin" }
                        </Link<AdminRoute>>
                      </li>
                    }

                    <li class="mb-1">
                      <a class="nav-link" href="#"
                        data-bs-toggle="modal"
                        data-bs-target={format!("#{}", crate::constants::ID_SIGNOUTMODAL)}
                        >{"Sign out"}</a>
                    </li>
                  </ul>
                  // <form class="d-flex">
                  //   <input class="form-control me-2" type="search" placeholder="Search" aria-label="Search" />
                  //   <button class="btn btn-outline-light" type="submit">{"Search"}</button>
                  // </form>
                </div>
              </div>
            </nav>
        // sign out modal dialogue box
        <div class="modal" tabindex="-1" role="dialog" id={crate::constants::ID_SIGNOUTMODAL}>
          <div class="modal-dialog" role="document">
            <div class="modal-content">
              <div class="modal-header">
                <h5 class="modal-title">{"Confirm Sign out"}</h5>
              </div>
              <div class="modal-body text-center">
                {"Are you sure you'd like to log out?"}<br />
                <img src="/pkg/img/kani-waving.svg" alt="Kani waving goodbye" />
              </div>
              <div class="modal-footer">
                <button type="button" class="btn btn-success"
                  data-bs-toggle="modal"
                  data-bs-target={format!("#{}", crate::constants::ID_SIGNOUTMODAL)}
                  onclick={ ctx.link().callback(|_| ViewsMsg::Logout) }>{ "Sign out" }</button>
                <button type="button" class="btn btn-secondary"
                  data-bs-dismiss="modal"
                  >{"Cancel"}</button>
              </div>
            </div>
          </div>
        </div>
        <main class="p-3 x-auto">
              <Switch<ViewRoute> render={ move |route: ViewRoute| {
                    // safety - can't panic because to get to this location we MUST be authenticated!
                    match route {
                        ViewRoute::Admin => html!{
                            <Switch<AdminRoute> render={ admin_routes } />
                        },
                        #[allow(clippy::let_unit_value)]
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
            do_request("/v1/auth/valid", RequestMethod::GET, None).await?;

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
            do_request("/v1/self/_uat", RequestMethod::GET, None).await?;

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
        let (kopid, status, value, _) = do_request("/v1/logout", RequestMethod::GET, None).await?;

        if status == 200 {
            Ok(ViewsMsg::LogoutComplete)
        } else {
            let emsg = value.as_string().unwrap_or_default();
            Ok(ViewsMsg::Error { emsg, kopid })
        }
    }
}

fn admin_routes(route: AdminRoute) -> Html {
    match route {
        AdminRoute::AdminMenu => html! {
          <admin_menu::AdminMenu />
        },
        AdminRoute::AdminListAccounts => html!(
          <admin_accounts::AdminListAccounts />
        ),
        AdminRoute::AdminListGroups => html!(
          <admin_groups::AdminListGroups />
        ),
        AdminRoute::AdminListOAuth2 => html!(
          <admin_oauth2::AdminListOAuth2 />
        ),
        AdminRoute::NotFound => html! (
          <Redirect<Route> to={Route::NotFound}/>
        ),
        AdminRoute::ViewGroup { uuid } => {
            html!(<admin_groups::AdminViewGroup uuid={uuid} />)
        }
        AdminRoute::ViewPerson { uuid } => html!(
          <admin_accounts::AdminViewPerson uuid={uuid} />
        ),
        AdminRoute::ViewServiceAccount { uuid } => html!(
          <admin_accounts::AdminViewServiceAccount uuid={uuid} />
        ),
        AdminRoute::ViewOAuth2RP { rs_name } => html! {
          <admin_oauth2::AdminViewOAuth2 rs_name={rs_name} />
        },
    }
}
