use crate::components::{admin_accounts, admin_groups, admin_oauth2, adminmenu};
use crate::error::*;
use crate::manager::Route;
use crate::models;
use crate::utils;
use gloo::console;
use kanidm_proto::v1::WhoamiResponse;
use serde::{Deserialize, Serialize};
use wasm_bindgen::{JsCast, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};
use yew::prelude::*;
use yew_router::prelude::*;

mod apps;
mod components;
mod profile;
mod security;

use apps::AppsApp;
use profile::ProfileApp;
use security::SecurityApp;

#[derive(Routable, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum ViewRoute {
    #[at("/ui/view/admin/*")]
    Admin,

    #[at("/ui/view/apps")]
    Apps,

    #[at("/ui/view/profile")]
    Profile,

    #[at("/ui/view/security")]
    Security,

    #[not_found]
    #[at("/ui/view/404")]
    NotFound,
}

#[derive(Routable, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum AdminRoute {
    #[at("/ui/view/admin/menu")]
    AdminMenu,

    #[at("/ui/view/admin/groups")]
    AdminListGroups,
    #[at("/ui/view/admin/accounts")]
    AdminListAccounts,
    #[at("/ui/view/admin/oauth2")]
    AdminListOAuth2,

    #[at("/ui/view/admin/group/:uuid")]
    ViewGroup { uuid: String },
    #[at("/ui/view/admin/person/:uuid")]
    ViewPerson { uuid: String },
    #[at("/ui/view/admin/service_account/:uuid")]
    ViewServiceAccount { uuid: String },
    #[at("/ui/view/admin/oauth2/:uuid")]
    ViewOAuth2RP { uuid: String },

    #[not_found]
    #[at("/ui/view/admin/404")]
    NotFound,
}

enum State {
    LoginRequired,
    Verifying,
    Authenticated(String),
    Error { emsg: String, kopid: Option<String> },
}

#[derive(PartialEq, Eq, Properties)]
pub struct ViewProps {
    pub token: String,
    pub current_user: Option<WhoamiResponse>,
}

pub struct ViewsApp {
    state: State,
    current_user: Option<WhoamiResponse>,
}

pub enum ViewsMsg {
    Verified(String),
    Logout,
    ProfileInfoRecieved(WhoamiResponse),
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
        #[cfg(debug)]
        console::debug!("views::create");

        // Ensure the token is valid before we proceed. Could be
        // due to a session expiry or something else, but we want to make
        // sure we are really authenticated before we proceed.
        let state = match models::get_bearer_token() {
            Some(token) => {
                // Send off the validation event.
                ctx.link().send_future(async {
                    match Self::check_token_valid(token).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                State::Verifying
            }
            None => State::LoginRequired,
        };

        ViewsApp {
            state,
            current_user: None,
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        #[cfg(debug)]
        console::debug!("views::changed");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug)]
        console::debug!("views::update");
        match msg {
            ViewsMsg::Verified(token) => {
                let tk = token.clone();
                self.state = State::Authenticated(token);
                // Populate the user profile
                ctx.link().send_future(async {
                    match Self::fetch_user_data(tk).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                true
            }
            ViewsMsg::Logout => {
                models::clear_bearer_token();
                self.state = State::LoginRequired;
                true
            }
            ViewsMsg::ProfileInfoRecieved(profile) => {
                self.current_user = Some(profile);
                true
            }
            ViewsMsg::Error { emsg, kopid } => {
                self.state = State::Error { emsg, kopid };
                true
            }
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug)]
        console::debug!("views::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.state {
            State::LoginRequired => {
                // Where are we?
                let loc = ctx
                    .link()
                    .history()
                    .expect_throw("failed to read history")
                    .location()
                    .route()
                    .expect_throw("invalid route");

                models::push_return_location(models::Location::Views(loc));

                ctx.link()
                    .history()
                    .expect_throw("failed to read history")
                    .push(Route::Login);
                html! { <div></div> }
            }
            State::Verifying => {
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
            State::Authenticated(_) => self.view_authenticated(ctx),
            State::Error { emsg, kopid } => {
                html! {
                  <main class="form-signin">
                    <div class="alert alert-danger" role="alert">
                      <h2>{ "An Error Occured 🥺" }</h2>
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
    fn view_authenticated(&self, ctx: &Context<Self>) -> Html {
        let current_user = self.current_user.clone();

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

                <li class="mb-1">
                  <Link<ViewRoute> classes="nav-link" to={ViewRoute::Profile}>
                    <span data-feather="file"></span>
                    { "Profile" }
                  </Link<ViewRoute>>
                </li>

                <li class="mb-1">
                  <Link<ViewRoute> classes="nav-link" to={ViewRoute::Security}>
                    <span data-feather="file"></span>
                    { "Security" }
                  </Link<ViewRoute>>
                </li>
                // TODO: the admin link should only show up if you're an admin
                <li class="mb-1">
                  <Link<AdminRoute> classes="nav-link" to={AdminRoute::AdminMenu}>
                    <span data-feather="file"></span>
                    { "Admin" }
                  </Link<AdminRoute>>
                </li>
                <li class="mb-1">
                  <a class="nav-link" href="#"
                    data-bs-toggle="modal"
                    data-bs-target={format!("#{}", crate::constants::ID_SIGNOUTMODAL)}
                    >{"Sign out"}</a>
                </li>
                  </ul>
                  <form class="d-flex">
                    <input class="form-control me-2" type="search" placeholder="Search" aria-label="Search" />
                    <button class="btn btn-outline-light" type="submit">{"Search"}</button>
                  </form>
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
              <Switch<ViewRoute> render={ Switch::render(move |route: &ViewRoute| {
                    // safety - can't panic because to get to this location we MUST be authenticated!
                    let token =
                        models::get_bearer_token().expect_throw("Invalid state, bearer token must be present!");

                    match route {

                        ViewRoute::Admin => html!{
                            <Switch<AdminRoute> render={ Switch::render(admin_routes) } />
                        },
                        ViewRoute::Apps => html! { <AppsApp /> },
                        ViewRoute::Profile => html! { <ProfileApp token={ token } current_user={ current_user.clone() } /> },
                        ViewRoute::Security => html! { <SecurityApp token={ token } current_user={ current_user.clone() } /> },
                        ViewRoute::NotFound => html! {
                            <Redirect<Route> to={Route::NotFound}/>
                        },
                    }
              })} />
        </main>
        </>
          }
    }
    async fn check_token_valid(token: String) -> Result<ViewsMsg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::SameOrigin);

        let request = Request::new_with_str_and_init("/v1/auth/valid", &opts)?;

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
            Ok(ViewsMsg::Verified(token))
        } else if status == 401 {
            // Not valid, re-auth
            Ok(ViewsMsg::Logout)
        } else {
            let headers = resp.headers();
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(ViewsMsg::Error { emsg, kopid })
        }
    }
    async fn fetch_user_data(token: String) -> Result<ViewsMsg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::SameOrigin);

        let request = Request::new_with_str_and_init("/v1/self", &opts)?;
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
        let headers = resp.headers();
        let kopid = headers.get("x-kanidm-opid").ok().flatten();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let whoamiresponse: WhoamiResponse = serde_wasm_bindgen::from_value(jsval)
                .map_err(|e| {
                    let e_msg = format!("serde error getting user data -> {:?}", e);
                    console::error!(e_msg.as_str());
                })
                .expect_throw("Invalid response type");
            Ok(ViewsMsg::ProfileInfoRecieved(whoamiresponse))
        } else {
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(ViewsMsg::Error { emsg, kopid })
        }
    }
}

fn admin_routes(route: &AdminRoute) -> Html {
    match route {
        AdminRoute::AdminMenu => html! {
          <adminmenu::AdminMenu />
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
            html!(<admin_groups::AdminViewGroup uuid={uuid.clone()} />)
        }
        AdminRoute::ViewPerson { uuid } => html!(
          <admin_accounts::AdminViewPerson uuid={uuid.clone()} />
        ),
        AdminRoute::ViewServiceAccount { uuid } => html!(
          <admin_accounts::AdminViewServiceAccount uuid={uuid.clone()} />
        ),
        AdminRoute::ViewOAuth2RP { uuid } => html! {
          <admin_oauth2::AdminViewOAuth2 uuid={uuid.clone()} />
        },
    }
}
