mod components;
mod router;

use gloo::console::{self, error};
use kanidmd_web_ui_shared::add_body_form_classes;
use kanidmd_web_ui_shared::constants::{
    CSS_NAVBAR_BRAND, CSS_NAVBAR_LINKS_UL, CSS_NAVBAR_NAV, CSS_NAV_LINK, ID_NAVBAR_COLLAPSE,
    IMG_LOGO_SQUARE, URL_USER_HOME,
};
use kanidmd_web_ui_shared::ui::{signout_link, signout_modal, ui_logout};
use kanidmd_web_ui_shared::utils::do_footer;
#[allow(unused_imports)] // because it's needed to compile wasm things
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use yew::{html, Component, Context, Html};
use yew_router::prelude::Link;
use yew_router::{BrowserRouter, Switch};

use crate::router::AdminRoute;

pub struct AdminApp {}

/// This builds the navbar, it's not generic because the link on the logo is different
fn make_navbar(links: Vec<Html>) -> Html {
    html! {
      <nav class={CSS_NAVBAR_NAV}>
          <div class="container-fluid">
          <a href={URL_USER_HOME} class={CSS_NAVBAR_BRAND}>
            {"Kanidm Administration"}
            </a>
            // this shows a button on mobile devices to open the menu
            <button class="navbar-toggler bg-light" type="button" data-bs-toggle="collapse" data-bs-target={["#", ID_NAVBAR_COLLAPSE].concat()} aria-controls={ID_NAVBAR_COLLAPSE} aria-expanded="false" aria-label="Toggle navigation">
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

#[derive(Clone, Debug)]
pub enum AdminViewsMsg {
    Logout,
    LogoutComplete,
}

impl Component for AdminApp {
    type Message = AdminViewsMsg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("manager::create");
        AdminApp {}
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("manager::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("manager::update");
        match msg {
            AdminViewsMsg::Logout => {
                console::debug!("manager::update -> logout");

                ctx.link().send_future(async {
                    match Self::fetch_logout().await {
                        Ok(v) => v,
                        Err(v) => {
                            error!("... failed to log out? {:?}", v);
                            AdminViewsMsg::Logout
                        }
                    }
                });
            }
            AdminViewsMsg::LogoutComplete => {
                let window = gloo_utils::window();
                window.location().set_href(URL_USER_HOME).unwrap();
            }
        }

        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("manager::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        add_body_form_classes!();

        let links = vec![
            html! {<a href={URL_USER_HOME} class={CSS_NAV_LINK}>{"Home"}</a>},
            html! {<Link<AdminRoute> classes={CSS_NAV_LINK} to={AdminRoute::AdminMenu}>{"Admin"}</Link<AdminRoute>>},
            html! {<Link<AdminRoute> classes={CSS_NAV_LINK} to={AdminRoute::AdminListAccounts}>{"Accounts"}</Link<AdminRoute>>},
            html! {<Link<AdminRoute> classes={CSS_NAV_LINK} to={AdminRoute::AdminListGroups}>{"Groups"}</Link<AdminRoute>>},
            html! {<Link<AdminRoute> classes={CSS_NAV_LINK} to={AdminRoute::AdminObjectGraph}>{"ObjectGraph"}</Link<AdminRoute>>},
            html! {<Link<AdminRoute> classes={CSS_NAV_LINK} to={AdminRoute::AdminListOAuth2}>{"OAuth2"}</Link<AdminRoute>>},
            signout_link(),
        ];

        html! {
            <BrowserRouter>

                // sign out modal dialogue box
                {signout_modal(ctx, AdminViewsMsg::Logout)}
                {make_navbar(links)}

                <main class="p-3 x-auto">
                    <Switch<AdminRoute> render={ router::switch } />
                </main>
                { do_footer() }
            </BrowserRouter>
        }
    }
}

impl AdminApp {
    async fn fetch_logout() -> Result<AdminViewsMsg, String> {
        match ui_logout().await {
            Ok(_) => Ok(AdminViewsMsg::LogoutComplete),
            Err((emsg, _kopid)) => {
                error!("failed to process logout request: {}", emsg);
                Ok(AdminViewsMsg::Logout)
            }
        }
    }
}

/// This is the entry point of the web front end. This triggers the manager app to load and begin
/// its event loop.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn run_app() -> Result<(), JsValue> {
    yew::Renderer::<AdminApp>::new().render();
    Ok(())
}
