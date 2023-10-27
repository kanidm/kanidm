//! This handles the login/auth flows, and is designed to be smol and snappy
//! so it loads fast and gets the user to where they need to go!
//!
//! - /ui/login
//! - /ui/oauth2
//! - /ui/reauth

mod components;
mod oauth2;
pub mod router;

use gloo::console;
use kanidmd_web_ui_shared::constants::URL_LOGIN;
use kanidmd_web_ui_shared::utils::window;
use router::LoginRoute;
#[allow(unused_imports)] // because it's needed to compile wasm things
use wasm_bindgen::prelude::wasm_bindgen;

use wasm_bindgen::{JsValue, UnwrapThrowExt};
use yew::{html, Html};
use yew_router::{BrowserRouter, Switch};

use crate::components::{LoginApp, LoginWorkflow};
use crate::oauth2::Oauth2App;

// Needed for yew to pass by value
#[allow(clippy::needless_pass_by_value)]
/// Handle routes for the login_flows app
fn switch(route: LoginRoute) -> Html {
    #[cfg(debug_assertions)]
    console::debug!(format!("UserUiApp::switch -> {:?}", route).as_str());
    match route {
        LoginRoute::Login => html! {<LoginApp workflow={LoginWorkflow::Login} />},
        LoginRoute::Reauth => html! {<LoginApp workflow={LoginWorkflow::Reauth} />},
        LoginRoute::Oauth2 => html! {<Oauth2App />},
        LoginRoute::NotFound => {
            console::error!("Unknown route {}, showing login flow");
            window()
                .location()
                .set_href(URL_LOGIN)
                .expect_throw("Failed to redirect user to the login page!");
            html! { <a href={URL_LOGIN}>{"Click here to return to the login page..."}</a> }
        }
    }
}

struct LoginFlowsApp {}

impl yew::Component for LoginFlowsApp {
    type Message = ();
    type Properties = ();

    fn create(_ctx: &yew::Context<Self>) -> Self {
        Self {}
    }

    fn view(&self, _ctx: &yew::Context<Self>) -> Html {
        html! {
            <BrowserRouter>
                <Switch<LoginRoute> render={switch} />
            </BrowserRouter>
        }
    }
}

/// This is the entry point of the web front end.
///
/// This triggers the manager app to load and begin its event loop.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn run_app() -> Result<(), JsValue> {
    yew::Renderer::<LoginFlowsApp>::new().render();
    Ok(())
}
