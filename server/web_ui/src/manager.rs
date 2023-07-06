//! This is the top level router of the web ui for kanidm. It decides based on the incoming
//! request, where to direct this too, and if the requirements for that request have been
//! met before rendering. For example, if you land here with an oauth request, but you are
//! not authenticated, this will determine that and send you to authentication first, then
//! will allow you to proceed with the oauth flow.

use gloo::console;
use serde::{Deserialize, Serialize};
use wasm_bindgen::UnwrapThrowExt;
use yew::functional::*;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::credential::reset::CredentialResetApp;
use crate::login::{LoginApp, LoginWorkflow};
use crate::oauth2::Oauth2App;
use crate::views::{ViewRoute, ViewsApp};

// router to decide on state.
#[derive(Routable, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum Route {
    #[at("/")]
    Landing,

    #[at("/ui/login")]
    Login,

    #[at("/ui/reauth")]
    Reauth,

    #[at("/ui/oauth2")]
    Oauth2,

    #[at("/ui/reset")]
    CredentialReset,

    #[not_found]
    #[at("/ui/404")]
    NotFound,

    #[at("/ui/*")]
    Views,
}

#[function_component(Landing)]
fn landing() -> Html {
    // Do this to allow use_navigator to work because lol.
    yew_router::hooks::use_navigator()
        .expect_throw("Unable to access history")
        .push(&ViewRoute::Apps);
    html! { <main></main> }
}

// Needed for yew to pass by value
#[allow(clippy::needless_pass_by_value)]
fn switch(route: Route) -> Html {
    #[cfg(debug_assertions)]
    console::debug!("manager::switch");
    match route {
        #[allow(clippy::let_unit_value)]
        Route::Landing => html! { <Landing /> },
        #[allow(clippy::let_unit_value)]
        Route::Login => html! { <LoginApp workflow={ LoginWorkflow::Login } /> },
        #[allow(clippy::let_unit_value)]
        Route::Reauth => html! { <LoginApp workflow={ LoginWorkflow::Reauth } /> },
        #[allow(clippy::let_unit_value)]
        Route::Oauth2 => html! { <Oauth2App /> },
        #[allow(clippy::let_unit_value)]
        Route::Views => html! { <ViewsApp /> },
        #[allow(clippy::let_unit_value)]
        Route::CredentialReset => html! { <CredentialResetApp /> },
        Route::NotFound => {
            add_body_form_classes!();

            html! {
                <>
                <main class="flex-shrink-0 form-signin text-center">
                        <img src="/pkg/img/logo-square.svg" alt="Kanidm" class="kanidm_logo"/>
                        // TODO: replace this with a call to domain info
                        <h3>{ "404 - Page not found" }</h3>

                        <div class="container">
                        <Link<ViewRoute> to={ ViewRoute::Apps }>
                        { "Home" }
                        </Link<ViewRoute>>
                        </div>
                </main>
                { crate::utils::do_footer() }
                </>
            }
        }
    }
}

pub struct ManagerApp {}

impl Component for ManagerApp {
    type Message = ();
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("manager::create");
        ManagerApp {}
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("manager::change");
        false
    }

    fn update(&mut self, _ctx: &Context<Self>, _msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("manager::update");
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("manager::rendered");
        // Can only access the current_route AFTER it renders.
        // console::debug!(format!("{:?}", yew_router::current_route::<Route>()).as_str())
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <BrowserRouter>
                <Switch<Route> render={ switch } />
            </BrowserRouter>
        }
    }
}
