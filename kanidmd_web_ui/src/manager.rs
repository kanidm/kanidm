//! This is the top level router of the web ui for kanidm. It decides based on the incoming
//! request, where to direct this too, and if the requirements for that request have been
//! met before rendering. For example, if you land here with an oauth request, but you are
//! not atuhenticated, this will determine that and send you to authentication first, then
//! will allow you to proceed with the oauth flow.

use gloo::console;
use wasm_bindgen::UnwrapThrowExt;
use yew::functional::*;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::login::LoginApp;
use crate::oauth2::Oauth2App;
use crate::views::{ViewRoute, ViewsApp};
use serde::{Deserialize, Serialize};

// router to decide on state.
#[derive(Routable, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum Route {
    #[at("/")]
    Landing,

    #[at("/ui/view/:s")]
    Views,

    #[at("/ui/login")]
    Login,

    #[at("/ui/oauth2")]
    Oauth2,

    #[not_found]
    #[at("/404")]
    NotFound,
}

#[function_component(Landing)]
fn landing() -> Html {
    // Do this to allow use_history to work because lol.
    use_history()
        .expect_throw("Unable to access history")
        .push(ViewRoute::Apps);
    html! { <main></main> }
}

fn switch(route: &Route) -> Html {
    console::log!("manager::switch");
    match route {
        Route::Landing => html! { <Landing /> },
        Route::Login => html! { <LoginApp /> },
        Route::Oauth2 => html! { <Oauth2App /> },
        Route::Views => html! { <ViewsApp /> },
        Route::NotFound => {
            html! {
                <main>
                    <h1>{ "404" }</h1>
                    <Link<ViewRoute> to={ ViewRoute::Apps }>
                    { "Home" }
                    </Link<ViewRoute>>
                </main>
            }
        }
    }
}

pub struct ManagerApp {}

impl Component for ManagerApp {
    type Message = ();
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        console::log!("manager::create");
        ManagerApp {}
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::log!("manager::change");
        false
    }

    fn update(&mut self, _ctx: &Context<Self>, _msg: Self::Message) -> bool {
        console::log!("manager::update");
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        console::log!("manager::rendered");
        // Can only access the current_route AFTER it renders.
        // console::log!(format!("{:?}", yew_router::current_route::<Route>()).as_str())
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <BrowserRouter>
                <Switch<Route> render={ Switch::render(switch) } />
            </BrowserRouter>
        }
    }
}
