//! This is the top level router of the web ui for kanidm. It decides based on the incoming
//! request, where to direct this too, and if the requirements for that request have been
//! met before rendering. For example, if you land here with an oauth request, but you are
//! not atuhenticated, this will determine that and send you to authentication first, then
//! will allow you to proceed with the oauth flow.

use gloo::console;
use yew::functional::*;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::login::LoginApp;
use crate::oauth2::Oauth2App;
use crate::views::ViewsApp;

// router to decide on state.
#[derive(Routable, PartialEq, Clone, Debug)]
pub enum Route {
    #[at("/")]
    Landing,

    #[at("/ui/view")]
    Index,

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
    use_history().unwrap().push(Route::Index);
    html! { <main></main> }
}

fn switch(routes: &Route) -> Html {
    console::log!("manager::switch");
    match routes {
        Route::Landing => html! { <Landing /> },
        Route::Index => html! { <ViewsApp /> },
        Route::Login => html! { <LoginApp /> },
        Route::Oauth2 => html! { <Oauth2App /> },
        Route::NotFound => {
            html! {
                <main>
                    <h1>{ "404" }</h1>
                    <Link<Route> to={ Route::Index }>
                    { "Home" }
                    </Link<Route>>
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
