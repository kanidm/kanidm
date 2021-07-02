//! This is the top level router of the web ui for kanidm. It decides based on the incoming
//! request, where to direct this too, and if the requirements for that request have been
//! met before rendering. For example, if you land here with an oauth request, but you are
//! not atuhenticated, this will determine that and send you to authentication first, then
//! will allow you to proceed with the oauth flow.

use yew::prelude::*;
use yew_services::ConsoleService;

use yew_router::prelude::*;
use yew_router::router::Router;

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

fn switch(routes: &Route) -> Html {
    ConsoleService::log("manager::switch");
    match routes {
        Route::Landing => {
            yew_router::push_route(Route::Index);
            html! { <body></body> }
        }
        Route::Index => html! { <ViewsApp /> },
        Route::Login => html! { <LoginApp /> },
        Route::Oauth2 => html! { <Oauth2App /> },
        Route::NotFound => {
            html! {
                <body>
                    <h1>{ "404" }</h1>
                    <Link<Route> route=Route::Index>
                    { "Home" }
                    </Link<Route>>
                </body>
            }
        }
    }
}

pub struct ManagerApp {
    link: ComponentLink<Self>,
    is_ready: bool,
}

impl Component for ManagerApp {
    type Message = bool;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        ConsoleService::log("manager::create");
        ManagerApp {
            link,
            is_ready: false,
        }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        ConsoleService::log("manager::change");
        false
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        ConsoleService::log("manager::update");
        self.is_ready = msg;
        true
    }

    fn rendered(&mut self, first_render: bool) {
        ConsoleService::log("manager::rendered");
        if first_render {
            // Can only access the current_route AFTER it renders.
            // ConsoleService::log(format!("{:?}", yew_router::current_route::<Route>()).as_str())
            self.link.send_message(first_render)
        }
    }

    fn view(&self) -> Html {
        html! {
        <>
            <head>
                <meta charset="utf-8"/>
                <title>{ "Kanidm" }</title>
                <link rel="stylesheet" href="/pkg/external/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T"/>
                <link rel="stylesheet" href="/pkg/style.css"/>
                <script src="/pkg/external/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo"></script>
                <script src="/pkg/external/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1"></script>
                <script src="/pkg/external/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM"></script>
                <script src="/pkg/external/confetti.js"></script>
            </head>

            {
                if self.is_ready {
                    html! {<Router<Route> render=Router::render(switch) /> }
                } else {
                    html! { <body></body> }
                }
            }
        </>
        }
    }
}
