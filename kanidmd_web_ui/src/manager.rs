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
    html! { <body></body> }
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
                <body>
                    <h1>{ "404" }</h1>
                    <Link<Route> to={ Route::Index }>
                    { "Home" }
                    </Link<Route>>
                </body>
            }
        }
    }
}

pub struct ManagerApp {
    is_ready: bool,
}

impl Component for ManagerApp {
    type Message = bool;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        console::log!("manager::create");
        ManagerApp { is_ready: false }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::log!("manager::change");
        false
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::log!("manager::update");
        self.is_ready = msg;
        true
    }

    fn rendered(&mut self, ctx: &Context<Self>, first_render: bool) {
        console::log!("manager::rendered");
        if first_render {
            // Can only access the current_route AFTER it renders.
            // console::log!(format!("{:?}", yew_router::current_route::<Route>()).as_str())
            ctx.link().send_message(first_render)
        }
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
        <>
            <head>
                <meta charset="utf-8"/>
                <title>{ "Kanidm" }</title>
                <link rel="stylesheet" href="/pkg/external/bootstrap.min.css" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC"/>
                <link rel="stylesheet" href="/pkg/style.css"/>
                <script src="/pkg/external/bootstrap.bundle.min.js" integrity="sha384-MrcW6ZMFYlzcLA8Nl+NtUVF0sA7MsXsP1UyJoMp4YLEuNSfAP+JcXn/tWtIaxVXM"></script>
                <script src="/pkg/external/confetti.js"></script>
                <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🦀</text></svg>" />

            </head>

            {
                if self.is_ready {
                    html! {
                        <BrowserRouter>
                            <Switch<Route> render={ Switch::render(switch) } />
                        </BrowserRouter>
                    }
                } else {
                    html! { <body></body> }
                }
            }
        </>
        }
    }
}
