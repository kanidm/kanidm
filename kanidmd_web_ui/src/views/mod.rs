use crate::models;
use gloo::console;
use wasm_bindgen::UnwrapThrowExt;
use yew::prelude::*;

use crate::manager::Route;
use yew_router::prelude::*;

use serde::{Deserialize, Serialize};

mod apps;
mod components;
mod security;

use apps::AppsApp;
use security::SecurityApp;

#[derive(Routable, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub enum ViewRoute {
    #[at("/ui/view/apps")]
    Apps,

    #[at("/ui/view/security")]
    Security,

    #[not_found]
    #[at("/ui/view/404")]
    NotFound,
}

enum State {
    LoginRequired,
    Authenticated(String),
}

pub struct ViewsApp {
    state: State,
}

pub enum ViewsMsg {
    Logout,
}

fn switch(route: &ViewRoute) -> Html {
    console::log!("views::switch");
    match route {
        ViewRoute::Apps => html! { <AppsApp /> },
        ViewRoute::Security => html! { <SecurityApp /> },
        ViewRoute::NotFound => html! {
            <Redirect<Route> to={Route::NotFound}/>
        },
    }
}

impl Component for ViewsApp {
    type Message = ViewsMsg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        console::log!("views::create");

        let state = models::get_bearer_token()
            .map(State::Authenticated)
            .unwrap_or(State::LoginRequired);

        ViewsApp { state }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::log!("views::changed");
        false
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::log!("views::update");
        match msg {
            ViewsMsg::Logout => {
                models::clear_bearer_token();
                self.state = State::LoginRequired;
                true
            }
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        console::log!("views::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match self.state {
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
            State::Authenticated(_) => self.view_authenticated(ctx),
        }
    }
}

impl ViewsApp {
    fn view_authenticated(&self, ctx: &Context<Self>) -> Html {
        // WARN set dash-body against body here?
        html! {
        <div class="dash-body">
          <header class="navbar navbar-dark sticky-top bg-dark flex-md-nowrap p-0 shadow">
            <a class="navbar-brand col-md-3 col-lg-2 me-0 px-3" href="#">{ "Kanidm" }</a>
            <button class="navbar-toggler position-absolute d-md-none collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#sidebarMenu" aria-controls="sidebarMenu" aria-expanded="false" aria-label="Toggle navigation">
              <span class="navbar-toggler-icon"></span>
            </button>
            <div class="navbar-nav">
              <div class="nav-item text-nowrap">
                <a class="nav-link px-3" href="#" onclick={ ctx.link().callback(|_| ViewsMsg::Logout) } >{ "Sign out" }</a>
              </div>
            </div>
          </header>

          <div class="container-fluid">
            <div class="row">
              <nav id="sidebarMenu" class="col-md-3 col-lg-2 d-md-block bg-light sidebar collapse">
                <div class="position-sticky pt-3">
                  <ul class="nav flex-column">

                    <li class="nav-item">
                      <Link<ViewRoute> classes="nav-link" to={ViewRoute::Apps}>
                        <span data-feather="file"></span>
                        { "Apps" }
                      </Link<ViewRoute>>
                    </li>

                    <li class="nav-item">
                      <Link<ViewRoute> classes="nav-link" to={ViewRoute::Security}>
                        <span data-feather="file"></span>
                        { "Security" }
                      </Link<ViewRoute>>
                    </li>

                  </ul>
                </div>
              </nav>

              <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                <Switch<ViewRoute> render={ Switch::render(switch) } />
              </main>
            </div>
          </div>
        </div>
          }
    }
}
