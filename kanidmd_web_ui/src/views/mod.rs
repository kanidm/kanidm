use yew::prelude::*;
use yew_services::ConsoleService;

use crate::models;

use crate::manager::Route;

enum State {
    LoginRequired,
    Authenticated(String),
}

pub struct ViewsApp {
    link: ComponentLink<Self>,
    state: State,
}

pub enum ViewsMsg {
    Logout,
}

impl Component for ViewsApp {
    type Message = ViewsMsg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        ConsoleService::log("views::create");

        let state = models::get_bearer_token()
            .map(State::Authenticated)
            .unwrap_or(State::LoginRequired);

        ViewsApp { link, state }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        ConsoleService::log("views::change");
        false
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        ConsoleService::log("views::update");
        match msg {
            ViewsMsg::Logout => {
                models::clear_bearer_token();
                self.state = State::LoginRequired;
                true
            }
        }
    }

    fn rendered(&mut self, _first_render: bool) {
        ConsoleService::log("views::rendered");
    }

    fn view(&self) -> Html {
        match self.state {
            State::LoginRequired => {
                models::push_return_location(models::Location::Views);
                yew_router::push_route(Route::Login);
                html! { <div></div> }
            }
            State::Authenticated(_) => self.view_authenticated(),
        }
    }
}

impl ViewsApp {
    fn view_authenticated(&self) -> Html {
        html! {
        <body class="dash-body">
          <header class="navbar navbar-dark sticky-top bg-dark flex-md-nowrap p-0 shadow">
            <a class="navbar-brand col-md-3 col-lg-2 me-0 px-3" href="#">{ "Kanidm" }</a>
            <button class="navbar-toggler position-absolute d-md-none collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#sidebarMenu" aria-controls="sidebarMenu" aria-expanded="false" aria-label="Toggle navigation">
              <span class="navbar-toggler-icon"></span>
            </button>
            <div class="navbar-nav">
              <div class="nav-item text-nowrap">
                <a class="nav-link px-3" href="#" onclick=self.link.callback(|_| ViewsMsg::Logout) >{ "Sign out" }</a>
              </div>
            </div>
          </header>

          <div class="container-fluid">
            <div class="row">
              <nav id="sidebarMenu" class="col-md-3 col-lg-2 d-md-block bg-light sidebar collapse">
                <div class="position-sticky pt-3">
                  <ul class="nav flex-column">
                    <li class="nav-item">
                      <a class="nav-link active" aria-current="page" href="#">
                        <span data-feather="home"></span>
                        { "Account" }
                      </a>
                    </li>
                  </ul>
                </div>
              </nav>

              <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4">
                <h2>{ "Section title" }</h2>
                <div class="table-responsive">
                  <table class="table table-striped table-sm">
                    <thead>
                      <tr>
                        <th scope="col">{ "#" }</th>
                        <th scope="col">{ "Header" }</th>
                        <th scope="col">{ "Header" }</th>
                        <th scope="col">{ "Header" }</th>
                        <th scope="col">{ "Header" }</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>{ "1,001" }</td>
                        <td>{ "random" }</td>
                        <td>{ "data" }</td>
                        <td>{ "placeholder" }</td>
                        <td>{ "text" }</td>
                      </tr>
                      <tr>
                        <td>{ "1,015" }</td>
                        <td>{ "random" }</td>
                        <td>{ "tabular" }</td>
                        <td>{ "information" }</td>
                        <td>{ "text" }</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </main>
            </div>
          </div>
        </body>
          }
    }
}
