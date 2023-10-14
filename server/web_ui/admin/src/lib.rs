mod components;
mod router;

use gloo::console;
use kanidmd_web_ui_shared::add_body_form_classes;
use kanidmd_web_ui_shared::utils::do_footer;
#[allow(unused_imports)] // because it's needed to compile wasm things
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

use yew::{html, Component, Context, Html};
use yew_router::{BrowserRouter, Switch};

pub struct AdminApp {}

// // Needed for yew to pass by value
// #[allow(clippy::needless_pass_by_value)]
// fn switch(route: Route) -> Html {
//     #[cfg(debug_assertions)]
//     console::debug!(format!("manager::switch -> {:?}", route).as_str());
//     match route {
//         #[allow(clippy::let_unit_value)]
//         Route::Landing => html! { <>{"Hello world"}</> },

//         Route::NotFound => html! { <>{"404!"}</> },
//     }
// }

impl Component for AdminApp {
    type Message = ();
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
        add_body_form_classes!();

        html! {

            <>
            <nav class="navbar navbar-expand-md navbar-dark bg-dark mb-4">
              <div class="container-fluid">
              <a href="/ui/apps">{"Home"}</a>
              </div>

            </nav>

            <BrowserRouter>
                <Switch<router::AdminRoute> render={ router::admin_routes } />
            </BrowserRouter>
            { do_footer() }
            </>
        }
    }
}

/// This is the entry point of the web front end. This triggers the manager app to load and begin
/// it's event loop.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn run_app() -> Result<(), JsValue> {
    yew::Renderer::<AdminApp>::new().render();
    Ok(())
}
