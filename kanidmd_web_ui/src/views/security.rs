use gloo::console;
use yew::prelude::*;

pub enum Msg {
    // Nothing
}

pub struct SecurityApp {}

impl Component for SecurityApp {
    type Message = Msg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        console::log!("views::security::create");
        SecurityApp {}
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::log!("views::security::changed");
        false
    }

    fn update(&mut self, _ctx: &Context<Self>, _msg: Self::Message) -> bool {
        console::log!("views::security::update");
        /*
        match msg {
            ViewsMsg::Logout => {
            }
        }
        */
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        console::log!("views::security::rendered");
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
              <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                <h2>{ "Security" }</h2>
              </div>
        }
    }
}
