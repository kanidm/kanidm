#[cfg(debug)]
use gloo::console;
use yew::prelude::*;

use crate::components::alpha_warning_banner;
use crate::constants::{CSS_CELL, CSS_PAGE_HEADER, CSS_TABLE};

pub enum Msg {
    // Nothing
}

pub struct AppsApp {}

impl Component for AppsApp {
    type Message = Msg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        #[cfg(debug)]
        console::debug!("views::apps::create");
        AppsApp {}
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        #[cfg(debug)]
        console::debug!("views::apps::changed");
        false
    }

    fn update(&mut self, _ctx: &Context<Self>, _msg: Self::Message) -> bool {
        #[cfg(debug)]
        console::debug!("views::apps::update");
        /*
        match msg {
            ViewsMsg::Logout => {
            }
        }
        */
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug)]
        console::debug!("views::apps::rendered");
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <>
              <div class={CSS_PAGE_HEADER}>
                <h2>{ "Apps" }</h2>
              </div>

              { alpha_warning_banner() }
              <div class="table-responsive">
                <table class={CSS_TABLE}>
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
                      <td class={CSS_CELL}>{ "1,001" }</td>
                      <td class={CSS_CELL}>{ "random" }</td>
                      <td class={CSS_CELL}>{ "data" }</td>
                      <td class={CSS_CELL}>{ "placeholder" }</td>
                      <td class={CSS_CELL}>{ "text" }</td>
                    </tr>
                    <tr>
                      <td class={CSS_CELL}>{ "1,015" }</td>
                      <td class={CSS_CELL}>{ "random" }</td>
                      <td class={CSS_CELL}>{ "tabular" }</td>
                      <td class={CSS_CELL}>{ "informaasdftion" }</td>
                      <td class={CSS_CELL}>{ "text" }</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </>
        }
    }
}
