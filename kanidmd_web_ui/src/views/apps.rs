use gloo::console;
use yew::prelude::*;

pub enum Msg {
    // Nothing
}

pub struct AppsApp {}

impl Component for AppsApp {
    type Message = Msg;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        console::debug!("views::apps::create");
        AppsApp {}
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::debug!("views::apps::changed");
        false
    }

    fn update(&mut self, _ctx: &Context<Self>, _msg: Self::Message) -> bool {
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
        console::debug!("views::apps::rendered");
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <>
              <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                <h2>{ "Apps" }</h2>
              </div>
              <div class="alert alert-warning" role="alert">
                { "🦀 Kanidm is still in early Alpha, this interface is a placeholder! " }
              </div>
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
                      <td>{ "informaasdftion" }</td>
                      <td>{ "text" }</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </>
        }
    }
}
