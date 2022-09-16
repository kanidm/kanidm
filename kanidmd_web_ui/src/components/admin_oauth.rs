use crate::components::adminmenu::ListProps;
use crate::components::alpha_warning_banner;
use crate::constants::CSS_PAGE_HEADER;
use yew::prelude::*;

pub struct AdminListOAuth;

impl Component for AdminListOAuth {
    type Message = ();
    type Properties = ListProps;

    fn create(_ctx: &Context<Self>) -> Self {
        AdminListOAuth
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <>
              <div class={CSS_PAGE_HEADER}>
                <h2>{ "System Administration" }</h2>
              </div>

              { alpha_warning_banner() }
        <div>
            {"OAuth Configs go here!"}
        </div>
        // TODO: pull the list from /v1/oauth2
        </>
        }
    }
}
