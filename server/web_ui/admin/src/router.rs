use serde::{Deserialize, Serialize};
use yew::{html, Html};
use yew_router::prelude::Redirect;
use yew_router::Routable;

use crate::components;

#[derive(Routable, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum AdminRoute {
    #[at("/ui/admin")]
    AdminMenu,
    #[at("/ui/admin/groups")]
    AdminListGroups,
    #[at("/ui/admin/accounts")]
    AdminListAccounts,
    #[at("/ui/admin/oauth2")]
    AdminListOAuth2,

    #[at("/ui/admin/group/:uuid")]
    ViewGroup { uuid: String },
    #[at("/ui/admin/person/:uuid")]
    ViewPerson { uuid: String },
    #[at("/ui/admin/service_account/:uuid")]
    ViewServiceAccount { uuid: String },
    #[at("/ui/admin/oauth2/:rs_name")]
    ViewOAuth2RP { rs_name: String },

    #[not_found]
    #[at("/ui/admin/404")]
    NotFound,
}

pub(crate) fn admin_routes(route: AdminRoute) -> Html {
    match route {
        AdminRoute::AdminMenu => html! {
          <components::admin_menu::AdminMenu />
        },
        AdminRoute::AdminListAccounts => html!(
          <components::admin_accounts::AdminListAccounts />
        ),
        AdminRoute::AdminListGroups => html!(
          <components::admin_groups::AdminListGroups />
        ),
        AdminRoute::AdminListOAuth2 => html!(
          <components::admin_oauth2::AdminListOAuth2 />
        ),
        AdminRoute::ViewGroup { uuid } => {
            html!(<components::admin_groups::AdminViewGroup uuid={uuid} />)
            // html! {<></>}
        }
        AdminRoute::ViewPerson { uuid } => html!(
            <components::admin_accounts::AdminViewPerson uuid={uuid} />
        ),
        AdminRoute::ViewServiceAccount { uuid } => html!(
              <components::admin_accounts::AdminViewServiceAccount uuid={uuid} />
            // html! {<></>}
        ),
        AdminRoute::ViewOAuth2RP { rs_name } => html! {
          <components::admin_oauth2::AdminViewOAuth2 rs_name={rs_name} />

        },
        AdminRoute::NotFound => html! (
          <Redirect<AdminRoute> to={AdminRoute::NotFound}/>
        ),
    }
}
