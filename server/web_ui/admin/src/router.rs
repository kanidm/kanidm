#![allow(clippy::disallowed_types)] // because `Routable` uses a hashmap

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
    #[at("/ui/admin/object-graph")]
    AdminObjectGraph,
    #[at("/ui/admin/oauth2")]
    AdminListOAuth2,

    #[at("/ui/admin/group/:id_or_name")]
    ViewGroup { id_or_name: String },
    #[at("/ui/admin/person/:id_or_name")]
    ViewPerson { id_or_name: String },
    #[at("/ui/admin/service_account/:id_or_name")]
    ViewServiceAccount { id_or_name: String },
    #[at("/ui/admin/oauth2/:id_or_name")]
    ViewOAuth2RP { id_or_name: String },

    #[not_found]
    #[at("/ui/admin/404")]
    NotFound,
}

pub(crate) fn switch(route: AdminRoute) -> Html {
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
        AdminRoute::AdminObjectGraph => html!(
            <components::admin_objectgraph::AdminObjectGraph />
        ),
        AdminRoute::AdminListOAuth2 => html!(
          <components::admin_oauth2::AdminListOAuth2 />
        ),
        AdminRoute::ViewGroup { id_or_name } => {
            html!(<components::admin_groups::AdminViewGroup id_or_name={id_or_name} />)
        }
        AdminRoute::ViewPerson { id_or_name } => html!(
            <components::admin_accounts::AdminViewPerson id_or_name={id_or_name} />
        ),
        AdminRoute::ViewServiceAccount { id_or_name } => html!(
              <components::admin_accounts::AdminViewServiceAccount id_or_name={id_or_name} />
            // html! {<></>}
        ),
        AdminRoute::ViewOAuth2RP { id_or_name } => html! {
          <components::admin_oauth2::AdminViewOAuth2 id_or_name={id_or_name} />

        },
        AdminRoute::NotFound => html! (
          <Redirect<AdminRoute> to={AdminRoute::NotFound}/>
        ),
    }
}
