use crate::components::alpha_warning_banner;
use crate::constants::CSS_PAGE_HEADER;
// use crate::error::FetchError;
use crate::views::AdminRoute;

use serde::{Deserialize, Serialize};
use yew::{html, Component, Context, Html, Properties};
use yew_router::prelude::Link;

const CSS_LINK_DARK_STRETCHED: &str = "link-dark stretched-link";
const CSS_CARD: &str = "card text-center";
const CSS_CARD_BODY: &str = "card-body text-center";

#[derive(PartialEq, Properties)]
pub struct Props;

// #[derive(PartialEq, Properties)]
// pub struct ListProps {
//     #[allow(dead_code)]
//     search: Option<String>,
//     #[allow(dead_code)]
//     page: Option<u32>,
// }
pub struct AdminMenu;

impl Component for AdminMenu {
    type Message = ();
    type Properties = Props;

    fn create(_ctx: &Context<Self>) -> Self {
        AdminMenu
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <>
              <div class={CSS_PAGE_HEADER}>
                <h2>{ "System Administration" }</h2>
              </div>
              { alpha_warning_banner() }
        <div class="row row-cols-1 row-cols-sm-2 row-cols-md-3 g-3">
          <div class="col">
            <div class={CSS_CARD}>
            <Link<AdminRoute> classes={CSS_LINK_DARK_STRETCHED} to={AdminRoute::AdminListAccounts}>
            <img src={"/pkg/img/icon-accounts.svg"} />
            </Link<AdminRoute>>
              <div class={CSS_CARD_BODY}>
              <h3>
              <Link<AdminRoute> classes={CSS_LINK_DARK_STRETCHED} to={AdminRoute::AdminListAccounts}>
              { "Accounts" }
              </Link<AdminRoute>>
              </h3>
              </div>

            </div>
          </div>

          // card for groups
          <div class="col">
            <div class={CSS_CARD}>
            <Link<AdminRoute> classes={CSS_LINK_DARK_STRETCHED} to={AdminRoute::AdminListGroups}>
            <img src={"/pkg/img/icon-groups.svg"} />
            </Link<AdminRoute>>
              <div class={CSS_CARD_BODY}>
              <h3>
              <Link<AdminRoute> classes={CSS_LINK_DARK_STRETCHED} to={AdminRoute::AdminListGroups}>
              { "Groups" }
              </Link<AdminRoute>>
              </h3>
              </div>

            </div>
          </div>

          // card for oauth
          <div class="col">
            <div class={CSS_CARD}>
            <Link<AdminRoute> classes={CSS_LINK_DARK_STRETCHED} to={AdminRoute::AdminListOAuth}>
            <img src={"/pkg/img/icon-oauth2.svg"} />
            </Link<AdminRoute>>
              <div class={CSS_CARD_BODY}>
              <h3>
              <Link<AdminRoute> classes={CSS_LINK_DARK_STRETCHED} to={AdminRoute::AdminListOAuth}>
              { "OAuth Configurations" }
              </Link<AdminRoute>>
              </h3>
              </div>

            </div>
          </div>

        </div>
        </>
        }
    }
}

// TODO: can this come from somewhere else more simply? Probably not, because reasons.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Attributes {
    pub class: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub description: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub displayname: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub name: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub spn: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub uuid: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Entity {
    pub attrs: Attributes,
    #[serde(default)]
    pub object_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GetError {
    pub err: String,
}
