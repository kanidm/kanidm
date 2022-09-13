use crate::views::AdminRoute;

use yew::{Component, Context, html, Html, Properties};
use yew_router::prelude::Link;

#[derive(PartialEq, Properties)]
pub struct Props;

#[derive(PartialEq, Properties)]
pub struct ListProps {
  #[allow(dead_code)]
  search: Option<String>,
  #[allow(dead_code)]
  page: Option<u32>,
}

pub struct AdminMenu;

impl Component for AdminMenu {
    type Message = ();
    type Properties = Props;

    fn create(_ctx: &Context<Self>) -> Self {
        AdminMenu
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        let link_class = "link-dark stretched-link";
        html! {
            <>
              <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                <h2>{ "System Administration" }</h2>
              </div>
              <div class="alert alert-warning" role="alert">
                { "🦀 Kanidm is still in early Alpha, this interface is a placeholder! " }
                </div>
        <div class="row row-cols-1 row-cols-sm-2 row-cols-md-3 g-3">
          <div class="col">
            <div class="card text-center">
            <Link<AdminRoute> classes={link_class} to={AdminRoute::AdminListAccounts}>
            <img src={"/pkg/img/icon-accounts.svg"} />
            </Link<AdminRoute>>
              <div class="card-body text-center">
              <h3>
              <Link<AdminRoute> classes={link_class} to={AdminRoute::AdminListAccounts}>
              { "Accounts" }
              </Link<AdminRoute>>
              </h3>
              </div>

            </div>
          </div>

          // card for groups
          <div class="col">
            <div class="card text-center">
            <Link<AdminRoute> classes={link_class} to={AdminRoute::AdminListGroups}>
            <img src={"/pkg/img/icon-groups.svg"} />
            </Link<AdminRoute>>
              <div class="card-body text-center">
              <h3>
              <Link<AdminRoute> classes={link_class} to={AdminRoute::AdminListGroups}>
              { "Groups" }
              </Link<AdminRoute>>
              </h3>
              </div>

            </div>
          </div>

          // card for oauth
          <div class="col">
            <div class="card text-center">
            <Link<AdminRoute> classes={link_class} to={AdminRoute::AdminListOAuth}>
            <img src={"/pkg/img/icon-oauth2.svg"} />
            </Link<AdminRoute>>
              <div class="card-body text-center">
              <h3>
              <Link<AdminRoute> classes={link_class} to={AdminRoute::AdminListOAuth}>
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

pub struct AdminListAccounts;

impl Component for AdminListAccounts {
    type Message = ();
    type Properties = ListProps;

    fn create(_ctx: &Context<Self>) -> Self {
        AdminListAccounts
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {

        html! {
            <>
              <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                <h2>{ "System Administration" }</h2>
              </div>
              <div class="alert alert-warning" role="alert">
                { "🦀 Kanidm is still in early Alpha, this interface is a placeholder! " }
                </div>
        <div>
            {"Accounts list goes here!!"}
        </div>
        // TODO: grab this and list it /v1/service_account
        </>
        }
    }
}

pub struct AdminListGroups;

impl Component for AdminListGroups {
    type Message = ();
    type Properties = ListProps;

    fn create(_ctx: &Context<Self>) -> Self {
        AdminListGroups
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {

        html! {
            <>
              <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                <h2>{ "System Administration" }</h2>
              </div>
              <div class="alert alert-warning" role="alert">
                { "🦀 Kanidm is still in early Alpha, this interface is a placeholder! " }
                </div>
        <div>
            {"Groups!"}
        </div>
        // TODO: pull the list from /v1/groups
        </>
        }
    }
}

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
              <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                <h2>{ "System Administration" }</h2>
              </div>
              <div class="alert alert-warning" role="alert">
                { "🦀 Kanidm is still in early Alpha, this interface is a placeholder! " }
                </div>
        <div>
            {"OAuth Configs go here!"}
        </div>
        // TODO: pull the list from /v1/oauth2
        </>
        }
    }
}
