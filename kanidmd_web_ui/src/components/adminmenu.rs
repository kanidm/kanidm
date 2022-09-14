use crate::components::alpha_warning_banner;
use crate::constants::CSS_PAGE_HEADER;
use crate::error::FetchError;
use crate::models;
use crate::views::AdminRoute;
use gloo_net::http::{Request, RequestMode};
use gloo::console;
use serde::{Deserialize,Serialize};
use std::collections::BTreeMap;
use yew_router::prelude::Link;
use yew::{Component, Context, html, Html, Properties};


const CSS_LINK_DARK_STRETCHED: &str = "link-dark stretched-link";
const CSS_CARD: &str = "card text-center";
const CSS_CARD_BODY: &str = "card-body text-center";


impl From<FetchError> for AdminListAccountsMsg {
  fn from(fe: FetchError) -> Self {
    AdminListAccountsMsg::Failed {
          emsg: fe.as_string(),
          kopid: None,
      }
  }
}


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

pub struct AdminListAccounts ;

pub enum AdminListAccountsMsg {
  Responded { response: BTreeMap<String, Entity> },
  // Loaded { status: String },
  Failed { emsg: String, kopid: Option<String> },
}

impl Component for AdminListAccounts {
    type Message = AdminListAccountsMsg;
    type Properties = ListProps;

    fn create(ctx: &Context<Self>) -> Self {
      // TODO: work out the querystring thing so we can just show x number of elements
      // console::log!("query: {:?}", location().query);
      let token = match models::get_bearer_token() {
          Some(value) => value,
          None => String::from(""),
      };

      ctx.link().send_future(async move {
          match get_accounts(token.clone().as_str(), "/v1/service_account").await {
              Ok(v) => v,
              Err(v) => v.into(),
            }
          });
      // let response_data = response.status;
      // console::log!(response_data)
      AdminListAccounts
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {

        html! {
            <>
              <div class={CSS_PAGE_HEADER}>
                <h2>{ "System Administration" }</h2>
              </div>

              { alpha_warning_banner() }
        <div id={"accountlist"}>
            {"Accounts list goes here!!"}
        </div>
        </>
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
      match msg {
        AdminListAccountsMsg::Responded { response } => {
          // this is where we update the list of accounts

          // TODO: paginate this
          for key in response.keys() {
                console::log!("response: {:?}", serde_json::to_string(response.get(key).unwrap()).unwrap() );

            }
        },
        AdminListAccountsMsg::Failed { emsg, kopid } => {
          console::log!("emsg: {:?}", emsg);
          console::log!("kopid: {:?}", kopid );
        },
      }
        false
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
              <div class={CSS_PAGE_HEADER}>
                <h2>{ "System Administration" }</h2>
              </div>

              { alpha_warning_banner() }
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

// impl AdminListAccounts {

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Attributes {
  class: Vec<String>,
  #[serde(skip_serializing_if = "Vec::is_empty", default)]
  description: Vec<String>,
  #[serde(skip_serializing_if = "Vec::is_empty", default)]
  displayname: Vec<String>,
  #[serde(skip_serializing_if = "Vec::is_empty", default)]
  name: Vec<String>,
  #[serde(skip_serializing_if = "Vec::is_empty", default)]
  spn: Vec<String>,
  #[serde(skip_serializing_if = "Vec::is_empty", default)]
  uuid: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
  pub struct Entity {
  pub attrs: Attributes
}

pub async fn get_accounts(token: &str, url: &str) -> Result<AdminListAccountsMsg, FetchError> {
    let request = Request::new(url)
      .mode(RequestMode::SameOrigin)
      .header("content-type", "application/json")
      .header("authorization", format!("Bearer {}", token).as_str());
    let response = match request.send().await {
      Ok(value) => value,
      Err(error) => panic!("{:?}", error)
    };
    let data: Vec<Entity> = response.json().await.unwrap();

    let mut mapped_data = BTreeMap::new();
    for entity in data.iter() {
      if let Some(name) = entity.attrs.displayname.first() {
        mapped_data.insert(
          format!("{}", name.as_str()),
          entity.to_owned()
        );
      }
    }

    Ok(AdminListAccountsMsg::Responded { response: mapped_data })
}
