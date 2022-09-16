use crate::components::adminmenu::{Entity, GetError};
use crate::components::alpha_warning_banner;
use crate::constants::CSS_PAGE_HEADER;
use crate::models;
use gloo::console;
use gloo_net::http::{Request, RequestMode};
use std::collections::BTreeMap;
use yew::prelude::*;
use yew::{html, Component, Context, Html, Properties};

impl From<GetError> for AdminListAccountsMsg {
    fn from(ge: GetError) -> Self {
        AdminListAccountsMsg::Failed {
            emsg: ge.err,
            kopid: None,
        }
    }
}

pub struct AdminListAccounts;

#[derive(PartialEq, Properties, Eq)]
pub struct AdminListAccountsProps {
    // for filtering and pagination
    // #[allow(dead_code)]
    // search: Option<String>,
    // #[allow(dead_code)]
    // page: Option<u32>,
    pub accounts: BTreeMap<String, Entity>,
}

/// Pulls all accounts (service or person-class) from the backend and returns a HashMap
/// with the "name" field being the keys, for easy human-facing sortability.
pub async fn get_accounts(token: &str) -> Result<AdminListAccountsMsg, GetError> {
    let mut all_accounts = BTreeMap::new();

    // we iterate over these endpoints
    let endpoints = ["/v1/service_account", "/v1/person"];

    for endpoint in endpoints {
        let request = Request::new(endpoint)
            .mode(RequestMode::SameOrigin)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", token).as_str());
        let response = match request.send().await {
            Ok(value) => value,
            Err(error) => {
                return Err(GetError {
                    err: format!("{:?}", error),
                })
            }
        };
        let data: Vec<Entity> = response.json().await.unwrap();

        for entity in data.iter() {
            let entity_id = match entity.attrs.name.first() {
                Some(value) => format!("{}", value),
                None => entity
                    .attrs
                    .spn
                    .first()
                    .expect(format!("Failed to grab the SPN for {:?}", entity.attrs).as_str())
                    .to_string(),
            };
            all_accounts.insert(format!("{}", entity_id), entity.to_owned());
        }
    }

    Ok(AdminListAccountsMsg::Responded {
        response: all_accounts,
    })
}

pub enum AdminListAccountsMsg {
    Responded { response: BTreeMap<String, Entity> },
    // Loaded { status: String },
    Failed { emsg: String, kopid: Option<String> },
}

impl Component for AdminListAccounts {
    type Message = AdminListAccountsMsg;
    type Properties = AdminListAccountsProps;

    fn create(ctx: &Context<Self>) -> Self {
        // TODO: work out the querystring thing so we can just show x number of elements
        // console::log!("query: {:?}", location().query);
        let token = match models::get_bearer_token() {
            Some(value) => value,
            None => String::from(""),
        };

        // start pulling the account data on startup
        ctx.link().send_future(async move {
            match get_accounts(token.clone().as_str()).await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });
        AdminListAccounts
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <>
              <div class={CSS_PAGE_HEADER}>
                <h2>{ "System Administration" }</h2>
              </div>

              { alpha_warning_banner() }
        <div id={"accountlist"}>
            {"Accounts list goes here!!"}
        </div>
        <div id={"accountlist"}>
        <AccountList accounts={ctx.props().accounts.clone()} />
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
                    console::log!(
                        "response: {:?}",
                        serde_json::to_string(response.get(key).unwrap()).unwrap()
                    );
                }
            }
            AdminListAccountsMsg::Failed { emsg, kopid } => {
                console::log!("emsg: {:?}", emsg);
                console::log!("kopid: {:?}", kopid);
            }
        }
        false
    }
}

#[function_component(AccountList)]
fn videos_list(AdminListAccountsProps { accounts }: &AdminListAccountsProps) -> Html {
    // console::debug!("search: ", format!("{:?}", search));
    // if let Some(pagenum) = page {
    //   console::debug!("page: {:?}", format!("{}", pagenum));
    // }
    accounts
        .keys()
        .map(|key| {
            html! {
              <p>{format!("{:?}", accounts.get(key).unwrap().attrs.displayname)}</p>
            }
        })
        .collect()
    // videos.iter().map(|video| html! {
    //     <p>{format!("{}: {}", video.speaker, video.title)}</p>
    // }).collect()
}
