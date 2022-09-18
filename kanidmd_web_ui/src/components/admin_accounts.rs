use crate::components::adminmenu::{Entity, GetError};
use crate::components::alpha_warning_banner;
use crate::constants::{CSS_CELL, CSS_PAGE_HEADER, CSS_TABLE};
use crate::models;
use crate::utils::{do_alert_error, init_request};
use gloo::console;
use std::collections::BTreeMap;
// use yew::prelude::*;
use yew::{html, Component, Context, Html, Properties};

impl From<GetError> for AdminListAccountsMsg {
    fn from(ge: GetError) -> Self {
        AdminListAccountsMsg::Failed {
            emsg: ge.err,
            kopid: None,
        }
    }
}

pub struct AdminListAccounts {
    state: ViewState,
}

// callback messaging for this confused pile of crab-bait
pub enum AdminListAccountsMsg {
    /// When the server responds and we need to update the page
    Responded {
        response: BTreeMap<String, Entity>,
    },
    Failed {
        emsg: String,
        kopid: Option<String>,
    },
}

enum ViewState {
    /// waiting for the page to load
    Loading,
    /// server has responded
    Responded { response: BTreeMap<String, Entity> },
    /// failed to pull the details
    #[allow(dead_code)]
    Failed {
        // TODO: use this
        emsg: String,
        kopid: Option<String>,
    },
    #[allow(dead_code)]
    /// Not authorized to pull the details
    NotAuthorized {}, // TODO: use this
}

#[derive(PartialEq, Properties, Eq)]
pub struct AdminListAccountsProps {
    // for filtering and pagination
    // #[allow(dead_code)]
    // search: Option<String>,
    // #[allow(dead_code)]
    // page: Option<u32>,
}

/// Pulls all accounts (service or person-class) from the backend and returns a HashMap
/// with the "name" field being the keys, for easy human-facing sortability.
pub async fn get_accounts(token: &str) -> Result<AdminListAccountsMsg, GetError> {
    // TODO: the actual pulling and turning into a BTreeMap in this and get_groups could *probably* be rolled up into one function? The result object differs but all the widgets are the same.
    let mut all_accounts = BTreeMap::new();

    // we iterate over these endpoints
    let endpoints = [
        ("/v1/service_account", "service_account"),
        ("/v1/person", "person"),
    ];

    for (endpoint, object_type) in endpoints {
        let request = init_request(endpoint, token);
        let response = match request.send().await {
            Ok(value) => value,
            Err(error) => {
                return Err(GetError {
                    err: format!("{:?}", error),
                })
            }
        };
        #[allow(clippy::panic)]
        let data: Vec<Entity> = match response.json().await {
            Ok(value) => value,
            Err(error) => panic!("Failed to grab the account data into JSON: {:?}", error),
        };

        for entity in data.iter() {
            let mut new_entity = entity.to_owned();
            new_entity.object_type = Some(object_type.to_string());

            // first we try the short name and, if that isn't there then just use the SPN...
            #[allow(clippy::expect_used)]
            let entity_id = match entity.attrs.name.first() {
                Some(value) => value.to_string(),
                None => entity
                    .attrs
                    .spn
                    .first()
                    .expect("Failed to grab the SPN for an account.")
                    .to_string(),
            };
            all_accounts.insert(entity_id.to_string(), new_entity);
        }
    }

    Ok(AdminListAccountsMsg::Responded {
        response: all_accounts,
    })
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
        AdminListAccounts {
            state: ViewState::Loading,
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <>
              <div class={CSS_PAGE_HEADER}>
                <h2>{ "System Administration" }</h2>
              </div>

              { alpha_warning_banner() }
        <div id={"accountlist"}>
        {self.view_state(ctx)}
        </div>
        </>
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            AdminListAccountsMsg::Responded { response } => {
                // TODO: do we paginate here?
                #[cfg(debug)]
                for key in response.keys() {
                    #[allow(clippy::unwrap_used)]
                    console::log!(
                        "response: {:?}",
                        serde_json::to_string(response.get(key).unwrap()).unwrap()
                    );
                }
                self.state = ViewState::Responded { response };
                return true;
            }
            AdminListAccountsMsg::Failed { emsg, kopid } => {
                console::log!("emsg: {:?}", emsg);
                console::log!("kopid: {:?}", kopid);
            }
        }
        false
    }
}

impl AdminListAccounts {
    /// output the information based on what's in the current state
    fn view_state(&self, _ctx: &Context<Self>) -> Html {
        match &self.state {
            ViewState::Loading => {
                html! {"Waiting on the accounts list to load..."}
            }

            ViewState::Responded { response } => {
                let scope_col = "col";

                html!(
                  <table class={CSS_TABLE}>
                  <thead>
                    <tr>
                      <th scope={scope_col}></th>
                      <th scope={scope_col}>{"Display Name"}</th>
                      <th scope={scope_col}>{"Username"}</th>
                      <th scope={scope_col}>{"Description"}</th>
                    </tr>
                  </thead>

                  {
                    response.keys().map(|name| {
                        #[allow(clippy::expect_used)]
                      let account: &Entity = response.get(name).expect("Couldn't get account key when it was just in the iter...");

                        let display_name: String = match account.attrs.displayname.first() {
                          Some(value) => value.to_string(),
                          None => String::from(""),
                        };

                        let description: String = match account.attrs.description.first() {
                          Some(value) => value.to_string(),
                          None => String::from(""),
                        };
                        let account_type: Html = match &account.object_type {
                            Some(value) => match value.as_str() {
                                // TODO: make these into tiny images
                                "service_account" => html!{<img src={"/pkg/img/icon-robot.svg"}  alt={"Service Account"} class={"p-0"} />},
                                "person" => html!{<img src={"/pkg/img/icon-person.svg"} alt={"Person"} class={"p-0"} />},
                                &_ => html!("x"),
                            },
                            None => html!{"x"},
                        };


                        let uuid: String = match account.attrs.uuid.first() {
                            Some(value) => value.to_string(),
                            None => {
                                console::error!("Account without a UUID?", format!("{:?}", account).to_string());
                                String::from("Unknown UUID!")
                            }
                        };

                        html!{
                          <tr key={uuid}>
                          <td class={CSS_CELL}>{account_type}</td>
                          <th scope={scope_col} class={CSS_CELL}>
                          // <Link<AdminRoute> classes={CSS_LINK_DARK_STRETCHED} to={AdminRoute::AdminViewAccount uuid}>
                          {display_name}
                        //   </Link<AdminRoute>>
                          </th>
                          <td class={CSS_CELL}>{name}</td>
                          <td class={CSS_CELL}>{description}</td>
                          </tr>
                        }
                    }).collect::<Html>()
                  }
                  </table>
                )
            }
            ViewState::Failed { emsg, kopid } => {
                console::error!("Failed to pull details", format!("{:?}", kopid));
                html!(
                    <>
                    {do_alert_error("Failed to Query Accounts", Some(emsg))}
                    </>
                )
            }
            ViewState::NotAuthorized {} => {
                do_alert_error("You're not authorized to see this page!", None)
            }
        }
    }
}
