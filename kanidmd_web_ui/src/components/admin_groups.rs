use crate::components::adminmenu::{Entity, GetError};
use crate::components::alpha_warning_banner;
use crate::constants::{CSS_CELL, CSS_PAGE_HEADER, CSS_TABLE};
use crate::models;
use crate::utils::{do_alert_error, init_request};
use gloo::console;
use std::collections::BTreeMap;
use yew::{html, Component, Context, Html, Properties};

impl From<GetError> for AdminListGroupsMsg {
    fn from(ge: GetError) -> Self {
        AdminListGroupsMsg::Failed {
            emsg: ge.err,
            kopid: None,
        }
    }
}

pub struct AdminListGroups {
    state: ViewState,
}

// callback messaging for this confused pile of crab-bait
pub enum AdminListGroupsMsg {
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
pub struct AdminListGroupsProps {
    // for filtering and pagination
    // #[allow(dead_code)]
    // search: Option<String>,
    // #[allow(dead_code)]
    // page: Option<u32>,
}

/// Pulls all accounts (service or person-class) from the backend and returns a HashMap
/// with the "name" field being the keys, for easy human-facing sortability.
pub async fn get_groups(token: &str) -> Result<AdminListGroupsMsg, GetError> {
    let mut all_groups = BTreeMap::new();

    // we iterate over these endpoints
    let endpoints = [("/v1/group", "group")];

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
            Err(error) => panic!("Failed to grab the group data into JSON: {:?}", error),
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
                    .expect("Failed to grab the SPN for a group.")
                    .to_string(),
            };
            all_groups.insert(entity_id.to_string(), new_entity);
        }
    }

    Ok(AdminListGroupsMsg::Responded {
        response: all_groups,
    })
}

impl Component for AdminListGroups {
    type Message = AdminListGroupsMsg;
    type Properties = AdminListGroupsProps;

    fn create(ctx: &Context<Self>) -> Self {
        // TODO: work out the querystring thing so we can just show x number of elements
        // console::log!("query: {:?}", location().query);
        let token = match models::get_bearer_token() {
            Some(value) => value,
            None => String::from(""),
        };

        // start pulling the account data on startup
        ctx.link().send_future(async move {
            match get_groups(token.clone().as_str()).await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });
        AdminListGroups {
            state: ViewState::Loading,
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <>
              <div class={CSS_PAGE_HEADER}>
                <h2>{ "Group Administration" }</h2>
              </div>

              { alpha_warning_banner() }
        <div id={"grouplist"}>
        {self.view_state(ctx)}
        </div>
        </>
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            AdminListGroupsMsg::Responded { response } => {
                // TODO: do we paginate here?
                #[cfg(test)]
                for key in response.keys() {
                    console::debug!(
                        "response: {:?}",
                        serde_json::to_string(response.get(key).unwrap()).unwrap()
                    );
                }
                self.state = ViewState::Responded { response };
                return true;
            }
            AdminListGroupsMsg::Failed { emsg, kopid } => {
                // TODO: make this push a view state
                console::log!("emsg: {:?}", emsg);
                console::log!("kopid: {:?}", kopid);
            }
        }
        false
    }
}

impl AdminListGroups {
    /// output the information based on what's in the current state
    fn view_state(&self, _ctx: &Context<Self>) -> Html {
        match &self.state {
            ViewState::Loading => {
                html! {"Waiting on the groups list to load..."}
            }

            ViewState::Responded { response } => {
                let scope_col = "col";

                html!(
                  <table class={CSS_TABLE}>
                  <thead>
                    <tr>
                      <th scope={scope_col}>{"Name"}</th>
                      <th scope={scope_col}>{"Description"}</th>
                    </tr>
                  </thead>

                  {
                    response.keys().map(|name| {
                        #[allow(clippy::expect_used)]
                      let group: &Entity = response.get(name).expect("Couldn't get group key when it was just in the iter...");

                        let description: String = match group.attrs.description.first() {
                          Some(value) => value.to_string(),
                          None => String::from(""),
                        };
                        let uuid: String = match group.attrs.uuid.first() {
                            Some(value) => value.to_string(),
                            None => {
                                console::error!("Group without a UUID?", format!("{:?}", group).to_string());
                                String::from("GROUP WITHOUT A UUID!")
                            }
                        };

                        html!{
                          <tr key={uuid}>
                          <td class={CSS_CELL} scope={scope_col}>{name}</td>
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
                    {do_alert_error("Failed to Query Groups", Some(emsg))}
                    </>
                )
            }
            ViewState::NotAuthorized {} => {
                do_alert_error("You're not authorized to see this page!", None)
            }
        }
    }
}
