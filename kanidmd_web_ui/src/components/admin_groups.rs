use std::collections::BTreeMap;

use gloo::console;
use yew::{html, Component, Context, Html, Properties};
use yew_router::prelude::Link;

use crate::components::adminmenu::{Entity, EntityType, GetError};
use crate::components::alpha_warning_banner;
use crate::constants::{CSS_BREADCRUMB_ITEM, CSS_BREADCRUMB_ITEM_ACTIVE, CSS_CELL, CSS_TABLE};
use crate::models;
use crate::utils::{do_alert_error, do_page_header, init_request};
use crate::views::AdminRoute;

impl From<GetError> for AdminListGroupsMsg {
    fn from(ge: GetError) -> Self {
        AdminListGroupsMsg::Failed {
            emsg: ge.err,
            kopid: None,
        }
    }
}

pub struct AdminListGroups {
    state: GroupsViewState,
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

enum GroupsViewState {
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
    let endpoints = [("/v1/group", EntityType::Group)];

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
            new_entity.object_type = object_type.clone();

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
            state: GroupsViewState::Loading,
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <>
              {do_page_header("Group Administration")}

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
                self.state = GroupsViewState::Responded { response };
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
            GroupsViewState::Loading => {
                html! {"Waiting on the groups list to load..."}
            }

            GroupsViewState::Responded { response } => {
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
                          <tr key={uuid.clone()}>
                          <td class={CSS_CELL} scope={scope_col}>
                          <Link<AdminRoute> to={AdminRoute::ViewGroup{uuid:{uuid.clone()}}} >{name}</Link<AdminRoute>></td>
                          <td class={CSS_CELL}>{description}</td>
                          </tr>
                        }
                    }).collect::<Html>()
                  }
                  </table>
                )
            }

            GroupsViewState::Failed { emsg, kopid } => {
                console::error!("Failed to pull details", format!("{:?}", kopid));
                html!(
                    <>
                    {do_alert_error("Failed to Query Groups", Some(emsg))}
                    </>
                )
            }
            GroupsViewState::NotAuthorized {} => {
                do_alert_error("You're not authorized to see this page!", None)
            }
        }
    }
}

#[derive(Properties, PartialEq, Eq, Clone)]
pub struct AdminViewGroupProps {
    pub uuid: String,
}

// callback messaging for group detail view
pub enum AdminViewGroupMsg {
    /// When the server responds and we need to update the page
    Responded { response: Entity },
    #[allow(dead_code)]
    Failed { emsg: String, kopid: Option<String> },
    #[allow(dead_code)]
    NotAuthorized {},
}

impl From<GetError> for AdminViewGroupMsg {
    fn from(ge: GetError) -> Self {
        AdminViewGroupMsg::Failed {
            emsg: ge.err,
            kopid: None,
        }
    }
}

enum GroupViewState {
    /// waiting for the page to load
    Loading,
    /// server has responded
    Responded { response: Entity },
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

pub struct AdminViewGroup {
    state: GroupViewState,
}

impl Component for AdminViewGroup {
    type Message = AdminViewGroupMsg;

    type Properties = AdminViewGroupProps;

    fn create(ctx: &Context<Self>) -> Self {
        let token = match models::get_bearer_token() {
            Some(value) => value,
            None => String::from(""),
        };
        let uuid = ctx.props().uuid.clone();
        // TODO: start pulling the group details then send the msg blep blep
        ctx.link().send_future(async move {
            match get_group(token.clone().as_str(), &uuid).await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });

        AdminViewGroup {
            state: GroupViewState::Loading,
        }
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        match &self.state {
            GroupViewState::Loading => html! {"Loading..."},
            GroupViewState::Responded { response } => {
                let group_name = match response.attrs.name.first() {
                    Some(value) => value.as_str(),
                    None => {
                        // TODO: this should throw an error
                        "No Group Name?"
                    }
                };
                let page_title = format!("Group: {}", group_name);

                let group_uuid = match response.attrs.uuid.first() {
                    Some(value) => value.clone(),
                    None => String::from("Error querying UUID!"),
                };
                html! {
                    <>
                    <ol class="breadcrumb">
                    <li class={CSS_BREADCRUMB_ITEM}><Link<AdminRoute> to={AdminRoute::AdminMenu}>{"Admin"}</Link<AdminRoute>></li>
                    <li class={CSS_BREADCRUMB_ITEM}><Link<AdminRoute> to={AdminRoute::AdminListGroups}>{"Groups"}</Link<AdminRoute>></li>
                    <li class={CSS_BREADCRUMB_ITEM_ACTIVE} aria-current="page">{group_name}</li>
                    </ol>
                    {do_page_header(&page_title)}
                    <p>{"UUID: "}{group_uuid}</p>
                    // TODO: pull group membership and show members
                    <p>{"Group Membership will show up here soon..."}</p>
                    </>
                }
            }
            GroupViewState::Failed { emsg, kopid } => do_alert_error(
                emsg,
                Some(
                    kopid
                        .as_ref()
                        .unwrap_or(&String::from("unknown operation ID")),
                ),
            ),
            GroupViewState::NotAuthorized {} => {
                do_alert_error("You are not authorized to view this page!", None)
            }
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            AdminViewGroupMsg::Responded { response } => {
                self.state = GroupViewState::Responded { response };
                true
            }
            AdminViewGroupMsg::Failed { emsg, kopid } => {
                self.state = GroupViewState::Failed { emsg, kopid };
                true
            }
            AdminViewGroupMsg::NotAuthorized {} => {
                self.state = GroupViewState::NotAuthorized {};
                true
            }
        }
    }
}

/// pull the details for a single group by UUID
pub async fn get_group(token: &str, groupid: &str) -> Result<AdminViewGroupMsg, GetError> {
    let request = init_request(format!("/v1/group/{}", groupid).as_str(), token);
    let response = match request.send().await {
        Ok(value) => value,
        Err(error) => {
            return Err(GetError {
                err: format!("{:?}", error),
            })
        }
    };
    #[allow(clippy::panic)]
    let data: Entity = match response.json().await {
        Ok(value) => value,
        Err(error) => panic!("Failed to grab the group data into JSON: {:?}", error),
    };
    Ok(AdminViewGroupMsg::Responded { response: data })
}
