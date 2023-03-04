use std::collections::BTreeMap;

use gloo::console;
use yew::{html, Component, Context, Html, Properties};
use yew_router::prelude::Link;

use crate::components::admin_menu::{Entity, EntityType, GetError};
use crate::components::alpha_warning_banner;
use crate::constants::{
    CSS_BREADCRUMB_ITEM, CSS_BREADCRUMB_ITEM_ACTIVE, CSS_CELL, CSS_DT, CSS_TABLE,
};
use crate::utils::{do_alert_error, do_page_header, init_request};
use crate::views::AdminRoute;

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

enum ViewAccountState {
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
pub async fn get_accounts() -> Result<AdminListAccountsMsg, GetError> {
    // TODO: the actual pulling and turning into a BTreeMap in this and get_groups could *probably* be rolled up into one function? The result object differs but all the widgets are the same.
    let mut all_accounts = BTreeMap::new();

    // we iterate over these endpoints
    let endpoints = [
        ("/v1/service_account", EntityType::ServiceAccount),
        ("/v1/person", EntityType::Person),
    ];

    for (endpoint, object_type) in endpoints {
        let request = init_request(endpoint);
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

            // TODO: this kind of thing comes back when you're logged out:  SerdeError(Error("invalid type: string \"sessionexpired\", expected a sequence", line: 1, column: 16))', server/web_ui/src/components/admin_accounts.rs:107:27
            Err(error) => {
                return Err(GetError {
                    err: format!("Failed to grab the account data into JSON: {:?}", error),
                })
            }
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

        // start pulling the account data on startup
        ctx.link().send_future(async move {
            match get_accounts().await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });
        AdminListAccounts {
            state: ViewState::Loading,
        }
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <>

            <ol class="breadcrumb">
            <li class={CSS_BREADCRUMB_ITEM}><Link<AdminRoute> to={AdminRoute::AdminMenu}>{"Admin"}</Link<AdminRoute>></li>
            <li class={CSS_BREADCRUMB_ITEM_ACTIVE} aria-current="page">{"Accounts"}</li>
            </ol>
            {do_page_header("Account Administration")}
            { alpha_warning_banner() }
        <div id={"accountlist"}>
        {match &self.state {
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
                        let account_type: Html = match account.object_type {
                            EntityType::ServiceAccount => html!{<img src={"/pkg/img/icon-robot.svg"}  alt={"Service Account"} class={"p-0"} />},
                            EntityType::Person => html!{<img src={"/pkg/img/icon-person.svg"} alt={"Person"} class={"p-0"} />},
                            _ => html!("x"),
                        };


                        let uuid: String = match account.attrs.uuid.first() {
                            Some(value) => value.to_string(),
                            None => {
                                console::error!("Account without a UUID?", format!("{:?}", account).to_string());
                                String::from("Unknown UUID!")
                            }
                        };

                        let object_link = match account.object_type {
                            EntityType::Person => AdminRoute::ViewPerson{uuid:uuid.clone()},
                            EntityType::ServiceAccount => AdminRoute::ViewServiceAccount{uuid:uuid.clone()},
                            // because matching is hard
                            _ => AdminRoute::ViewPerson{uuid:uuid.clone()},
                        };

                        html!{
                          <tr key={uuid}>
                          <td class={CSS_CELL}>{account_type}</td>
                          <th scope={scope_col} class={CSS_CELL}>
                            <Link<AdminRoute> to={object_link} >
                            {display_name}
                            </Link<AdminRoute>>
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
        }}
        </div>
        </>
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            AdminListAccountsMsg::Responded { response } => {
                // TODO: do we paginate here?
                /*
                // Seems broken
                #[cfg(debug_assertions)]
                for key in response.keys() {
                    #[allow(clippy::unwrap_used)]
                    console::log!(
                        "response: {:?}",
                        serde_json::to_string(response.get(key).unwrap()).unwrap()
                    );
                }
                */
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

// impl AdminListAccounts {
//     /// output the information based on what's in the current state
//     fn view_state(&self, _ctx: &Context<Self>) -> Html {

//     }
// }

impl From<GetError> for AdminViewPersonMsg {
    fn from(ge: GetError) -> Self {
        AdminViewPersonMsg::Failed {
            emsg: ge.err,
            kopid: None,
        }
    }
}

pub struct AdminViewPerson {
    #[allow(dead_code)]
    state: ViewAccountState,
}

#[derive(Properties, PartialEq, Eq, Clone)]
/// Properties for accounts, either Person or Service Account
pub struct AdminViewAccountProps {
    pub uuid: String,
}

// callback messaging for this confused pile of crab-bait
pub enum AdminViewPersonMsg {
    /// When the server responds and we need to update the page
    Responded { response: Entity },
    #[allow(dead_code)]
    Failed { emsg: String, kopid: Option<String> },
}

impl Component for AdminViewPerson {
    type Message = AdminViewPersonMsg;
    type Properties = AdminViewAccountProps;

    fn create(ctx: &Context<Self>) -> Self {
        let uuid = ctx.props().uuid.clone();
        ctx.link().send_future(async move {
            match get_person(&uuid).await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });
        AdminViewPerson {
            state: ViewAccountState::Loading,
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            AdminViewPersonMsg::Responded { response } => {
                self.state = ViewAccountState::Responded { response }
            }
            AdminViewPersonMsg::Failed { emsg, kopid } => {
                self.state = ViewAccountState::Failed { emsg, kopid }
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.state {
            ViewAccountState::Loading => html! {{"Loading..."}},
            ViewAccountState::Failed { emsg, kopid } => do_alert_error(
                emsg.clone().as_str(),
                Some(&format!("Operation ID: {:?}", kopid)),
            ),
            // TODO: the not authorized page needs to be better
            ViewAccountState::NotAuthorized {} => {
                html! {{"You are not authorized to view this page!"}}
            }
            ViewAccountState::Responded { response } => {
                // TODO: This is pretty lacking in detail, even logged in as the idm_admin user, so will have to work out how to pull all the details
                let username = match response.attrs.name.first() {
                    Some(value) => value.to_owned(),
                    None => String::from("Unable to query username"),
                };
                let display_name = match response.attrs.displayname.first() {
                    Some(value) => value.to_string(),
                    None => String::from("Display Name Unset"),
                };
                // let user_groups = userinfo.youare.attrs.get("memberof");

                // let mail_primary = match userinfo.uat.mail_primary.as_ref() {
                //     Some(email_address) => {
                //         html! {
                //             <a href={ format!("mailto:{}", &email_address)}>
                //             {email_address}
                //             </a>
                //         }
                //     }
                //     None => html! { {"<primary email is unset>"}},
                // };
                html! {
                    <>
                    <ol class="breadcrumb">
                        <li class={CSS_BREADCRUMB_ITEM}><Link<AdminRoute> to={AdminRoute::AdminMenu}>{"Admin"}</Link<AdminRoute>></li>
                        <li class={CSS_BREADCRUMB_ITEM}><Link<AdminRoute> to={AdminRoute::AdminListAccounts}>{"Accounts"}</Link<AdminRoute>></li>
                        <li class={CSS_BREADCRUMB_ITEM_ACTIVE} aria-current="page">{username.as_str()}</li>
                    </ol>
                    {do_page_header(display_name.as_str())}
                    {alpha_warning_banner()}

                    // <dt class={CSS_DT}>{ "Display Name" }</dt>
                    // <dl class="row">
                    // <dd class="col">{  }</dd>

                //         <dt class={CSS_DT}>{ "Primary Email" }</dt>
                //         <dd class="col">{mail_primary}</dd>

                //         <dt class={CSS_DT}>{ "Group Memberships" }</dt>
                //         <dd class="col">
                //             <ul class="list-group">
                //             {
                //             match user_groups {
                //                 Some(grouplist) => html!{
                //                     {
                //                         for grouplist.iter()
                //                             .map(|group|
                //                     {
                //                         html!{ <li>{
                //                             #[allow(clippy::unwrap_used)]
                //                             group.split('@').next().unwrap().to_string()
                //                         }</li> }

                //                     })
                //                 }
                //                 },
                //                 None => html!{
                //                     <li>{"Not a member of any groups"}</li>
                //                     }
                //                 }
                //             }
                //             </ul>
                //         </dd>


                //     <dt class={CSS_DT}>
                //     { "User's SPN" }
                //     </dt>
                //       <dd class="col">
                //       { username.to_string() }{"@"}{ domain }
                //       </dd>

                    <dt class={CSS_DT}>{ "Username" }</dt>
                    <dd class="col">{ username }</dd>

                    <dt class={CSS_DT}>{ "User's UUID" }</dt>
                    <dd class="col">{ ctx.props().to_owned().uuid }</dd>

                // </dl>
                </>
                }
            }
        }
    }
}

impl From<GetError> for AdminViewServiceAccountMsg {
    fn from(ge: GetError) -> Self {
        AdminViewServiceAccountMsg::Failed {
            emsg: ge.err,
            kopid: None,
        }
    }
}

pub struct AdminViewServiceAccount {
    #[allow(dead_code)]
    state: ViewAccountState,
}

// callback messaging for this confused pile of crab-bait
pub enum AdminViewServiceAccountMsg {
    /// When the server responds and we need to update the page
    Responded { response: Entity },
    #[allow(dead_code)]
    Failed { emsg: String, kopid: Option<String> },
}

impl Component for AdminViewServiceAccount {
    type Message = AdminViewServiceAccountMsg;
    type Properties = AdminViewAccountProps;

    fn create(ctx: &Context<Self>) -> Self {
        let uuid = ctx.props().uuid.clone();
        ctx.link().send_future(async move {
            match get_service_account(&uuid).await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });
        AdminViewServiceAccount {
            state: ViewAccountState::Loading,
        }
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        match &self.state {
            ViewAccountState::Loading => html! {{"Loading..."}},
            ViewAccountState::Responded { response } => {
                let account = &response.attrs;
                let username = match account.name.first() {
                    Some(value) => value.as_str(),
                    None => "Unable to pull username",
                };
                let displayname = match account.displayname.first() {
                    Some(value) => value.as_str(),
                    None => "Unable to pull displayname",
                };

                let description = match account.description.first() {
                    Some(value) => html! {<p>{"Description: "}{value.as_str()}</p>},
                    None => html! {},
                };

                html! {
                <>
                <ol class="breadcrumb">
                    <li class={CSS_BREADCRUMB_ITEM}><Link<AdminRoute> to={AdminRoute::AdminMenu}>{"Admin"}</Link<AdminRoute>></li>
                    <li class={CSS_BREADCRUMB_ITEM}><Link<AdminRoute> to={AdminRoute::AdminListAccounts}>{"Accounts"}</Link<AdminRoute>></li>
                    <li class={CSS_BREADCRUMB_ITEM_ACTIVE} aria-current="page">{username}</li>
                </ol>
                {do_page_header(&format!("Service Account: {}", username))}
                {alpha_warning_banner()}
                <p>{"Display Name: "}{displayname}</p>
                {description}
                </>
                }
            }
            ViewAccountState::Failed { emsg, kopid } => html! {
                do_alert_error(emsg.as_str(), Some(&format!("Operation ID: {:?}", kopid)))
            },
            // TODO: this error needs fixing
            ViewAccountState::NotAuthorized {} => {
                html! {{"You're not authorized to view this page!"}}
            }
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            AdminViewServiceAccountMsg::Responded { response } => {
                self.state = ViewAccountState::Responded { response }
            }
            AdminViewServiceAccountMsg::Failed { emsg, kopid } => {
                self.state = ViewAccountState::Failed { emsg, kopid }
            }
        }
        true
    }
}

/// pull the details for a single person by UUID
pub async fn get_person(uuid: &str) -> Result<AdminViewPersonMsg, GetError> {
    let request = init_request(format!("/v1/person/{}", uuid).as_str());
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
        Err(error) => panic!("Failed to grab the person data into JSON: {:?}", error),
    };
    Ok(AdminViewPersonMsg::Responded { response: data })
}

/// pull the details for a single service_account by UUID
pub async fn get_service_account(uuid: &str) -> Result<AdminViewServiceAccountMsg, GetError> {
    let request = init_request(format!("/v1/service_account/{}", uuid).as_str());
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
        Err(error) => panic!(
            "Failed to grab the service account data into JSON: {:?}",
            error
        ),
    };
    Ok(AdminViewServiceAccountMsg::Responded { response: data })
}
