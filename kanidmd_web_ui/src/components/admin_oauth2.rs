use crate::components::adminmenu::{Entity, EntityType, GetError};
use crate::components::alpha_warning_banner;
use crate::constants::{CSS_BREADCRUMB_ITEM, CSS_BREADCRUMB_ITEM_ACTIVE};
use crate::constants::{CSS_CELL, CSS_TABLE};
use crate::models;
use crate::utils::{do_alert_error, do_page_header, init_request};
use crate::views::AdminRoute;
use gloo::console;
use std::collections::BTreeMap;
use yew::{html, Component, Context, Html, Properties};
use yew_router::prelude::Link;

impl From<GetError> for AdminListOAuth2Msg {
    fn from(ge: GetError) -> Self {
        AdminListOAuth2Msg::Failed {
            emsg: ge.err,
            kopid: None,
        }
    }
}

pub struct AdminListOAuth2 {
    state: ListViewState,
}

// callback messaging for this confused pile of crab-bait
pub enum AdminListOAuth2Msg {
    /// When the server responds and we need to update the page
    Responded {
        response: BTreeMap<String, Entity>,
    },
    Failed {
        emsg: String,
        kopid: Option<String>,
    },
}

enum ListViewState {
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
pub struct AdminListOAuth2Props {
    // for filtering and pagination
    // #[allow(dead_code)]
    // search: Option<String>,
    // #[allow(dead_code)]
    // page: Option<u32>,
}

/// Pulls all OAuth2 RPs from the backend and returns a HashMap
/// with the "name" field being the keys, for easy human-facing sortability.
pub async fn get_entities(token: &str) -> Result<AdminListOAuth2Msg, GetError> {
    // TODO: the actual pulling and turning into a BTreeMap across the admin systems could *probably* be rolled up into one function? The result object differs but all the query bits are the same.
    let mut oauth2_objects = BTreeMap::new();

    // we iterate over these endpoints
    let endpoints = [("/v1/oauth2", EntityType::OAuth2RP)];

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
            Err(error) => panic!("Failed to grab the OAuth2 RP data into JSON: {:?}", error),
        };

        for entity in data.iter() {
            let mut new_entity = entity.to_owned();
            new_entity.object_type = object_type.clone();

            // first we try the uuid and if that isn't there oh no.
            #[allow(clippy::expect_used)]
            let entity_id = entity
                .attrs
                .uuid
                .first()
                .expect("Failed to grab the SPN for an account.");
            oauth2_objects.insert(entity_id.to_string(), new_entity);
        }
    }

    Ok(AdminListOAuth2Msg::Responded {
        response: oauth2_objects,
    })
}

impl Component for AdminListOAuth2 {
    type Message = AdminListOAuth2Msg;
    type Properties = AdminListOAuth2Props;

    fn create(ctx: &Context<Self>) -> Self {
        // TODO: work out the querystring thing so we can just show x number of elements
        let token = match models::get_bearer_token() {
            Some(value) => value,
            None => String::from(""),
        };

        // start pulling the data on startup
        ctx.link().send_future(async move {
            match get_entities(token.clone().as_str()).await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });
        AdminListOAuth2 {
            state: ListViewState::Loading,
        }
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        match &self.state {
            ListViewState::Loading => {
                html! {"Waiting on the OAuth2 data to load..."}
            }

            ListViewState::Responded { response } => {
                let scope_col = "col";
                html! {
                    <>

                    <ol class="breadcrumb">
                    <li class={CSS_BREADCRUMB_ITEM}><Link<AdminRoute> to={AdminRoute::AdminMenu}>{"Admin"}</Link<AdminRoute>></li>
                    <li class={CSS_BREADCRUMB_ITEM_ACTIVE} aria-current="page">{"OAuth2"}</li>
                    </ol>
                      {do_page_header("OAuth2")}

                      { alpha_warning_banner() }
                <div id={"accountlist"}>
                  <table class={CSS_TABLE}>
                  <thead>
                    <tr>
                      <th scope={scope_col}>{"Display Name"}</th>
                      <th scope={scope_col}>{"Username"}</th>
                      <th scope={scope_col}>{"Description"}</th>
                    </tr>
                  </thead>

                  {
                    response.keys().map(|uuid| {
                        #[allow(clippy::expect_used)]
                      let oauth2_object: &Entity = response.get(uuid).expect("Couldn't get oauth2 key when it was just in the iter...");

                        let display_name: String = match oauth2_object.attrs.displayname.first() {
                          Some(value) => value.to_string(),
                          None => String::from(""),
                        };

                        let description: String = match oauth2_object.attrs.description.first() {
                          Some(value) => value.to_string(),
                          None => String::from(""),
                        };
                        console::log!(format!("{:?}", oauth2_object.attrs));
                        let rs_name: String = match oauth2_object.attrs.oauth2_rs_name.first() {
                            Some(value) => value.to_string(),
                            None => String::from("!error getting rs_name!")
                        };

                        let uuid: String = match oauth2_object.attrs.uuid.first() {
                            Some(value) => value.to_string(),
                            None => {
                                console::error!("Config without a UUID?", format!("{:?}", oauth2_object).to_string());
                                String::from("Unknown UUID!")
                            }
                        };

                        html!{
                          <tr key={uuid.clone()}>
                          <th scope={scope_col} class={CSS_CELL}>
                            <Link<AdminRoute> to={AdminRoute::ViewOAuth2RP{rs_name: rs_name.clone()}}>
                                {display_name}
                                </Link<AdminRoute>></th>
                          <td class={CSS_CELL}>{uuid}</td>
                          <td class={CSS_CELL}>{description}</td>
                          </tr>
                        }
                    }).collect::<Html>()
                  }
                  </table>
                  </div>
                  </>
                }
            }
            ListViewState::Failed { emsg, kopid } => {
                console::error!("Failed to pull details", format!("{:?}", kopid));
                html!(
                    <>
                    {do_alert_error("Failed to Query OAuth2", Some(emsg))}
                    </>
                )
            }
            ListViewState::NotAuthorized {} => {
                do_alert_error("You're not authorized to see this page!", None)
            }
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            AdminListOAuth2Msg::Responded { response } => {
                // TODO: do we paginate here?
                #[cfg(debug)]
                for key in response.keys() {
                    console::log!(
                        "response: {:?}",
                        serde_json::to_string(response.get(key).unwrap()).unwrap()
                    );
                }
                self.state = ListViewState::Responded { response };
                return true;
            }
            AdminListOAuth2Msg::Failed { emsg, kopid } => {
                console::log!("emsg: {:?}", emsg);
                console::log!("kopid: {:?}", kopid);
            }
        }
        false
    }
}

impl From<GetError> for AdminViewOAuth2Msg {
    fn from(ge: GetError) -> Self {
        AdminViewOAuth2Msg::Failed {
            emsg: ge.err,
            kopid: None,
        }
    }
}

// callback messaging for this confused pile of crab-bait
pub enum AdminViewOAuth2Msg {
    /// When the server responds and we need to update the page
    Responded {
        response: Entity,
    },
    Failed {
        emsg: String,
        kopid: Option<String>,
    },
}

#[derive(PartialEq, Eq, Properties)]
pub struct AdminViewOAuth2Props {
    pub rs_name: String,
}

enum ViewState {
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

pub struct AdminViewOAuth2 {
    state: ViewState,
}

impl Component for AdminViewOAuth2 {
    type Message = AdminViewOAuth2Msg;
    type Properties = AdminViewOAuth2Props;

    fn create(ctx: &Context<Self>) -> Self {
        let token = match models::get_bearer_token() {
            Some(value) => value,
            None => String::from(""),
        };
        let rs_name = ctx.props().rs_name.clone();

        // start pulling the data on startup
        ctx.link().send_future(async move {
            match get_oauth2_rp(token.clone().as_str(), &rs_name).await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });
        AdminViewOAuth2 {
            state: ViewState::Loading,
        }
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        match &self.state {
            ViewState::Loading => {
                html! {"Waiting on the OAuth2 data to load..."}
            }

            ViewState::Responded { response } => {
                let oauth2_object: &Entity = response;

                let display_name: String = match oauth2_object.attrs.displayname.first() {
                    Some(value) => value.to_string(),
                    None => String::from("!error getting display name!"),
                };

                let description: String = match oauth2_object.attrs.description.first() {
                    Some(value) => value.to_string(),
                    None => String::from(""),
                };
                let oauth2_rs_name: String = match oauth2_object.attrs.oauth2_rs_name.first() {
                    Some(value) => value.to_string(),
                    None => String::from("!error getting oauth2_rs_name!"),
                };
                let oauth2_rs_origin: String = match oauth2_object.attrs.oauth2_rs_origin.first() {
                    Some(value) => value.to_string(),
                    None => String::from("!error getting oauth2_rs_origin!"),
                };
                let uuid: String = match oauth2_object.attrs.uuid.first() {
                    Some(value) => value.to_string(),
                    None => {
                        console::error!("Config without a UUID?", format!("{:?}", oauth2_object));
                        String::from("Unknown UUID!")
                    }
                };
                html! {
                  <>

                  <ol class="breadcrumb">
                  <li class={CSS_BREADCRUMB_ITEM}><Link<AdminRoute> to={AdminRoute::AdminMenu}>{"Admin"}</Link<AdminRoute>></li>
                  <li class={CSS_BREADCRUMB_ITEM}><Link<AdminRoute> to={AdminRoute::AdminListOAuth2}>{"OAuth2"}</Link<AdminRoute>></li>
                  <li class={CSS_BREADCRUMB_ITEM_ACTIVE} aria-current="page">{display_name.as_str()}</li>
                  </ol>
                  {do_page_header(display_name.as_str())}
                  {alpha_warning_banner()}

                  <p>{"UUID: "}{uuid}</p>
                  <p>{description}</p>
                  <p>{"RS Name: "}{oauth2_rs_name}</p>
                  <p>{"Origin: "}{oauth2_rs_origin}</p>
                  </>
                }
            }
            ViewState::Failed { emsg, kopid } => {
                console::error!("Failed to pull details", format!("{:?}", kopid));
                html!(
                    <>
                    {do_alert_error("Failed to Query OAuth2", Some(emsg))}
                    </>
                )
            }
            ViewState::NotAuthorized {} => {
                do_alert_error("You're not authorized to see this page!", None)
            }
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            AdminViewOAuth2Msg::Responded { response } => {
                // TODO: do we paginate here?
                #[cfg(debug)]
                for key in response.keys() {
                    console::log!(
                        "response: {:?}",
                        serde_json::to_string(response.get(key).unwrap()).unwrap()
                    );
                }
                self.state = ViewState::Responded { response };
            }
            AdminViewOAuth2Msg::Failed { emsg, kopid } => {
                console::log!("emsg: {:?}", &emsg);
                console::log!("kopid: {:?}", kopid.to_owned());
                self.state = ViewState::Failed { emsg, kopid };
            }
        }
        true
    }
}

pub async fn get_oauth2_rp(token: &str, rs_name: &str) -> Result<AdminViewOAuth2Msg, GetError> {
    let request = init_request(format!("/v1/oauth2/{}", rs_name).as_str(), token);
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
        Ok(value) => {
            console::log!(format!("{:?}", value));
            value
        }
        Err(error) => {
            //TODO: turn this into an error, and handle when we aren't authorized. The server doesn't seem to be sending back anything nice for this, which is.. painful.
            console::log!(
                "Failed to grab the OAuth2 RP data into JSON:",
                format!("{:?}", error)
            );
            return Err(GetError {
                err: format!("Failed to grab the OAuth2 RP data into JSON: {:?}", error),
            });
        }
    };

    Ok(AdminViewOAuth2Msg::Responded { response: data })
}
