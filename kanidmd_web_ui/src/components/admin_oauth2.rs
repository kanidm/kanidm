use crate::components::adminmenu::{Entity, GetError};
use crate::components::alpha_warning_banner;
use crate::constants::{CSS_CELL, CSS_PAGE_HEADER, CSS_TABLE};
use crate::models;
use crate::utils::{do_alert_error, init_request};
use gloo::console;
use std::collections::BTreeMap;
use yew::{html, Component, Context, Html, Properties};

impl From<GetError> for AdminListOAuth2Msg {
    fn from(ge: GetError) -> Self {
        AdminListOAuth2Msg::Failed {
            emsg: ge.err,
            kopid: None,
        }
    }
}

pub struct AdminListOAuth2 {
    state: ViewState,
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
    let endpoints = [("/v1/oauth2", "oauth2_rp")];

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
            new_entity.object_type = Some(object_type.to_string());

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
            state: ViewState::Loading,
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        html! {
            <>
              <div class={CSS_PAGE_HEADER}>
                <h2>{ "OAuth2 Configs" }</h2>
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
            AdminListOAuth2Msg::Responded { response } => {
                // TODO: do we paginate here?
                #[cfg(debug)]
                for key in response.keys() {
                    console::log!(
                        "response: {:?}",
                        serde_json::to_string(response.get(key).unwrap()).unwrap()
                    );
                }
                self.state = ViewState::Responded { response };
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

impl AdminListOAuth2 {
    /// output the information based on what's in the current state
    fn view_state(&self, _ctx: &Context<Self>) -> Html {
        match &self.state {
            ViewState::Loading => {
                html! {"Waiting on the OAuth2 data to load..."}
            }

            ViewState::Responded { response } => {
                let scope_col = "col";

                html!(
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
                        // TODO: maybe pull the OAuth2 RP details here? "path": "/v1/oauth2/:id",

                        let uuid: String = match oauth2_object.attrs.uuid.first() {
                            Some(value) => value.to_string(),
                            None => {
                                console::error!("Config without a UUID?", format!("{:?}", oauth2_object).to_string());
                                String::from("Unknown UUID!")
                            }
                        };

                        html!{
                          <tr key={uuid.clone()}>
                          <th scope={scope_col} class={CSS_CELL}>{display_name}</th>
                          <td class={CSS_CELL}>{uuid}</td>
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
                    {do_alert_error("Failed to Query OAuth2", Some(emsg))}
                    </>
                )
            }
            ViewState::NotAuthorized {} => {
                do_alert_error("You're not authorized to see this page!", None)
            }
        }
    }
}
