use gloo::console;
use kanidm_proto::v1::{Entry, WhoamiResponse};
use uuid::Uuid;
use wasm_bindgen::{JsCast, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestCredentials, RequestInit, RequestMode, Response};
use yew::prelude::*;
use yew::virtual_dom::VNode;

use crate::constants::CSS_PAGE_HEADER;
use crate::error::FetchError;
use crate::utils;
use crate::views::ViewProps;

struct Profile {
    mail_primary: Option<String>,
    spn: String,
    displayname: String,
    groups: Vec<String>,
    uuid: Uuid,
}

impl TryFrom<Entry> for Profile {
    type Error = String;

    fn try_from(entry: Entry) -> Result<Self, Self::Error> {
        console::error!("Entry Dump", format!("{:?}", entry));

        let uuid = entry
            .attrs
            .get("uuid")
            .and_then(|list| list.get(0))
            .ok_or_else(|| "Missing UUID".to_string())
            .and_then(|uuid_str| {
                Uuid::parse_str(uuid_str).map_err(|_| "Invalid UUID".to_string())
            })?;

        let spn = entry
            .attrs
            .get("spn")
            .and_then(|list| list.get(0))
            .cloned()
            .ok_or_else(|| "Missing SPN".to_string())?;

        let displayname = entry
            .attrs
            .get("displayname")
            .and_then(|list| list.get(0))
            .cloned()
            .ok_or_else(|| "Missing displayname".to_string())?;

        let groups = entry.attrs.get("memberof").cloned().unwrap_or_default();

        let mail_primary = entry
            .attrs
            .get("mail_primary")
            .and_then(|list| list.get(0))
            .cloned();

        Ok(Profile {
            mail_primary,
            spn,
            displayname,
            groups,
            uuid,
        })
    }
}

enum State {
    Loading,
    Ready(Profile),
    Error { emsg: String, kopid: Option<String> },
}

pub enum Msg {
    Profile { entry: Entry },
    Error { emsg: String, kopid: Option<String> },
}

impl From<FetchError> for Msg {
    fn from(fe: FetchError) -> Self {
        Msg::Error {
            emsg: fe.as_string(),
            kopid: None,
        }
    }
}

// User Profile UI
pub struct ProfileApp {
    state: State,
}

impl Component for ProfileApp {
    type Message = Msg;
    type Properties = ViewProps;

    fn create(ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("views::profile::create");

        ctx.link().send_future(async {
            match Self::fetch_profile_data().await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });

        ProfileApp {
            state: State::Loading,
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        true
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("profile::update");
        match msg {
            Msg::Profile { entry } => {
                self.state = match Profile::try_from(entry) {
                    Ok(profile) => State::Ready(profile),
                    Err(emsg) => State::Error { emsg, kopid: None },
                };
                true
            }
            Msg::Error { emsg, kopid } => {
                self.state = State::Error { emsg, kopid };
                true
            }
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("views::profile::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.state {
            State::Loading => {
                html! {
                  <main class="text-center form-signin h-100">
                    <div class="vert-center">
                      <div class="spinner-border text-dark" role="status">
                        <span class="visually-hidden">{ "Loading..." }</span>
                      </div>
                    </div>
                  </main>
                }
            }
            State::Ready(profile) => self.view_profile(ctx, profile),
            State::Error { emsg, kopid } => self.do_alert_error(
                "An error has occured 😔 ",
                Some(
                    format!(
                        "{}\n\n{}",
                        emsg.as_str(),
                        if let Some(opid) = kopid.as_ref() {
                            format!("Operation ID: {}", opid.clone())
                        } else {
                            "Error occurred client-side.".to_string()
                        }
                    )
                    .as_str(),
                ),
                ctx,
            ),
        }
    }
}

impl ProfileApp {
    fn do_alert_error(
        &self,
        alert_title: &str,
        alert_message: Option<&str>,
        _ctx: &Context<Self>,
    ) -> VNode {
        html! {
        <div class="container">
            <div class="row justify-content-md-center">
                <div class="alert alert-danger" role="alert">
                    <p><strong>{ alert_title }</strong></p>
                    if let Some(value) = alert_message {
                        <p>{ value }</p>
                    }
                </div>
            </div>
        </div>
        }
    }

    /// UI view for the user profile
    fn view_profile(&self, _ctx: &Context<Self>, profile: &Profile) -> Html {
        let mail_primary = match profile.mail_primary.as_ref() {
            Some(email_address) => {
                html! {
                    <a href={ format!("mailto:{}", &email_address)}>
                    {email_address}
                    </a>
                }
            }
            None => html! { {"<primary email is unset>"}},
        };

        let spn = &profile.spn.to_owned();
        let spn_split = spn.split('@');
        let username = &spn_split.clone().next().unwrap_throw();
        let domain = &spn_split.clone().last().unwrap_throw();
        let display_name = profile.displayname.to_owned();
        let user_groups: Vec<String> = profile
            .groups
            .iter()
            .map(|group_spn| {
                #[allow(clippy::unwrap_used)]
                group_spn.split('@').next().unwrap().to_string()
            })
            .collect();

        let pagecontent = html! {
            <dl class="row">
                <dt class="col-6">{ "Display Name" }</dt>
                <dd class="col">{ display_name }</dd>

                <dt class="col-6">{ "Primary Email" }</dt>
                <dd class="col">{mail_primary}</dd>

                <dt class="col-6">{ "Group Memberships" }</dt>
                <dd class="col">
                    <ul class="list-group">
                    {
                        if user_groups.is_empty() {
                            html!{
                                <li>{"Not a member of any groups"}</li>
                            }
                        } else {
                            html!{
                                {
                                    for user_groups.iter()
                                        .map(|group|
                                            html!{ <li>{ group }</li> }
                                        )
                                }
                            }
                        }
                    }
                    </ul>
                </dd>


            <dt class="col-6">
            { "User's SPN" }
            </dt>
              <dd class="col">
              { username.to_string() }{"@"}{ domain }
              </dd>

            <dt class="col-6">
            { "User's UUID" }
            </dt>
              <dd class="col">
              { format!("{}", &profile.uuid ) }
              </dd>

        </dl>
        };
        html! {
            <>
            <div class={CSS_PAGE_HEADER}>
                <h2>{ "Profile" }</h2>
            </div>

            { pagecontent }
            </>
        }
    }

    async fn fetch_profile_data() -> Result<Msg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::SameOrigin);
        opts.credentials(RequestCredentials::SameOrigin);

        let request = Request::new_with_str_and_init("/v1/self", &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
        let status = resp.status();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let state: WhoamiResponse = serde_wasm_bindgen::from_value(jsval)
                .map_err(|e| {
                    let e_msg = format!("serde error -> {:?}", e);
                    console::error!(e_msg.as_str());
                })
                .expect_throw("Invalid response type");

            Ok(Msg::Profile {
                entry: state.youare,
            })
        } else {
            let headers = resp.headers();
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_default();
            Ok(Msg::Error { emsg, kopid })
        }
    }
}
