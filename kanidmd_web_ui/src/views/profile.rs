use crate::error::FetchError;
// use crate::error::*;
// use crate::models;
use crate::utils;
use crate::views::ViewProps;

// use compact_jwt::{Jws, JwsUnverified};
use gloo::console;
use kanidm_proto::v1::WhoamiResponse;
// use kanidm_proto::v1::{UserAuthToken,WhoamiResponse};
use std::fmt::Debug;
// use std::str::FromStr;
use wasm_bindgen::JsCast;
// use wasm_bindgen::JsValue;
use wasm_bindgen::UnwrapThrowExt;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};
use yew::prelude::*;
// use web_sys::{Request, RequestInit, RequestMode, Response};

pub enum Msg {
    // Nothing
    TokenValid(String),
    TokenInvalid,
    Error { emsg: String, kopid: Option<String> },
    ProfileInfoRecieved(WhoamiResponse),
}

#[derive(Debug)]
enum ProfileAppState {
    Loading,
    Loaded,
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
    // #[allow(dead_code)] // not really, because it's read in update()
    state: ProfileAppState,
    token: Option<String>,
    user: Option<WhoamiResponse>,
}

impl Component for ProfileApp {
    type Message = Msg;
    type Properties = ViewProps;

    fn create(ctx: &Context<Self>) -> Self {
        #[cfg(debug)]
        console::debug!("views::profile::create");

        // Submit a req to init the session.
        // The uuid we want to submit against - hint, it's us.
        let token = ctx.props().token.clone();
        #[cfg(debug)]
        console::debug!("token: ", &token);

        // let jwtu = JwsUnverified::from_str(&token).expect_throw("Invalid UAT, unable to parse");

        // let uat: Jws<UserAuthToken> = jwtu
        //     .unsafe_release_without_verification()
        //     .expect_throw("Unvalid UAT, unable to release ");

        let token_c = token.clone();
        ctx.link().send_future(async {
            match Self::fetch_token_valid(token_c).await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });

        return ProfileApp {
            state: ProfileAppState::Loading,
            token: None,
            user: None,
        };

        // // TODO: if the token's not valid then redirect to home
        // let location = utils::window().location();

        // match location.replace(loc.as_str()) {
        //     // No need to redraw, we are leaving.
        //     Ok(_) => false,
        //     Err(e) => {
        //         // Something went bang, opps.
        //         console::error!(format!("{:?}", e).as_str());
        //         self.state = State::ErrInvalidRequest;
        //         true
        //     }
        // }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        #[cfg(debug)]
        console::debug!("views::profile::changed");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug)]
        console::debug!("views::profile::update");
        match msg {
            Msg::Error { emsg, kopid } => {
                console::error!(format!(
                    "Failed to something {:?} - kopid {:?}",
                    emsg, kopid
                ));
            }
            Msg::TokenInvalid => {
                // TODO redirect off to login
                let location = utils::window().location();

                match location.replace("/") {
                    // No need to redraw, we are leaving.
                    Ok(_) => return false,
                    Err(e) => {
                        // Something went bang, opps.
                        console::error!(format!("{:?}", e).as_str());
                        // self.state = State::ErrInvalidRequest;
                    }
                }
            }
            Msg::TokenValid(token) => {
                // nothin' much
                self.token = Some(token.clone());
                #[cfg(debug)]
                console::debug!(format!("Token is valid! ({})", token));

                // TODO: start doing the thing with the update of the window etc
                let token_c = token.clone();
                ctx.link().send_future(async {
                    match Self::fetch_user_data(token_c).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
            }
            Msg::ProfileInfoRecieved(data) => {
                #[cfg(debug)]
                console::debug!(format!("ProfileInfoRecieved({:?})", data));
                self.state = ProfileAppState::Loaded;
                self.user = Some(data);
            }
        }
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug)]
        console::debug!("views::profile::rendered");
    }

    /// UI view for the user profile
    fn view(&self, _ctx: &Context<Self>) -> Html {
        #[cfg(debug)]
        console::debug!(format!(
            "views::profile::starting view state: {:?}",
            &self.state
        ));

        let pagecontent = match self.state {
            ProfileAppState::Loading => {
                html! {
                    <h2>
                        {"Loading user info..."}
                    </h2>
                }
            }
            ProfileAppState::Loaded => {
                let userinfo = self.user.as_ref().unwrap();

                let mail_primary = match userinfo.uat.mail_primary.as_ref() {
                    Some(email_address) => {
                        html! {
                            <a href={ format!("mailto:{}", &email_address)}>
                            {email_address}
                            </a>
                        }
                    }
                    None => html! { {"<primary email is unset>"}},
                };
                // .unwrap_or(&"<primary email is unset>".to_string()).into();

                let spn = &userinfo.uat.spn.to_owned();
                let spn_split = spn.split("@");

                let username = &spn_split.clone().nth(0).unwrap();
                let domain = &spn_split.clone().last().unwrap();
                let display_name = userinfo.uat.displayname.to_owned();
                let user_groups = userinfo.youare.attrs.get("memberof");

                html! {
                    <dl class="row">
                        <dt class="col-6">{ "Display Name" }</dt>
                        <dd class="col">{ display_name }</dd>

                        <dt class="col-6">{ "Primary Email" }</dt>
                        <dd class="col">{mail_primary}</dd>

                        <dt class="col-6">{ "Group Memberships" }</dt>
                        <dd class="col">
                            <ul class="list-group">
                            {
                            match user_groups {
                                Some(grouplist) => html!{
                                    {
                                        for grouplist.iter()
                                            .map(|group|
                                    {
                                        html!{ <li>{ format!( "{}", group.split("@").nth(0).unwrap() ) }</li> }

                                    })
                                }
                                },
                                None => html!{
                                    <li>{"Not a member of any groups"}</li>
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
                      { format!("{}", &userinfo.uat.uuid ) }
                      </dd>

                </dl>
                }
            }
        };
        html! {
            <>
            <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                <h2>{ "Profile" }</h2>
            </div>
            <div class="alert alert-warning" role="alert">
                { "🦀 Kanidm is still in early Alpha, this interface is a placeholder! " }
            </div>

            { pagecontent }
            </>
        }
    }
}

impl ProfileApp {
    async fn fetch_token_valid(token: String) -> Result<Msg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::SameOrigin);
        let request = Request::new_with_str_and_init("/v1/auth/valid", &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");
        request
            .headers()
            .set("authorization", format!("Bearer {}", token).as_str())
            .expect_throw("failed to set header");

        let window = crate::utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
        let status = resp.status();

        if status == 200 {
            Ok(Msg::TokenValid(token))
        } else if status == 401 {
            Ok(Msg::TokenInvalid)
        } else {
            let headers = resp.headers();
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(Msg::Error { emsg, kopid })
        }
    }

    async fn fetch_user_data(token: String) -> Result<Msg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::SameOrigin);

        let request = Request::new_with_str_and_init("/v1/self", &opts)?;
        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");
        request
            .headers()
            .set("authorization", format!("Bearer {}", token).as_str())
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
        let status = resp.status();
        let headers = resp.headers();
        let kopid = headers.get("x-kanidm-opid").ok().flatten();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let whoamiresponse: WhoamiResponse = jsval
                .into_serde()
                .map_err(|e| {
                    let e_msg = format!("serde error getting user data -> {:?}", e);
                    console::error!(e_msg.as_str());
                })
                .expect_throw("Invalid response type");
            Ok(Msg::ProfileInfoRecieved(whoamiresponse))
        } else {
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(Msg::Error { emsg, kopid })
        }
    }
}
