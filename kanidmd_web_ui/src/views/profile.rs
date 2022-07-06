// use crate::error::*;
// use crate::models;
// use crate::utils;
use crate::views::ViewProps;

use compact_jwt::{Jws, JwsUnverified};
use gloo::console;
use kanidm_proto::v1::UserAuthToken;
use std::str::FromStr;
use wasm_bindgen::UnwrapThrowExt;
use yew::prelude::*;
// use web_sys::{Request, RequestInit, RequestMode, Response};

pub enum Msg {
    // Nothing
}


// User Profile UI
pub struct ProfileApp {
}

impl Component for ProfileApp {
    type Message = Msg;
    type Properties = ViewProps;

    fn create(_ctx: &Context<Self>) -> Self {
        console::log!("views::profile::create");
        ProfileApp {}
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::log!("views::profile::changed");
        false
    }

    fn update(&mut self, _ctx: &Context<Self>, _msg: Self::Message) -> bool {
        console::log!("views::profile::update");
        /*
        match msg {
            ViewsMsg::Logout => {
            }
        }
        */
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        console::log!("views::profile::rendered");
    }

    /// UI view for the user profile
    fn view(&self, ctx: &Context<Self>) -> Html {
        console::log!("views::profile::starting view");

        // Submit a req to init the session.
        // The uuid we want to submit against - hint, it's us.
        let token = ctx.props().token.clone();
        console::log!("token: ", &token);

        let jwtu =
        JwsUnverified::from_str(&token).expect_throw("Invalid UAT, unable to parse");

        let uat: Jws<UserAuthToken> = jwtu
        .unsafe_release_without_verification()
        .expect_throw("Unvalid UAT, unable to release ");

        let id = uat.inner.uuid.to_string();


        console::log!("uuid:", id);
        // let valid_token = ctx.link().send_future(async {
        //     match Self::fetch_token_valid(id, token).await {
        //         Ok(v) => v,
        //         Err(v) => v.into(),
        //     }
        // });
        // console::log!("valid_token: {:?}");

        html! {
            <>
              <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                <h2>{ "Profile" }</h2>
              </div>
              <div class="alert alert-warning" role="alert">
                { "🦀 Kanidm is still in early Alpha, this interface is a placeholder! " }
              </div>

              <form class="form-horizontal" role="form">


              <div class="form-group">
                <label for="username">{ "Username" }</label>
                <input type="username" class="form-control" id="username" value={ "cbizkit" } />
                </div>


                <label for="spn">{ "SPN" }</label>
                <div class="input-group mb-3">
                <input type="text" id="spn" class="form-control" value="cbizkit" aria-label="Recipient's username" aria-describedby="basic-addon2" />
                <span class="input-group-text" id="basic-addon2">{"@kanidm.example.com"}</span>
                </div>


                <div class="form-group">
                    <label for="legalname">{ "Legal Name" }</label>
                    <input type="legalname" class="form-control" id="legalname" value={ "Cheese Bizkit" } />
                </div>
                <div class="form-group">
                    <label for="primary_email">{ "Primary Email" }</label>
                    <input type="primary_email" class="form-control" id="primary_email" value={ "cheese-wizz@bizkit.example.com" } />
                </div>
              </form>

              <strong>{ "Groups" }</strong>
              <ul class="list-group">
                <li class="list-group-item">
                {"Crab Admins"}
                <span class="badge bg-danger">{"HP"}</span>
                </li>
                <li class="list-group-item">
                    {"Lobster Wranglers"}
                </li>
             </ul>
            </>
        }
    }
}


impl ProfileApp {
    // async fn fetch_token_valid(id: String, token: String) -> Result<Msg, FetchError> {
    //     let mut opts = RequestInit::new();
    //     opts.method("GET");
    //     opts.mode(RequestMode::SameOrigin);

    //     let uri = format!("/v1/account/{}/_credential/_update", id);

    //     let request = Request::new_with_str_and_init(uri.as_str(), &opts)?;

    //     request
    //         .headers()
    //         .set("content-type", "application/json")
    //         .expect_throw("failed to set header");
    //     request
    //         .headers()
    //         .set("authorization", format!("Bearer {}", token).as_str())
    //         .expect_throw("failed to set header");

    //     let window = utils::window();
    //     let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    //     let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
    //     let status = resp.status();

    //     if status == 200 {
    //         let jsval = JsFuture::from(resp.json()?).await?;
    //         let (token, status): (CUSessionToken, CUStatus) =
    //             jsval.into_serde().expect_throw("Invalid response type");
    //         Ok(Msg::BeginCredentialUpdate { token, status })
    //     } else {
    //         let headers = resp.headers();
    //         let kopid = headers.get("x-kanidm-opid").ok().flatten();
    //         let text = JsFuture::from(resp.text()?).await?;
    //         let emsg = text.as_string().unwrap_or_else(|| "".to_string());
    //         // let jsval_json = JsFuture::from(resp.json()?).await?;
    //         Ok(Msg::Error { emsg, kopid })
    //     }
    // }
}
