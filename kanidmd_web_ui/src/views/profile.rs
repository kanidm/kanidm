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
pub struct ProfileApp {}

impl Component for ProfileApp {
    type Message = Msg;
    type Properties = ViewProps;

    fn create(_ctx: &Context<Self>) -> Self {
        console::debug!("views::profile::create");
        ProfileApp {}
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::debug!("views::profile::changed");
        false
    }

    fn update(&mut self, _ctx: &Context<Self>, _msg: Self::Message) -> bool {
        console::debug!("views::profile::update");
        /*
        match msg {
            ViewsMsg::Logout => {
            }
        }
        */
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        console::debug!("views::profile::rendered");
    }

    /// UI view for the user profile
    fn view(&self, ctx: &Context<Self>) -> Html {
        console::debug!("views::profile::starting view");

        // Submit a req to init the session.
        // The uuid we want to submit against - hint, it's us.
        let token = ctx.props().token.clone();
        console::debug!("token: ", &token);

        let jwtu = JwsUnverified::from_str(&token).expect_throw("Invalid UAT, unable to parse");

        let uat: Jws<UserAuthToken> = jwtu
            .unsafe_release_without_verification()
            .expect_throw("Unvalid UAT, unable to release ");

        let id = uat.inner.uuid.to_string();

        console::debug!("uuid:", id);
        // let valid_token = ctx.link().send_future(async {
        //     match Self::fetch_token_valid(id, token).await {
        //         Ok(v) => v,
        //         Err(v) => v.into(),
        //     }
        // });
        // console::debug!("valid_token: {:?}");

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
                  <label for="legalname">{ "Legal Name" }</label>
                  <input type="legalname" class="form-control" disabled=true id="legalname" value={ "Cheese Bizkit" } />
              </div>

              <div class="form-group">
                <label for="username">{ "Username" }</label>
                <input type="username" class="form-control" disabled=true id="username" value={ "cbizkit" } />
                </div>

                <div class="form-group">
                    <label for="primary_email">{ "Primary Email" }</label>
                    <input type="primary_email" class="form-control" disabled=true id="primary_email" value={ "cheese-wizz@bizkit.example.com" } />
                </div>
              </form>

              <strong>{ "Groups" }</strong>
              <ul class="list-group">
                <li class="list-group-item">
                {"Crab Admins"}
                // the styling for this is broken because bootstrap's doing inline styles, boo
                <span class="badge bg-danger">{"HP"}</span>
                </li>
                <li class="list-group-item">
                    {"Lobster Wranglers"}
                </li>
             </ul>

             <label for="spn">{ "SPN" }</label>
             <div class="input-group mb-3">
             <input type="text" id="spn" disabled=true class="form-control" value="cbizkit" aria-label="Recipient's username" aria-describedby="basic-addon2" />
             <span class="input-group-text" id="basic-addon2">{"@kanidm.example.com"}</span>
             </div>
            </>
        }
    }
}

impl ProfileApp {}
