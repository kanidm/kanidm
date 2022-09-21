use crate::constants::CSS_PAGE_HEADER;
use crate::views::ViewProps;

use gloo::console;
use wasm_bindgen::UnwrapThrowExt;
use yew::prelude::*;

// User Profile UI
pub struct ProfileApp {}

impl Component for ProfileApp {
    type Message = ();
    type Properties = ViewProps;

    fn create(_ctx: &Context<Self>) -> Self {
        #[cfg(debug)]
        console::debug!("views::profile::create");

        ProfileApp {}
    }

    fn changed(&mut self, ctx: &Context<Self>) -> bool {
        console::debug!(format!(
            "views::profile::changed current_user: {:?}",
            ctx.props().current_user_uat,
        ));
        true
    }

    fn update(&mut self, ctx: &Context<Self>, _msg: Self::Message) -> bool {
        console::debug!(format!(
            "views::profile::update current_user: {:?}",
            ctx.props().current_user_uat,
        ));
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug)]
        console::debug!("views::profile::rendered");
    }

    /// UI view for the user profile
    fn view(&self, ctx: &Context<Self>) -> Html {
        let pagecontent = match &ctx.props().current_user_uat {
            None => {
                html! {
                    <h2>
                        {"Loading user info..."}
                    </h2>
                }
            }
            Some(uat) => {
                let mail_primary = match uat.mail_primary.as_ref() {
                    Some(email_address) => {
                        html! {
                            <a href={ format!("mailto:{}", &email_address)}>
                            {email_address}
                            </a>
                        }
                    }
                    None => html! { {"<primary email is unset>"}},
                };

                let spn = &uat.spn.to_owned();
                let spn_split = spn.split('@');
                let username = &spn_split.clone().next().unwrap_throw();
                let domain = &spn_split.clone().last().unwrap_throw();
                let display_name = uat.displayname.to_owned();
                let user_groups: Vec<String> = uat.groups.iter()
                    .map(|group| {
                        #[allow(clippy::unwrap_used)]
                        group.spn.split('@').next().unwrap().to_string()
                    })
                    .collect();

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
                      { format!("{}", &uat.uuid ) }
                      </dd>

                </dl>
                }
            }
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
}
