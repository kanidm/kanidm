//! UI things
//!

use gloo::console;
use wasm_bindgen::JsValue;
use yew::{html, BaseComponent, Context, Html};

use crate::constants::{CSS_NAV_LINK, ID_SIGNOUTMODAL};
use crate::models::clear_bearer_token;
use crate::{do_request, RequestMethod};

/// returns an a-href link which can trigger the signout flow
pub fn signout_link() -> Html {
    html! {
        <a class={CSS_NAV_LINK} href="#" data-bs-toggle="modal"
        data-bs-target={["#", ID_SIGNOUTMODAL].concat()}
        >{"Sign out"}</a>
    }
}

/// does the logout action, calling the api and clearing the local tokens
pub async fn ui_logout() -> Result<(), (String, Option<String>)> {
    let (kopid, status, value, _) = do_request("/v1/logout", RequestMethod::GET, None::<JsValue>)
        .await
        .map_err(|e| {
            let emsg = format!("failed to logout -> {:?}", e);
            console::error!(emsg.as_str());
            (emsg, None)
        })?;

    if status == 200 {
        // only clear the local token if it actually worked, because otherwise you could
        // think the session is gone, while it's still live.
        clear_bearer_token();
        Ok(())
    } else {
        let emsg = value.as_string().unwrap_or_default();
        Err((emsg, kopid))
    }
}

/// Builds the signout modal dialogue box - the "target" is the Message to send when clicked.
pub fn signout_modal<T, U>(ctx: &Context<T>, target: U) -> Html
where
    T: BaseComponent,
    U: Clone + 'static,
    <T as BaseComponent>::Message: From<U>,
{
    html! {<div class="modal" tabindex="-1" role="dialog" id={ID_SIGNOUTMODAL}>
        <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
            <h5 class="modal-title">{"Confirm Sign out"}</h5>
            </div>
            <div class="modal-body text-center">
            {"Are you sure you'd like to log out?"}<br />
            <img src="/pkg/img/kani-waving.svg" alt="Kani waving goodbye" />
            </div>
            <div class="modal-footer">
            <button type="button" class="btn btn-success"
                data-bs-toggle="modal"
                data-bs-target={["#", ID_SIGNOUTMODAL].concat()}
                onclick={ ctx.link().callback(move |_| target.clone()) }>{ "Sign out" }</button>
            <button type="button" class="btn btn-secondary"
                data-bs-dismiss="modal"
                >{"Cancel"}</button>
            </div>
        </div>
        </div>
    </div>}
}
