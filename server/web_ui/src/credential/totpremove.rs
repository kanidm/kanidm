use super::reset::{EventBusMsg, TotpRemoveProps};
#[cfg(debug_assertions)]
use gloo::console;
use kanidm_proto::v1::{CURequest, CUSessionToken, CUStatus};
use wasm_bindgen::{JsCast, JsValue, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use crate::error::*;
use crate::utils;
use yew::prelude::*;

pub enum Msg {
    Submit,
    Success,
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

pub struct TotpRemoveComp {
    enabled: bool,
}

impl Component for TotpRemoveComp {
    type Message = Msg;
    type Properties = TotpRemoveProps;

    fn create(_ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("totp remove::create");

        TotpRemoveComp { enabled: true }
    }

    fn changed(&mut self, _ctx: &Context<Self>, _old_props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("totp remove::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("totp remove::update");
        let cb = ctx.props().cb.clone();

        match msg {
            Msg::Submit => {
                let token_c = ctx.props().token.clone();
                let label = ctx.props().label.clone();
                ctx.link().send_future(async {
                    match Self::submit_totp_update(token_c, CURequest::TotpRemove(label), cb).await
                    {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                self.enabled = false;
            }
            Msg::Success => {
                // Do nothing, very well.
            }
            Msg::Error { emsg, kopid } => {
                // Submit the error to the parent.
                cb.emit(EventBusMsg::Error { emsg, kopid });
            }
        }
        true
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let label = ctx.props().label.clone();
        let submit_enabled = self.enabled;

        html! {
          <div class="row mb-3">
            <div class="col">{ label }</div>
            <div class="col">
            <button type="button" class="btn btn-dark btn-sml"
                disabled={ !submit_enabled }
                onclick={
                    ctx.link()
                        .callback(move |_| Msg::Submit)
                }
            >
              { "Remove TOTP" }
            </button>
            </div>
          </div>
        }
    }
}

impl TotpRemoveComp {
    async fn submit_totp_update(
        token: CUSessionToken,
        req: CURequest,
        cb: Callback<EventBusMsg>,
    ) -> Result<Msg, FetchError> {
        let req_jsvalue = serde_json::to_string(&(req, token))
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise pw curequest");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);

        opts.body(Some(&req_jsvalue));

        let request = Request::new_with_str_and_init("/v1/credential/_update", &opts)?;
        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
        let status = resp.status();
        let headers = resp.headers();

        let kopid = headers.get("x-kanidm-opid").ok().flatten();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let status: CUStatus =
                serde_wasm_bindgen::from_value(jsval).expect_throw("Invalid response type");

            cb.emit(EventBusMsg::UpdateStatus { status });

            Ok(Msg::Success)
        } else {
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_default();
            Ok(Msg::Error { emsg, kopid })
        }
    }
}
