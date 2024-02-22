use super::reset::{EventBusMsg, TotpRemoveProps};
#[cfg(debug_assertions)]
use gloo::console;
use kanidm_proto::internal::{CURequest, CUSessionToken, CUStatus};
use kanidmd_web_ui_shared::RequestMethod;
use kanidmd_web_ui_shared::{do_request, error::FetchError};
use serde::Serialize;
use wasm_bindgen::UnwrapThrowExt;
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
        let request = (req, token);
        let req_jsvalue = request
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .expect("Failed to serialise request");
        let req_jsvalue = js_sys::JSON::stringify(&req_jsvalue).expect_throw("failed to stringify");

        let (kopid, status, value, _) = do_request(
            "/v1/credential/_update",
            RequestMethod::POST,
            Some(req_jsvalue),
        )
        .await?;
        if status == 200 {
            let status: CUStatus =
                serde_wasm_bindgen::from_value(value).expect_throw("Invalid response type");

            cb.emit(EventBusMsg::UpdateStatus { status });

            Ok(Msg::Success)
        } else {
            let emsg = value.as_string().unwrap_or_default();
            Ok(Msg::Error { emsg, kopid })
        }
    }
}
