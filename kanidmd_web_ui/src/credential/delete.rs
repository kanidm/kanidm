use crate::error::*;
use crate::utils;

use super::eventbus::{EventBus, EventBusMsg};
use super::reset::ModalProps;

#[cfg(debug)]
use gloo::console;
use yew::prelude::*;
use yew_agent::Dispatched;

use wasm_bindgen::{JsCast, JsValue, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use kanidm_proto::v1::{CURequest, CUSessionToken, CUStatus};

enum State {
    Init,
    Waiting,
}

pub struct DeleteApp {
    state: State,
}

pub enum Msg {
    Cancel,
    Submit,
    Error { emsg: String, kopid: Option<String> },
    Success,
}

impl From<FetchError> for Msg {
    fn from(fe: FetchError) -> Self {
        Msg::Error {
            emsg: fe.as_string(),
            kopid: None,
        }
    }
}

impl DeleteApp {
    fn reset_and_hide(&mut self) {
        utils::modal_hide_by_id("staticDeletePrimaryCred");
        self.state = State::Init;
    }

    async fn submit_update(token: CUSessionToken, req: CURequest) -> Result<Msg, FetchError> {
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
            let status: CUStatus = jsval.into_serde().expect_throw("Invalid response type");

            EventBus::dispatcher().send(EventBusMsg::UpdateStatus { status });

            Ok(Msg::Success)
        } else {
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(Msg::Error { emsg, kopid })
        }
    }
}

impl Component for DeleteApp {
    type Message = Msg;
    type Properties = ModalProps;

    fn create(_ctx: &Context<Self>) -> Self {
        #[cfg(debug)]
        console::debug!("delete modal create");

        DeleteApp { state: State::Init }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        #[cfg(debug)]
        console::debug!("delete modal::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug)]
        console::debug!("delete modal::update");
        let token_c = ctx.props().token.clone();
        match msg {
            Msg::Cancel => {
                self.reset_and_hide();
            }
            Msg::Submit => {
                ctx.link().send_future(async {
                    match Self::submit_update(token_c, CURequest::PrimaryRemove).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                self.state = State::Waiting;
            }
            Msg::Success => {
                self.reset_and_hide();
            }
            Msg::Error { emsg, kopid } => {
                // Submit the error to the parent.
                EventBus::dispatcher().send(EventBusMsg::Error { emsg, kopid });
                self.reset_and_hide();
            }
        };
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug)]
        console::debug!("delete modal::rendered");
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        #[cfg(debug)]
        console::debug!("delete modal::destroy");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        #[cfg(debug)]
        console::debug!("delete modal::view");

        let submit_enabled = matches!(&self.state, State::Init);

        html! {
            <div class="modal fade" id="staticDeletePrimaryCred" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticDeletePrimaryCred" aria-hidden="true">
              <div class="modal-dialog">
                <div class="modal-content">
                  <div class="modal-header">
                    <h5 class="modal-title" id="staticDeletePrimaryCredLabel">{ "Delete Credential" }</h5>
                    <button type="button" class="btn-close" aria-label="Close"
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::Cancel
                                })
                        }
                    ></button>
                  </div>
                  <div class="modal-body">

                    <p>{ "Delete your Password and any associated MFA?" }</p>
                    <p><strong>{ "Note:"}</strong>{" this will not remove Passkeys." }</p>

                  </div>
                  <div class="modal-footer">
                    <button id="delete-cancel" type="button" class="btn btn-secondary"
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::Cancel
                                })
                        }
                    >{ "Cancel" }</button>
                    <button id="delete-submit" type="button" class="btn btn-danger"
                        disabled={ !submit_enabled }
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::Submit
                                })
                        }
                    >{ "Submit" }</button>
                  </div>
                </div>
              </div>
            </div>
        }
    }
}
