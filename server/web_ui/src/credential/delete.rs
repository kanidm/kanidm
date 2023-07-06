#[cfg(debug_assertions)]
use gloo::console;
use kanidm_proto::v1::{CURequest, CUSessionToken, CUStatus};
use wasm_bindgen::{JsValue, UnwrapThrowExt};
use yew::prelude::*;

use super::reset::{EventBusMsg, ModalProps};
use crate::do_request;
use crate::error::*;
use crate::utils;
use crate::RequestMethod;

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

    async fn submit_update(
        token: CUSessionToken,
        req: CURequest,
        cb: Callback<EventBusMsg>,
    ) -> Result<Msg, FetchError> {
        let req_jsvalue = serde_json::to_string(&(req, token))
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise pw curequest");

        let (kopid, status, value, _) = do_request(
            "/v1/credential/_update",
            RequestMethod::POST,
            Some(req_jsvalue),
        )
        .await?;
        if status == 200 {
            let custatus: CUStatus =
                serde_wasm_bindgen::from_value(value).expect_throw("Invalid response type");

            cb.emit(EventBusMsg::UpdateStatus { status: custatus });

            Ok(Msg::Success)
        } else {
            let emsg = value.as_string().unwrap_or_default();
            Ok(Msg::Error { emsg, kopid })
        }
    }
}

impl Component for DeleteApp {
    type Message = Msg;
    type Properties = ModalProps;

    fn create(_ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("delete modal create");

        DeleteApp { state: State::Init }
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("delete modal::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("delete modal::update");
        let token_c = ctx.props().token.clone();
        let cb = ctx.props().cb.clone();
        match msg {
            Msg::Cancel => {
                self.reset_and_hide();
            }
            Msg::Submit => {
                ctx.link().send_future(async {
                    match Self::submit_update(token_c, CURequest::PrimaryRemove, cb).await {
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
                cb.emit(EventBusMsg::Error { emsg, kopid });
                self.reset_and_hide();
            }
        };
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("delete modal::rendered");
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        #[cfg(debug_assertions)]
        console::debug!("delete modal::destroy");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        #[cfg(debug_assertions)]
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
