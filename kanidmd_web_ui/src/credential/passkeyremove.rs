use crate::error::*;
use crate::utils;

use super::eventbus::{EventBus, EventBusMsg};
use super::reset::PasskeyRemoveModalProps;

#[cfg(debug)]
use gloo::console;
use yew::prelude::*;
use yew_agent::Dispatched;

use wasm_bindgen::{JsCast, JsValue, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use uuid::Uuid;

use kanidm_proto::v1::{CURegState, CURequest, CUSessionToken, CUStatus};

pub struct PasskeyRemoveModalApp {
    state: State,
    target: String,
    tag: String,
    uuid: Uuid,
}

pub enum State {
    Init,
    Submitting,
}

pub enum Msg {
    Cancel,
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

impl PasskeyRemoveModalApp {
    pub fn render_button(tag: &str, uuid: Uuid) -> Html {
        let remove_tgt = format!("#staticPasskeyRemove-{}", uuid);
        let tag = tag.to_string();

        html! {
          <div class="row mb-3">
            <div class="col">{ tag.clone() }</div>
            <div class="col">
            <button type="button" class="btn btn-dark btn-sml" id={tag} data-bs-toggle="modal" data-bs-target={ remove_tgt }>
              { "Remove" }
            </button>
            </div>
          </div>
        }
    }

    fn reset_and_hide(&mut self) {
        utils::modal_hide_by_id(&self.target);
        self.state = State::Init;
    }

    async fn submit_passkey_update(
        token: CUSessionToken,
        req: CURequest,
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

            EventBus::dispatcher().send(EventBusMsg::UpdateStatus {
                status: status.clone(),
            });

            Ok(match status.mfaregstate {
                CURegState::TotpCheck(_)
                | CURegState::TotpTryAgain
                | CURegState::TotpInvalidSha1
                | CURegState::Passkey(_)
                | CURegState::BackupCodes(_) => Msg::Error {
                    emsg: "Invalid Passkey reg state response".to_string(),
                    kopid,
                },
                CURegState::None => Msg::Success,
            })
        } else {
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(Msg::Error { emsg, kopid })
        }
    }
}

impl Component for PasskeyRemoveModalApp {
    type Message = Msg;
    type Properties = PasskeyRemoveModalProps;

    fn create(ctx: &Context<Self>) -> Self {
        #[cfg(debug)]
        console::debug!("passkey remove modal create");

        let tag = ctx.props().tag.clone();
        let uuid = ctx.props().uuid;
        let target = format!("staticPasskeyRemove-{}", uuid);

        PasskeyRemoveModalApp {
            state: State::Init,
            tag,
            uuid,
            target,
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        #[cfg(debug)]
        console::debug!("passkey remove modal::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug)]
        console::debug!("passkey remove modal::update");
        match msg {
            Msg::Submit => {
                self.reset_and_hide();

                // Do the call back.
                let token_c = ctx.props().token.clone();
                let uuid = self.uuid;

                ctx.link().send_future(async move {
                    match Self::submit_passkey_update(token_c, CURequest::PasskeyRemove(uuid)).await
                    {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                self.state = State::Submitting;
            }
            Msg::Success | Msg::Cancel => {
                self.reset_and_hide();
            }
            Msg::Error { emsg, kopid } => {
                // Submit the error to the parent.
                EventBus::dispatcher().send(EventBusMsg::Error { emsg, kopid });
                self.reset_and_hide();
            }
        }
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug)]
        console::debug!("passkey remove modal::rendered");
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        #[cfg(debug)]
        console::debug!("passkey remove modal::destroy");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        #[cfg(debug)]
        console::debug!("passkey remove modal::view");

        let remove_tgt = self.target.clone();
        let remove_id = format!("staticPasskeyRemove-{}", self.uuid);
        let remove_label = format!("staticPasskeyRemoveLabel-{}", self.uuid);

        let msg = format!("Delete the Passkey named '{}'?", self.tag);

        let submit_enabled = matches!(self.state, State::Init);

        html! {
            <div class="modal fade" id={ remove_id } data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby={ remove_tgt } aria-hidden="true">
              <div class="modal-dialog">
                <div class="modal-content">
                  <div class="modal-header">
                    <h5 class="modal-title" id={ remove_label }>{ "Delete Passkey" }</h5>
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

                    <p>{ msg }</p>

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
