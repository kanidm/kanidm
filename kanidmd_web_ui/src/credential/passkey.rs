use gloo::console;
use kanidm_proto::v1::{CURegState, CURequest, CUSessionToken, CUStatus};
use kanidm_proto::webauthn::{CreationChallengeResponse, RegisterPublicKeyCredential};
use wasm_bindgen::{JsCast, JsValue, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};
use yew::prelude::*;
use yew_agent::Dispatched;

use super::eventbus::{EventBus, EventBusMsg};
use super::reset::ModalProps;
use crate::error::*;
use crate::utils;

pub struct PasskeyModalApp {
    state: State,
    label_val: String,
}

pub enum State {
    Init,
    FetchingChallenge,
    ChallengeReady(CreationChallengeResponse),
    CredentialReady(RegisterPublicKeyCredential),
    Submitting,
}

pub enum Msg {
    LabelCheck,
    Cancel,
    Submit,
    Generate,
    Success,
    ChallengeReady(CreationChallengeResponse),
    CredentialCreate,
    CredentialReady(RegisterPublicKeyCredential),
    Error { emsg: String, kopid: Option<String> },
    NavigatorError,
}

impl From<FetchError> for Msg {
    fn from(fe: FetchError) -> Self {
        Msg::Error {
            emsg: fe.as_string(),
            kopid: None,
        }
    }
}

impl PasskeyModalApp {
    fn reset_and_hide(&mut self) {
        utils::modal_hide_by_id("staticPasskeyCreate");
        self.state = State::Init;
        self.label_val = "".to_string();
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
                | CURegState::BackupCodes(_) => Msg::Error {
                    emsg: "Invalid Passkey reg state response".to_string(),
                    kopid,
                },
                CURegState::Passkey(challenge) => Msg::ChallengeReady(challenge),
                CURegState::None => Msg::Success,
            })
        } else {
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_default();
            Ok(Msg::Error { emsg, kopid })
        }
    }
}

impl Component for PasskeyModalApp {
    type Message = Msg;
    type Properties = ModalProps;

    fn create(_ctx: &Context<Self>) -> Self {
        console::debug!("passkey modal create");

        PasskeyModalApp {
            state: State::Init,
            label_val: "".to_string(),
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::debug!("passkey modal::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::debug!("passkey modal::update");
        match msg {
            Msg::LabelCheck => {
                let label = utils::get_value_from_element_id("passkey-label")
                    .unwrap_or_else(|| "".to_string());

                self.label_val = label;
            }
            Msg::Submit => {
                if let State::CredentialReady(rpkc) = &self.state {
                    let rpkc = rpkc.clone();
                    let label = self.label_val.clone();
                    // Init a fetch to get the challenge.
                    let token_c = ctx.props().token.clone();

                    ctx.link().send_future(async {
                        match Self::submit_passkey_update(
                            token_c,
                            CURequest::PasskeyFinish(label, rpkc),
                        )
                        .await
                        {
                            Ok(v) => v,
                            Err(v) => v.into(),
                        }
                    });

                    self.state = State::Submitting;
                }
                // Error?
            }
            Msg::Success => {
                self.reset_and_hide();
            }
            Msg::Generate => {
                // Init a fetch to get the challenge.
                let token_c = ctx.props().token.clone();

                ctx.link().send_future(async {
                    match Self::submit_passkey_update(token_c, CURequest::PasskeyInit).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                self.state = State::FetchingChallenge;
            }
            Msg::ChallengeReady(challenge) => {
                console::debug!(format!("{:?}", challenge).as_str());
                self.state = State::ChallengeReady(challenge);
            }
            Msg::CredentialCreate => {
                if let State::ChallengeReady(ccr) = &self.state {
                    let ccr = ccr.clone();
                    let c_options: web_sys::CredentialCreationOptions = ccr.into();

                    // Create a promise that calls the browsers navigator.credentials.create api.
                    let promise = utils::window()
                        .navigator()
                        .credentials()
                        .create_with_options(&c_options)
                        .expect_throw("Unable to create promise");
                    let fut = JsFuture::from(promise);

                    // Wait on the promise, when complete it will issue a callback.
                    ctx.link().send_future(async move {
                        match fut.await {
                            Ok(jsval) => {
                                // Convert from the raw js value into the expected PublicKeyCredential
                                let w_rpkc = web_sys::PublicKeyCredential::from(jsval);
                                // Serialise the web_sys::pkc into the webauthn proto version, ready to
                                // handle/transmit.
                                let rpkc = RegisterPublicKeyCredential::from(w_rpkc);

                                // Update our state
                                Msg::CredentialReady(rpkc)
                            }
                            Err(e) => {
                                console::error!(format!("error -> {:?}", e).as_str());
                                Msg::NavigatorError
                            }
                        }
                    });
                }
            }
            Msg::CredentialReady(rpkc) => {
                console::debug!(format!("{:?}", rpkc).as_str());
                self.state = State::CredentialReady(rpkc);
            }
            Msg::NavigatorError => {
                // Do something useful, like prompt or have a breadcrumb. But it's
                // not a full error.
            }
            Msg::Cancel => {
                let token_c = ctx.props().token.clone();

                ctx.link().send_future(async {
                    match Self::submit_passkey_update(token_c, CURequest::CancelMFAReg).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                self.state = State::FetchingChallenge;
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
        console::debug!("passkey modal::rendered");
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        console::debug!("passkey modal::destroy");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        console::debug!("passkey modal::view");

        let label_val = self.label_val.clone();

        let passkey_state = match &self.state {
            State::Init => {
                html! {
                    <button id="passkey-generate" type="button" class="btn btn-secondary"
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::Generate
                                })
                        }
                    >
                    // TODO: start the session once the modal is popped up
                    { "Start Creating a New Passkey" }</button>
                }
            }
            State::Submitting | State::FetchingChallenge => {
                html! {
                      <div class="spinner-border text-dark" role="status">
                        <span class="visually-hidden">{ "Loading..." }</span>
                      </div>
                }
            }
            State::ChallengeReady(_challenge) => {
                // This works around a bug in safari :(
                html! {
                    <button id="passkey-generate" type="button" class="btn btn-primary"
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::CredentialCreate
                                })
                        }
                    >{ "Do it!" }</button>
                }
            }
            State::CredentialReady(_) => {
                html! {
                    <h3>{ "Passkey Created!" }</h3>
                }
            }
        };

        let submit_enabled =
            !label_val.is_empty() && matches!(self.state, State::CredentialReady(_));

        let submit_state = match &self.state {
            State::CredentialReady(_rpkc) => {
                html! {
                    <>
                    <form class="row needs-validation" novalidate=true
                        onsubmit={ ctx.link().callback(move |e: FocusEvent| {
                            #[cfg(debug_assertions)]
                            console::debug!("passkey modal::on form submit prevent default");
                            e.prevent_default();
                            if submit_enabled {
                                Msg::Submit
                            } else {
                                Msg::Cancel
                            }
                        } ) }
                    >
                      <label for="passkey-label" class="form-label">{ "Please name this Passkey" }</label>
                      <input
                        type="text"
                        class="form-control"
                        id="passkey-label"
                        placeholder=""
                        value={ label_val }
                        required=true
                        oninput={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::LabelCheck
                                })
                        }
                      />
                    </form>
                    <button id="passkey-submit" type="button" class={crate::constants::CLASS_BUTTON_SUCCESS}
                        disabled={ !submit_enabled }
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::Submit
                                })
                        }
                    >{ "Submit" }</button>
                    </>
                }
            }
            _ => {
                html! {
                    <button id="passkey-cancel" type="button" class="btn btn-secondary"
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::Cancel
                                })
                        }
                    >{ "Cancel" }</button>
                }
            }
        };

        html! {
            <div class="modal fade" id="staticPasskeyCreate" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticPasskeyLabel" aria-hidden="true">
              <div class="modal-dialog">
                <div class="modal-content">
                  <div class="modal-header">
                    <h5 class="modal-title" id="staticPasskeyLabel">{ "Add a New Passkey" }</h5>
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

                    <div class="container">
                      <div class="row">
                        { passkey_state }
                      </div>
                    </div>
                  </div>
                  <div class="modal-footer">
                    { submit_state }
                  </div>
                </div>
              </div>
            </div>
        }
    }
}
