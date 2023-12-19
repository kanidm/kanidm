use gloo::console;
use kanidm_proto::v1::{CURegState, CURequest, CUSessionToken, CUStatus};
use kanidm_proto::webauthn::{CreationChallengeResponse, RegisterPublicKeyCredential};
use kanidmd_web_ui_shared::constants::CLASS_BUTTON_SUCCESS;
use kanidmd_web_ui_shared::error::FetchError;
use serde::Serialize;
use wasm_bindgen::UnwrapThrowExt;
use wasm_bindgen_futures::JsFuture;
use yew::prelude::*;

use super::reset::{EventBusMsg, PasskeyClass, PasskeyModalProps};

use kanidmd_web_ui_shared::{do_request, utils, RequestMethod};
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

            cb.emit(EventBusMsg::UpdateStatus {
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
                CURegState::AttestedPasskey(challenge) | CURegState::Passkey(challenge) => {
                    Msg::ChallengeReady(challenge)
                }
                CURegState::None => Msg::Success,
            })
        } else {
            let emsg = value.as_string().unwrap_or_default();
            Ok(Msg::Error { emsg, kopid })
        }
    }
}

impl Component for PasskeyModalApp {
    type Message = Msg;
    type Properties = PasskeyModalProps;

    fn create(_ctx: &Context<Self>) -> Self {
        console::debug!("passkey modal create");

        PasskeyModalApp {
            state: State::Init,
            label_val: "".to_string(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::debug!("passkey modal::update");
        let cb = ctx.props().cb.clone();
        match msg {
            Msg::LabelCheck => {
                let label = utils::get_value_from_element_id("passkey-label")
                    // Default is empty string.
                    .unwrap_or_default();

                self.label_val = label;
            }
            Msg::Submit => {
                if let State::CredentialReady(rpkc) = &self.state {
                    let rpkc = rpkc.clone();
                    let label = self.label_val.clone();
                    // Init a fetch to get the challenge.
                    let token_c = ctx.props().token.clone();

                    let req = match &ctx.props().class {
                        PasskeyClass::Any => CURequest::PasskeyFinish(label, rpkc),
                        PasskeyClass::Attested => CURequest::AttestedPasskeyFinish(label, rpkc),
                    };

                    ctx.link().send_future(async {
                        match Self::submit_passkey_update(token_c, req, cb).await {
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

                let req = match &ctx.props().class {
                    PasskeyClass::Any => CURequest::PasskeyInit,
                    PasskeyClass::Attested => CURequest::AttestedPasskeyInit,
                };

                ctx.link().send_future(async {
                    match Self::submit_passkey_update(token_c, req, cb).await {
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
                        .map_err(|e| {
                            console::error!(format!("error -> {:?}", e).as_str());
                        })
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
                    match Self::submit_passkey_update(token_c, CURequest::CancelMFAReg, cb).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                self.state = State::FetchingChallenge;
            }
            Msg::Error { emsg, kopid } => {
                // Submit the error to the parent.
                cb.emit(EventBusMsg::Error { emsg, kopid });
                self.reset_and_hide();
            }
        };

        true
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        console::debug!("passkey modal::change");
        false
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        console::debug!("passkey modal::view");

        let label_val = self.label_val.clone();

        let passkey_state = match &self.state {
            State::Init | State::Submitting | State::FetchingChallenge => {
                html! {
                      <div class="spinner-border text-dark" role="status">
                        <span class="visually-hidden">{ "Loading..." }</span>
                      </div>
                }
            }
            State::ChallengeReady(_challenge) => {
                let allowed_devices = ctx.props().allowed_devices.clone();
                // This works around a bug in safari :(
                html! {
                    <>
                        {
                            if let Some(allowed_devices) = allowed_devices {
                                html! {
                                    <>
                                        <p>{ "The following devices are allowed to register" }</p>
                                        <ul>
                                        {
                                            for allowed_devices.iter().map(|dev|
                                                html!{
                                                    <li> { dev } </li>
                                                }
                                            )
                                        }
                                        </ul>
                                    </>
                                }
                            } else {
                                html!{ <></> }
                            }
                        }
                        <button id="passkey-generate" type="button" class="btn btn-primary"
                            onclick={
                                ctx.link()
                                    .callback(move |_| {
                                        Msg::CredentialCreate
                                    })
                            }
                        >{ "Begin Passkey Enrollment" }</button>
                    </>
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
                        onsubmit={ ctx.link().callback(move |e: SubmitEvent| {
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
                    <button id="passkey-submit" type="button" class={CLASS_BUTTON_SUCCESS}
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
          <>
            <button type="button"
                class="btn btn-primary"
                data-bs-toggle="modal"
                data-bs-target="#staticPasskeyCreate"
                onclick={
                    ctx.link()
                        .callback(move |_| {
                            Msg::Generate
                        })
                }
            >
              { "Add Passkey" }
            </button>
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
          </>
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        console::debug!("passkey modal::rendered");
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        console::debug!("passkey modal::destroy");
    }
}
