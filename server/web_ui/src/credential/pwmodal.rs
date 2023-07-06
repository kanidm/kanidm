use gloo::console;
use kanidm_proto::v1::{CURequest, CUSessionToken, CUStatus, OperationError, PasswordFeedback};
use wasm_bindgen::{JsValue, UnwrapThrowExt};

use yew::prelude::*;

use super::reset::{EventBusMsg, ModalProps};
use crate::error::*;
use crate::utils;
use crate::{do_request, RequestMethod};

enum PwState {
    Init,
    Feedback(Vec<PasswordFeedback>),
    Waiting,
}

enum PwCheck {
    Init,
    Valid,
    Invalid,
}

pub struct PwModalApp {
    state: PwState,
    pw_check: PwCheck,
    pw_val: String,
    pw_check_val: String,
}

#[allow(clippy::large_enum_variant)]
pub enum Msg {
    PasswordCheck,
    PasswordSubmit,
    PasswordCancel,
    PasswordResponseQuality { feedback: Vec<PasswordFeedback> },
    PasswordResponseSuccess { status: CUStatus },
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

impl PwModalApp {
    fn reset_and_hide(&mut self) {
        utils::modal_hide_by_id("staticPassword");
        self.pw_val = "".to_string();
        self.pw_check_val = "".to_string();
        self.pw_check = PwCheck::Init;
        self.state = PwState::Init;
    }

    async fn submit_password_update(token: CUSessionToken, pw: String) -> Result<Msg, FetchError> {
        let req_jsvalue = serde_json::to_string(&(CURequest::Password(pw), token))
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise pw curequest");

        let (kopid, status, value, _) = do_request(
            "/v1/credential/_update",
            RequestMethod::POST,
            Some(req_jsvalue),
        )
        .await?;

        if status == 200 {
            let status: CUStatus =
                serde_wasm_bindgen::from_value(value).expect_throw("Invalid response type");
            Ok(Msg::PasswordResponseSuccess { status })
        } else if status == 400 {
            let status: OperationError =
                serde_wasm_bindgen::from_value(value).expect_throw("Invalid response type");
            match status {
                OperationError::PasswordQuality(feedback) => {
                    Ok(Msg::PasswordResponseQuality { feedback })
                }
                e => Ok(Msg::Error {
                    emsg: format!("Invalid PWResp State Transition due to {:?}", e),
                    kopid,
                }),
            }
        } else {
            let emsg = value.as_string().unwrap_or_default();
            Ok(Msg::Error { emsg, kopid })
        }
    }
}

impl Component for PwModalApp {
    type Message = Msg;
    type Properties = ModalProps;

    fn create(_ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("pw modal create");

        PwModalApp {
            state: PwState::Init,
            pw_check: PwCheck::Init,
            pw_val: "".to_string(),
            pw_check_val: "".to_string(),
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("pw modal::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("pw modal::update");
        let cb = ctx.props().cb.clone();
        match msg {
            Msg::PasswordCheck => {
                // default is empty string
                let pw = utils::get_value_from_element_id("new-password").unwrap_or_default();
                let check =
                    utils::get_value_from_element_id("new-password-check").unwrap_or_default();

                if pw == check {
                    self.pw_check = PwCheck::Valid
                } else {
                    self.pw_check = PwCheck::Invalid
                }

                self.pw_val = pw;
                self.pw_check_val = check;
            }
            Msg::PasswordCancel => {
                self.reset_and_hide();
            }
            Msg::PasswordSubmit => {
                self.state = PwState::Waiting;

                // default is empty string
                let pw = utils::get_value_from_element_id("new-password").unwrap_or_default();
                let token_c = ctx.props().token.clone();

                ctx.link().send_future(async {
                    match Self::submit_password_update(token_c, pw).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
            }
            Msg::PasswordResponseQuality { feedback } => self.state = PwState::Feedback(feedback),
            Msg::PasswordResponseSuccess { status } => {
                // Submit the update to the parent
                cb.emit(EventBusMsg::UpdateStatus { status });
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
        console::debug!("pw modal::rendered");
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        #[cfg(debug_assertions)]
        console::debug!("pw modal::destroy");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        #[cfg(debug_assertions)]
        console::debug!("pw modal::view");

        let (pw_class, pw_feedback) = match &self.state {
            PwState::Feedback(feedback) => {
                let fb = html! {
                  <div id="password-validation-feedback" class="invalid-feedback">
                        <ul>
                          {
                            feedback.iter()
                                .map(|item| {
                                    html! { <li>{ format!("{:?}", item) }</li> }
                                })
                                .collect::<Html>()
                          }
                        </ul>
                  </div>
                };

                (classes!("form-control", "is-invalid"), fb)
            }
            _ => {
                let fb = html! {
                  <div id="password-validation-feedback" class="invalid-feedback">
                  </div>
                };
                (classes!("form-control"), fb)
            }
        };

        let pw_check_class = match &self.pw_check {
            PwCheck::Init => classes!("form-control"),
            PwCheck::Valid => classes!("form-control", "is-valid"),
            PwCheck::Invalid => classes!("form-control", "is-invalid"),
        };

        let submit_enabled = matches!(
            (&self.state, &self.pw_check),
            (PwState::Feedback(_), PwCheck::Valid) | (PwState::Init, PwCheck::Valid),
        );

        let pw_val = self.pw_val.clone();
        let pw_check_val = self.pw_check_val.clone();

        html! {
            <div class="modal fade" id="staticPassword" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticPasswordLabel" aria-hidden="true">
              <div class="modal-dialog">
                <div class="modal-content">
                  <div class="modal-header">
                    <h5 class="modal-title" id="staticPasswordLabel">{ "Add a New Password" }</h5>
                    <button type="button" class="btn-close" aria-label="Close"
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::PasswordCancel
                                })
                        }
                    ></button>
                  </div>
                  <div class="modal-body">
                    <form class="row g-3 needs-validation" novalidate=true
                        onsubmit={ ctx.link().callback(move |e: SubmitEvent| {
                            console::debug!("pw modal::on form submit prevent default");
                            e.prevent_default();
                            if submit_enabled {
                                Msg::PasswordSubmit
                            } else {
                                Msg::PasswordCancel
                            }
                        } ) }
                    >
                      <input hidden=true type="text" autocomplete="username" />
                      <label for="new-password" class="form-label">{ "Enter New Password" }</label>
                      <input
                        aria-describedby="password-validation-feedback"
                        autocomplete="new-password"
                        class={ pw_class }
                        id="new-password"
                        oninput={
                            ctx.link()
                            .callback(move |_| {
                                Msg::PasswordCheck
                            })
                        }
                        placeholder=""
                        required=true
                        type="password"
                        value={ pw_val }
                      />
                      { pw_feedback }
                      <label for="new-password-check" class="form-label">{ "Repeat Password" }</label>
                      <input
                        aria-describedby="new-password-check-feedback"
                        autocomplete="new-password"
                        class={ pw_check_class }
                        id="new-password-check"
                        oninput={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::PasswordCheck
                                })
                        }
                        placeholder=""
                        required=true
                        type="password"
                        value={ pw_check_val }
                      />
                      if !submit_enabled {
                        <div class="invalid-feedback">
                            { "Passwords do not match." }
                        </div>
                      }
                    </form>
                  </div>
                  <div class="modal-footer">
                    <button id="password-cancel" type="button" class="btn btn-secondary"
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::PasswordCancel
                                })
                        }
                    >{ "Cancel" }</button>
                    <button id="password-submit" type="button" class="btn btn-primary"
                        disabled={ !submit_enabled }
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::PasswordSubmit
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
