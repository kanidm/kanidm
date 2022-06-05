use crate::error::*;
use crate::utils;

use super::eventbus::{EventBus, EventBusMsg};
use super::reset::ModalProps;

use gloo::console;
use yew::prelude::*;
use yew_agent::{Dispatched, Dispatcher};

use wasm_bindgen::{JsCast, JsValue, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use kanidm_proto::v1::{CURequest, CUSessionToken, CUStatus, OperationError, PasswordFeedback};

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
        let intentreq_jsvalue = serde_json::to_string(&(CURequest::Password(pw), token))
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise pw curequest");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);

        opts.body(Some(&intentreq_jsvalue));

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

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let status: CUStatus = jsval.into_serde().expect_throw("Invalid response type");
            Ok(Msg::PasswordResponseSuccess { status })
        } else if status == 400 {
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let jsval = JsFuture::from(resp.json()?).await?;
            let status: OperationError = jsval.into_serde().expect_throw("Invalid response type");
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
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(Msg::Error { emsg, kopid })
        }
    }
}

impl Component for PwModalApp {
    type Message = Msg;
    type Properties = ModalProps;

    fn create(ctx: &Context<Self>) -> Self {
        console::log!("pw modal create");

        PwModalApp {
            state: PwState::Init,
            pw_check: PwCheck::Init,
            pw_val: "".to_string(),
            pw_check_val: "".to_string(),
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::log!("pw modal::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::log!("pw modal::update");
        match msg {
            Msg::PasswordCheck => {
                let pw =
                    utils::get_value_from_element_id("password").unwrap_or_else(|| "".to_string());
                let check = utils::get_value_from_element_id("password-check")
                    .unwrap_or_else(|| "".to_string());

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

                let pw =
                    utils::get_value_from_element_id("password").unwrap_or_else(|| "".to_string());
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
                EventBus::dispatcher().send(EventBusMsg::UpdateStatus { status });
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
        console::log!("pw modal::rendered");
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        console::log!("pw modal::destroy");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        console::log!("pw modal::view");

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

        let submit_enabled = match (&self.state, &self.pw_check) {
            (PwState::Feedback(_), PwCheck::Valid) | (PwState::Init, PwCheck::Valid) => true,
            _ => false,
        };

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
                        onsubmit={ ctx.link().callback(move |e: FocusEvent| {
                            console::log!("pw modal::on form submit prevent default");
                            e.prevent_default();
                            if submit_enabled {
                                Msg::PasswordSubmit
                            } else {
                                Msg::PasswordCancel
                            }
                        } ) }
                    >
                      <label for="password" class="form-label">{ "Enter New Password" }</label>
                      <input
                        type="password"
                        class={ pw_class }
                        id="password"
                        placeholder=""
                        aria-describedby="password-validation-feedback"
                        value={ pw_val }
                        required=true
                        oninput={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::PasswordCheck
                                })
                        }
                      />
                      { pw_feedback }
                      <label for="password-check" class="form-label">{ "Repeat Password" }</label>
                      <input
                        type="password"
                        class={ pw_check_class }
                        id="password-check"
                        placeholder=""
                        aria-describedby="password-check-feedback"
                        value={ pw_check_val }
                        required=true
                        oninput={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::PasswordCheck
                                })
                        }
                      />
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
