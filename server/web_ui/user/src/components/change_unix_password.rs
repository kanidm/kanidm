use kanidm_proto::internal::UserAuthToken;
use kanidm_proto::v1::SingleStringRequest;
use kanidmd_web_ui_shared::constants::ID_UNIX_PASSWORDCHANGE;
use kanidmd_web_ui_shared::do_request;
use kanidmd_web_ui_shared::error::FetchError;
use kanidmd_web_ui_shared::RequestMethod;
use serde::Serialize;
use uuid::Uuid;
use wasm_bindgen::{JsCast, UnwrapThrowExt};
use web_sys::{FormData, HtmlFormElement};
use yew::prelude::*;

use kanidmd_web_ui_shared::utils::{self, modal_hide_by_id};

#[derive(PartialEq)]
enum PwCheck {
    Init,
    Valid,
    Invalid,
}

pub struct ChangeUnixPassword {
    state: State,
    pw_check: PwCheck,
    pw_val: String,
    pw_check_val: String,
}

#[derive(Debug, Default)]
struct FormValues {
    password_input: String,
}

impl From<FormData> for FormValues {
    fn from(data: FormData) -> Self {
        #[allow(clippy::expect_used)]
        Self {
            password_input: data
                .get("password_input")
                .as_string()
                .expect_throw("Failed to pull the password input field"),
        }
    }
}

pub enum Msg {
    Submit(FormData),
    Error { emsg: String, kopid: Option<String> },
    Success,
    PasswordCheck,
}

impl From<FetchError> for Msg {
    fn from(fe: FetchError) -> Self {
        Msg::Error {
            emsg: fe.as_string(),
            kopid: None,
        }
    }
}

pub enum State {
    Init,
    Error { emsg: String, kopid: Option<String> },
}

#[derive(PartialEq, Eq, Properties)]
pub struct ChangeUnixPasswordProps {
    pub uat: UserAuthToken,
    pub enabled: bool,
}

impl Component for ChangeUnixPassword {
    type Message = Msg;
    type Properties = ChangeUnixPasswordProps;

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            state: State::Init,
            pw_check: PwCheck::Init,
            pw_val: "".to_string(),
            pw_check_val: "".to_string(),
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::Submit(data) => {
                let fd: FormValues = data.into();
                let id = ctx.props().uat.uuid;

                ctx.link().send_future(async move {
                    match Self::update_unix_password(id, fd.password_input).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                false
            }
            Msg::Error { emsg, kopid } => {
                self.reset();
                self.state = State::Error { emsg, kopid };
                self.pw_check = PwCheck::Init;
                true
            }
            Msg::Success => {
                self.reset();
                modal_hide_by_id(ID_UNIX_PASSWORDCHANGE);
                self.state = State::Init;
                true
            }
            Msg::PasswordCheck => {
                let pw = utils::get_value_from_element_id("password_input").unwrap_or_default();
                let check =
                    utils::get_value_from_element_id("password_repeat_input").unwrap_or_default();

                if pw == check {
                    self.pw_check = PwCheck::Valid
                } else {
                    self.pw_check = PwCheck::Invalid
                }
                self.pw_val = pw;
                self.pw_check_val = check;
                true
            }
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        false
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let flash = match &self.state {
            State::Error { emsg, kopid } => {
                let message = match kopid {
                    Some(k) => format!("An error occurred - {} - {}", emsg, k),
                    None => format!("An error occurred - {} - No Operation ID", emsg),
                };
                html! {
                  <div class="alert alert-danger alert-dismissible fade show" role="alert">
                    { message }
                    <button type="button" class="btn btn-close" data-dismiss="alert" aria-label="Close"></button>
                  </div>
                }
            }
            _ => html! { <></> },
        };

        let submit_enabled = self.pw_check == PwCheck::Valid;
        let button_enabled = ctx.props().enabled;

        let pw_val = self.pw_val.clone();
        let pw_check_val = self.pw_check_val.clone();
        let pw_check_class = match &self.pw_check {
            PwCheck::Init | PwCheck::Valid => classes!("form-control"),
            PwCheck::Invalid => classes!("form-control", "is-invalid"),
        };

        html! {
          <>
            <button type="button" class="btn btn-primary"
              disabled={ !button_enabled }
              data-bs-toggle="modal"
              data-bs-target={format!("#{}", ID_UNIX_PASSWORDCHANGE)}
            >
              { "Update your Unix Password" }
            </button>
            <div class="modal" tabindex="-1" role="dialog" id={ID_UNIX_PASSWORDCHANGE}>
              <div class="modal-dialog" role="document">
                  <form
                      onsubmit={
                        ctx.link().callback(|e: SubmitEvent| {
                          e.prevent_default();
                          #[allow(clippy::expect_used)]
                          let form = e.target().and_then(|t| t.dyn_into::<HtmlFormElement>().ok()).expect("Failed to pull the form data from the browser");
                          #[allow(clippy::expect_used)]
                          Msg::Submit(FormData::new_with_form(&form).expect("Failed to send the form data across the channel"))
                        })
                      }
                  >
                    <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{"Update your unix password"}</h5>
                    </div>

                    <div class="modal-body">
                        <p> { "This password is used when logging into a unix-like system as well as applications utilizing LDAP" } </p>
                        { flash }
                        <div class="form-group">
                          <label for="password_input"> {"New Password" }</label>
                          <input
                              autofocus=true
                              class="autofocus form-control"
                              name="password_input"
                              id="password_input"
                              type="password"
                              value={ pw_val }
                              oninput={
                                  ctx.link()
                                  .callback(move |_| {
                                      Msg::PasswordCheck
                                  })
                              }
                          />
                        </div>
                        <div class="form-group">
                          <label for="password_repeat_input"> {"Repeat Password" }</label>
                          <input
                              class={ pw_check_class }
                              name="password_repeat_input"
                              id="password_repeat_input"
                              type="password"
                              value={ pw_check_val }
                              oninput={
                                  ctx.link()
                                  .callback(move |_| {
                                      Msg::PasswordCheck
                                  })
                              }
                          />
                              <div class="invalid-feedback">
                                  { "Passwords do not match." }
                              </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="submit" class="btn btn-success" disabled={ !submit_enabled }>{ "Update Password" }</button>
                        <button type="button" class="btn btn-secondary"
                        onclick={
                          ctx.link().callback(|_e| {
                              Msg::Success
                          })
                        }
                        >{"Cancel"}</button>
                    </div>
                    </div>
                  </form>
              </div>
            </div>
          </>
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {}

    fn destroy(&mut self, _ctx: &Context<Self>) {}
}

impl ChangeUnixPassword {
    async fn update_unix_password(id: Uuid, new_password: String) -> Result<Msg, FetchError> {
        let req = SingleStringRequest {
            value: new_password,
        };
        let req_jsvalue = req
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .expect("Failed to serialise request");
        let req_jsvalue = js_sys::JSON::stringify(&req_jsvalue).expect_throw("failed to stringify");

        let uri = format!("/v1/person/{}/_unix/_credential", id);
        let (kopid, status, value, _) =
            do_request(&uri, RequestMethod::PUT, Some(req_jsvalue)).await?;

        if status == 200 {
            Ok(Msg::Success)
        } else {
            let emsg = value.as_string().unwrap_or_default();
            Ok(Msg::Error { emsg, kopid })
        }
    }

    fn reset(&mut self) {
        self.pw_val = "".to_string();
        self.pw_check_val = "".to_string();
        self.pw_check = PwCheck::Init;
    }
}
