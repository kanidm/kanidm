use compact_jwt::{Jws, JwsUnverified};
use kanidm_proto::v1::{SingleStringRequest, UserAuthToken};
use std::str::FromStr;
use wasm_bindgen::{JsCast, JsValue, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{FormData, HtmlFormElement};

use web_sys::{Request, RequestInit, RequestMode, Response};
use yew::prelude::*;

use crate::error::*;
use crate::utils;

pub struct ChangeUnixPassword {
    state: State,
}

#[derive(Debug, Default)]
struct FormValues {
    password_input: String,
    password_repeat_input: String,
}

impl From<FormData> for FormValues {
    fn from(data: FormData) -> Self {
        Self {
            password_input: data.get("password_input").as_string().unwrap(),
            password_repeat_input: data.get("password_repeat_input").as_string().unwrap(),
        }
    }
}

pub enum Msg {
    Submit(FormData),
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

pub enum State {
    Init,
    Error { emsg: String, kopid: Option<String> },
}

#[derive(PartialEq, Eq, Properties)]
pub struct ChangeUnixPasswordProps {
    pub token: String,
}

impl Component for ChangeUnixPassword {
    type Message = Msg;
    type Properties = ChangeUnixPasswordProps;

    fn create(_ctx: &Context<Self>) -> Self {
        Self { state: State::Init }
    }
    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::Submit(data) => {
                let fd: FormValues = data.into();
                if fd.password_input != fd.password_repeat_input {
                    return self.update(
                        ctx,
                        Msg::Error {
                            emsg: "Password fields did not match".to_string(),
                            kopid: None,
                        },
                    );
                }
                let tk = ctx.props().token.clone();
                ctx.link().send_future(async {
                    match Self::update_unix_password(tk, fd.password_input).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                false
            }
            Msg::Error { emsg, kopid } => {
                self.state = State::Error { emsg, kopid };
                true
            }
            Msg::Success => {
                utils::modal_hide_by_id(crate::constants::ID_UNIX_PASSWORDCHANGE);
                self.state = State::Init;
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let flash = match &self.state {
            State::Error { emsg, kopid } => {
                let message = match kopid {
                    Some(k) => format!("An error occured - {} - {}", emsg, k),
                    None => format!("An error occured - {} - No Operation ID", emsg),
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
        html! {
          <>
            <button type="button" class="btn btn-primary"
            data-bs-toggle="modal"
            data-bs-target={format!("#{}", crate::constants::ID_UNIX_PASSWORDCHANGE)}
            >
              { "Update your Unix Password" }
            </button>
            <div class="modal" tabindex="-1" role="dialog" id={crate::constants::ID_UNIX_PASSWORDCHANGE}>
              <div class="modal-dialog" role="document">
                  <form
                      onsubmit={
                        ctx.link().callback(|e: FocusEvent| {
                          e.prevent_default();
                          let form = e.target().and_then(|t| t.dyn_into::<HtmlFormElement>().ok()).unwrap();
                          Msg::Submit(FormData::new_with_form(&form).unwrap())
                        })
                      }
                  >
                    <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{"Update your password"}</h5>
                    </div>

                    <div class="modal-body">
                        { flash }
                        <div class="form-group">
                          <label for="password_input"> {"New Password" }</label>
                          <input
                              autofocus=true
                              class="autofocus form-control"
                              name="password_input"
                              id="password_input"
                              type="password"
                              value=""
                          />
                        </div>
                        <div class="form-group">
                          <label for="password_repeat_input"> {"Repeat Password" }</label>
                          <input
                              class="autofocus form-control"
                              name="password_repeat_input"
                              id="password_repeat_input"
                              type="password"
                              value=""
                          />
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="submit" class="btn btn-success">{ "Update Password" }</button>
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

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        false
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {}

    fn destroy(&mut self, _ctx: &Context<Self>) {}
}

impl ChangeUnixPassword {
    async fn update_unix_password(token: String, new_password: String) -> Result<Msg, FetchError> {
        let jwtu = JwsUnverified::from_str(&token).expect_throw("Invalid UAT, unable to parse");

        let uat: Jws<UserAuthToken> = jwtu
            .unsafe_release_without_verification()
            .expect_throw("Unvalid UAT, unable to release ");

        let id = uat.inner.uuid.to_string();
        let changereq_jsvalue = serde_json::to_string(&SingleStringRequest {
            value: new_password,
        })
        .map(|s| JsValue::from(&s))
        .expect_throw("Failed to change request");
        let mut opts = RequestInit::new();
        opts.method("PUT");
        opts.mode(RequestMode::SameOrigin);
        opts.body(Some(&changereq_jsvalue));

        let uri = format!("/v1/person/{}/_unix/_credential", id);

        let request = Request::new_with_str_and_init(uri.as_str(), &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");
        request
            .headers()
            .set("authorization", format!("Bearer {}", token).as_str())
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
        let status = resp.status();

        if status == 200 {
            Ok(Msg::Success)
        } else {
            let headers = resp.headers();
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(Msg::Error { emsg, kopid })
        }
    }
}
