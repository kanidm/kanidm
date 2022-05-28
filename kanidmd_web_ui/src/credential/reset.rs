use crate::utils;
use gloo::console;
use yew::prelude::*;
use yew_router::prelude::*;

use kanidm_proto::v1::{
    CUIntentToken, CURegState, CUSessionToken, CUStatus, CredentialDetail, CredentialDetailType, CURequest
};
use wasm_bindgen::UnwrapThrowExt;

use qrcode::{render::svg, QrCode};

use crate::error::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, RequestRedirect, Response};

pub enum Msg {
    TokenSubmit,
    BeginSession {
        token: CUSessionToken,
        status: CUStatus,
    },
    UpdateSession {
        status: CUStatus,
    },
    Error {
        emsg: String,
        kopid: Option<String>,
    },
    PasswordInput,
    PasswordResponseSuccess { status: CUStatus },
    // PasswordCheck { check: bool },
    Ignore,
}

impl From<FetchError> for Msg {
    fn from(fe: FetchError) -> Self {
        Msg::Error {
            emsg: fe.as_string(),
            kopid: None,
        }
    }
}

enum State {
    TokenInput,
    WaitingForStatus,
    Main {
        token: CUSessionToken,
        status: CUStatus,
    },
    Error {
        emsg: String,
        kopid: Option<String>,
    },
}

pub struct CredentialResetApp {
    state: State,
}

impl Component for CredentialResetApp {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        console::log!("credential::reset::create");

        // Inject our class to centre everything.
        if let Err(e) = crate::utils::body().class_list().add_1("form-signin-body") {
            console::log!(format!("class_list add error -> {:?}", e));
        };

        // Can we pre-load in a session token?

        /* Were we given a token for the reset? */

        let location = ctx
            .link()
            .location()
            .expect_throw("Can't access current location");

        let query: Option<CUIntentToken> = location
            .query()
            .map_err(|e| {
                let e_msg = format!("query decode error -> {:?}", e);
                console::log!(e_msg.as_str());
            })
            .ok();

        let state = match query {
            Some(cu_intent) => {
                // Go straight to go! Collect 200!
                ctx.link().send_future(async {
                    match Self::exchange_intent_token(cu_intent.token).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                State::WaitingForStatus
            }
            None => State::TokenInput,
        };

        /*
        let state = State::Main {
            token: CUSessionToken {
                token: "invalid".to_string(),
            },
            status: CUStatus {
                spn: "placeholder@example.com".to_string(),
                displayname: "Lorum Ipsum Fuck You".to_string(),
                can_commit: false,
                primary: None,
                mfaregstate: CURegState::None,
            },
        };
        */

        CredentialResetApp { state }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::log!("credential::reset::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::log!("credential::reset::update");
        let next_state = match (msg, &self.state) {
            (Msg::Ignore, _) => None,
            (Msg::TokenSubmit, State::TokenInput) => {
                let token = utils::get_value_from_element_id("autofocus").expect("No token");

                ctx.link().send_future(async {
                    match Self::exchange_intent_token(token).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                Some(State::WaitingForStatus)
            }
            (Msg::BeginSession { token, status }, State::WaitingForStatus) => {
                console::log!(format!("{:?}", status).as_str());
                Some(State::Main { token, status })
            }
            (Msg::PasswordInput, State::Main { token, status: _ }) => {
                console::log!("credential::reset::update - password input");

                let pw_input = utils::get_inputelement_by_id("password")
                    .unwrap_throw();
                let ck_input = utils::get_inputelement_by_id("password-check")
                    .unwrap_throw();
                let submit = utils::get_buttonelement_by_id("password-submit")
                    .unwrap_throw();
                let cancel = utils::get_buttonelement_by_id("password-cancel")
                    .unwrap_throw();

                pw_input.set_disabled(true);
                ck_input.set_disabled(true);
                submit.set_disabled(true);
                cancel.set_disabled(true);

                let pw = utils::get_value_from_element_id("password").unwrap_or_else(|| "".to_string());

                let token_c = token.clone();

                // Okay send of the request to the server.
                ctx.link().send_future(async {
                    match Self::submit_password_update(token_c, pw).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                None
            }
            // Msg::PasswordResponseError
            // Msg::PasswordResponseQuality
            // Msg::PasswordResponseSuccess
            (Msg::PasswordResponseSuccess { status }, State::Main { token, status: _ }) => {
                console::log!("credential::reset::update - password response success");
                utils::modal_hide_by_id("staticPassword");

                let pw_input = utils::get_inputelement_by_id("password")
                    .unwrap_throw();
                let ck_input = utils::get_inputelement_by_id("password-check")
                    .unwrap_throw();
                let submit = utils::get_buttonelement_by_id("password-submit")
                    .unwrap_throw();
                let cancel = utils::get_buttonelement_by_id("password-cancel")
                    .unwrap_throw();

                pw_input.set_disabled(false);
                pw_input.set_value("");
                ck_input.set_disabled(false);
                ck_input.set_value("");
                submit.set_disabled(true);
                cancel.set_disabled(false);

                // If the submit was valid, we need to reset the forms because just
                // hiding the modal DOES NOT do this!!!
                Some(State::Main { token: token.clone(), status })
            }
            /*
            (Msg::PasswordCheck { pw, check }, State::Main { token, status: _ }) => {
                // Update this in real time.
                console::log!("credential::reset::update - password check");
                None
            }
            */
            (Msg::Error { emsg, kopid }, _) => Some(State::Error { emsg, kopid }),
            (_, _) => unreachable!(),
        };

        if let Some(mut next_state) = next_state {
            std::mem::swap(&mut self.state, &mut next_state);
            true
        } else {
            false
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        crate::utils::autofocus();
        console::log!("credential::reset::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        console::log!("credential::reset::view");
        match &self.state {
            State::TokenInput => self.view_token_input(ctx),
            State::WaitingForStatus => self.view_waiting(ctx),
            State::Main { token, status } => self.view_main(ctx, &status),
            State::Error { emsg, kopid } => self.view_error(ctx, &emsg, kopid.as_deref()),
        }
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        console::log!("credential::reset::destroy");
        if let Err(e) = crate::utils::body()
            .class_list()
            .remove_1("form-signin-body")
        {
            console::log!(format!("class_list remove error -> {:?}", e));
        }
    }
}

impl CredentialResetApp {
    fn view_token_input(&self, ctx: &Context<Self>) -> Html {
        html! {
          <main class="form-signin">
            <div class="container">
              <p>
                {"Enter your credential reset token"}
              </p>
            </div>
            <div class="container">
              <form
                  onsubmit={ ctx.link().callback(|e: FocusEvent| {
                      console::log!("credential::reset::view_token_input -> TokenInput - prevent_default()");
                      e.prevent_default();

                      Msg::TokenSubmit
                  } ) }
                  action="javascript:void(0);"
              >
                  <input
                      id="autofocus"
                      type="text"
                      class="form-control"
                      value=""
                  />
                  <button type="submit" class="btn btn-dark">{" Submit "}</button>
              </form>
            </div>
          </main>
        }
    }

    fn view_waiting(&self, ctx: &Context<Self>) -> Html {
        html! {
          <main class="text-center form-signin h-100">
            <div class="vert-center">
              <div class="spinner-border text-dark" role="status">
                <span class="visually-hidden">{ "Loading..." }</span>
              </div>
            </div>
          </main>
        }
    }

    fn view_main(&self, ctx: &Context<Self>, status: &CUStatus) -> Html {
        if let Err(e) = crate::utils::body()
            .class_list()
            .remove_1("form-signin-body")
        {
            console::log!(format!("class_list remove error -> {:?}", e));
        }

        let displayname = status.displayname.clone();
        let spn = status.spn.clone();

        let can_commit = status.can_commit;

        // match on primary, get type_.
        // FUTURE: Need to work out based on policy if this is shown!

        let pw_html = match &status.primary {
            Some(CredentialDetail {
                uuid: _,
                claims,
                type_: CredentialDetailType::Password,
            }) => {
                html! {
                    <p>{ "Password Set" }</p>
                }
            }
            Some(CredentialDetail {
                uuid: _,
                claims,
                type_: CredentialDetailType::GeneratedPassword,
            }) => {
                html! {
                    <p>{ "Genie" }</p>
                }
            }
            Some(CredentialDetail {
                uuid: _,
                claims,
                type_: CredentialDetailType::Webauthn(_),
            }) => {
                html! {
                    <p>{ "Invalid!" }</p>
                }
            }
            Some(CredentialDetail {
                uuid: _,
                claims,
                type_:
                    CredentialDetailType::PasswordMfa(
                        totp_set,
                        security_key_labels,
                        backup_codes_remaining,
                    ),
            }) => {
                html! {
                    <p>{ "Mfa" }</p>
                }
            }
            None => {
                html! {
                    <button type="button" class="btn btn-warning" data-bs-toggle="modal" data-bs-target="#staticPassword">
                      { "Add Password" }
                    </button>
                }
            }
        };

        html! {
          <div class="d-flex align-items-start form-cred-reset-body">
            <main class="w-100">
              <div class="py-5 text-center">
                <h4>{ "Updating Credentials" }</h4>
                <p>{ displayname }</p>
                <p>{ spn }</p>
              </div>

              <div class="row g-3">
                  <form class="needs-validation" novalidate=true>
                    <hr class="my-4" />

                    <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#staticTrustedDevice">
                      { "Add New Trusted Device" }
                    </button>

                    <hr class="my-4" />

                    { pw_html }

                    <hr class="my-4" />
                    <button class="w-100 btn btn-success btn-lg" type="submit" disabled=true>{ "Submit Changes" }</button>
                  </form>
              </div>
            </main>

            <div class="modal fade" id="staticTrustedDevice" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticTrustedDeviceLabel" aria-hidden="true">
              <div class="modal-dialog modal-lg">
                <div class="modal-content">
                  <div class="modal-header">
                    <h5 class="modal-title" id="staticTrustedDeviceLabel">{ "Add a Trusted Device" }</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                  </div>
                  <div class="modal-body">
                    <p>{ "Scan the following link to add a new device" }</p>

                    <div class="spinner-border text-success" role="status">
                      <span class="visually-hidden">{ "Loading..." }</span>
                    </div>
                  </div>

                  <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">{ "Cancel" }</button>
                    <button type="button" class="btn btn-primary">{ "Submit" }</button>
                  </div>
                </div>
              </div>
            </div>

            <div class="modal fade" id="staticPassword" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticPasswordLabel" aria-hidden="true">
              <div class="modal-dialog">
                <div class="modal-content">
                  <div class="modal-header">
                    <h5 class="modal-title" id="staticPasswordLabel">{ "Add a New Password" }</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                  </div>
                  <div class="modal-body">
                    <form class="row g-3 needs-validation" novalidate=true>
                      <label for="password" class="form-label">{ "Enter New Password" }</label>
                      <input
                        type="password"
                        class="form-control"
                        id="password"
                        placeholder=""
                        value=""
                        aria-describedby="password-validation-feedback"
                        required=true
                        oninput={ password_modal_check_inputs }
                      />
                      <div id="password-validation-feedback" class="invalid-feedback">
                        { "Make Stronger" }
                      </div>
                      <label for="password-check" class="form-label">{ "Repeat Password" }</label>
                      <input
                        type="password"
                        class="form-control"
                        id="password-check"
                        placeholder=""
                        value=""
                        aria-describedby="password-check-feedback"
                        required=true
                        oninput={ password_modal_check_inputs }
                      />
                      <div id="password-check-feedback" class="invalid-feedback">
                        { "Passwords do not match" }
                      </div>
                    </form>
                  </div>
                  <div class="modal-footer">
                    <button id="password-cancel" type="button" class="btn btn-secondary" data-bs-dismiss="modal">{ "Cancel" }</button>
                    <button id="password-submit" type="button" class="btn btn-primary"
                        disabled=true
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::PasswordInput
                                })
                        }
                    >{ "Submit" }</button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        }
    }

    fn view_error(&self, ctx: &Context<Self>, msg: &str, kopid: Option<&str>) -> Html {
        html! {
          <main class="form-signin">
            <div class="container">
              <h2>{ "An Error Occured 🥺" }</h2>
            </div>
            <p>{ msg.to_string() }</p>
            <p>
                {
                    if let Some(opid) = kopid.as_ref() {
                        format!("Operation ID: {}", opid)
                    } else {
                        "Local Error".to_string()
                    }
                }
            </p>
          </main>
        }
    }

    async fn exchange_intent_token(token: String) -> Result<Msg, FetchError> {
        let intentreq_jsvalue = serde_json::to_string(&CUIntentToken { token })
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise intent request");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);

        opts.body(Some(&intentreq_jsvalue));

        let request = Request::new_with_str_and_init("/v1/credential/_exchange_intent", &opts)?;
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
            let (token, status): (CUSessionToken, CUStatus) =
                jsval.into_serde().expect_throw("Invalid response type");
            Ok(Msg::BeginSession { token, status })
        } else {
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(Msg::Error { emsg, kopid })
        }
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
            let status: CUStatus =
                jsval.into_serde().expect_throw("Invalid response type");
            Ok(Msg::PasswordResponseSuccess { status })
        } else {
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(Msg::Error { emsg, kopid })
        }
        
    }
}

fn password_modal_check_inputs(e: InputEvent) -> () {
    let pw = utils::get_value_from_element_id("password").unwrap_or_else(|| "".to_string());
    let check = utils::get_value_from_input_event(e);

    console::log!("credential::reset::update - password check");

    match utils::get_element_by_id("password-check") {
        Some(elem) => {
            let _ = elem.class_list().remove_1("is-valid");
            let _ = elem.class_list().remove_1("is-invalid");
            let submit = utils::get_buttonelement_by_id("password-submit")
                .unwrap_throw();
            if pw == check {
                let _ = elem.class_list().add_1("is-valid");
                submit.set_disabled(false);
            } else {
                let _ = elem.class_list().add_1("is-invalid");
                submit.set_disabled(true);
            }
        }
        None => unreachable!(),
    };
    // Based on this, we can enable/disable the submit button.

}







