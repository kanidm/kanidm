use crate::error::*;
use crate::models;
use crate::utils;

use gloo::console;
use yew::prelude::*;
use yew_agent::{Bridge, Bridged};
use yew_router::prelude::*;

use kanidm_proto::v1::{
    CUIntentToken, CUSessionToken, CUStatus, CredentialDetail, CredentialDetailType,
};

use wasm_bindgen::{JsCast, JsValue, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use super::delete::DeleteApp;
use super::eventbus::{EventBus, EventBusMsg};
use super::passkey::PasskeyModalApp;
use super::passkeyremove::PasskeyRemoveModalApp;
use super::pwmodal::PwModalApp;
use super::totpmodal::TotpModalApp;

use uuid::Uuid;

#[derive(PartialEq, Properties)]
pub struct ModalProps {
    pub token: CUSessionToken,
}

#[derive(PartialEq, Properties)]
pub struct PasskeyRemoveModalProps {
    pub token: CUSessionToken,
    pub tag: String,
    pub uuid: Uuid,
}

pub enum Msg {
    TokenSubmit,
    BeginSession {
        token: CUSessionToken,
        status: CUStatus,
    },
    UpdateSession {
        status: CUStatus,
    },
    Cancel,
    Commit,
    Success,
    Error {
        emsg: String,
        kopid: Option<String>,
    },
    // TODO: use this? :)
    #[allow(dead_code)]
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

#[allow(clippy::large_enum_variant)]
//Page state
enum State {
    TokenInput,
    WaitingForStatus,
    Main {
        token: CUSessionToken,
        status: CUStatus,
    },
    WaitingForCommit,
    #[allow(clippy::large_enum_variant)]
    Error {
        emsg: String,
        kopid: Option<String>,
    },
}

pub struct CredentialResetApp {
    state: State,
    // TODO: I'm sure past-William had a plan for this 🚌
    #[allow(dead_code)]
    eventbus: Box<dyn Bridge<EventBus>>,
}

impl Component for CredentialResetApp {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        console::debug!("credential::reset::create");

        // On a page refresh/reload, should we restart a session that *may* have existed?
        // This could be achieved with local storage

        // Where did we come from?

        add_body_form_classes!();

        // Can we pre-load in a session token? This occures when we are sent a
        // credential reset from the views UI.

        /* Were we given a token for the reset? */

        let location = ctx
            .link()
            .location()
            .expect_throw("Can't access current location");

        let query: Option<CUIntentToken> = location
            .query()
            .map_err(|e| {
                let e_msg = format!("query decode error -> {:?}", e);
                console::error!(e_msg.as_str());
            })
            .ok();

        let m_session = models::pop_cred_update_session();

        let state = match (query, m_session) {
            (Some(cu_intent), None) => {
                // Go straight to go! Collect 200!
                ctx.link().send_future(async {
                    match Self::exchange_intent_token(cu_intent.token).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                State::WaitingForStatus
            }
            (None, Some((token, status))) => State::Main { token, status },
            (None, None) => State::TokenInput,
            (Some(_), Some(_)) => State::Error {
                emsg: "Invalid State - Reset link and memory session both are available!"
                    .to_string(),
                kopid: None,
            },
        };

        let eventbus = EventBus::bridge(ctx.link().callback(|req| match req {
            EventBusMsg::UpdateStatus { status } => Msg::UpdateSession { status },
            EventBusMsg::Error { emsg, kopid } => Msg::Error { emsg, kopid },
        }));

        CredentialResetApp { state, eventbus }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::debug!("credential::reset::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::debug!("credential::reset::update");
        let next_state = match (msg, &self.state) {
            (Msg::Ignore, _) => None,
            (Msg::TokenSubmit, State::TokenInput) => {
                #[allow(clippy::expect_used)]
                let token = utils::get_value_from_element_id("autofocus")
                    .expect("Unable to find autofocus element");

                ctx.link().send_future(async {
                    match Self::exchange_intent_token(token).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                Some(State::WaitingForStatus)
            }
            (Msg::BeginSession { token, status }, State::WaitingForStatus) => {
                console::debug!(format!("{:?}", status).as_str());
                Some(State::Main { token, status })
            }
            (Msg::UpdateSession { status }, State::Main { token, status: _ }) => {
                console::debug!(format!("{:?}", status).as_str());
                Some(State::Main {
                    token: token.clone(),
                    status,
                })
            }
            (Msg::Commit, State::Main { token, status }) => {
                console::debug!(format!("{:?}", status).as_str());
                let token_c = token.clone();

                ctx.link().send_future(async {
                    match Self::commit_session(token_c).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                Some(State::WaitingForCommit)
            }
            (Msg::Cancel, State::Main { token, status }) => {
                console::debug!(format!("{:?}", status).as_str());
                let token_c = token.clone();

                ctx.link().send_future(async {
                    match Self::cancel_session(token_c).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                Some(State::WaitingForCommit)
            }
            (Msg::Success, State::WaitingForCommit) => {
                let loc = models::pop_return_location();
                console::debug!(format!("Going to -> {:?}", loc));
                loc.goto(&ctx.link().history().expect_throw("failed to read history"));

                None
            }
            (Msg::Error { emsg, kopid }, _) => Some(State::Error { emsg, kopid }),
            (_, _) => {
                console::debug!("CredentialResetApp state match fail on update.");
                None
            }
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
        console::debug!("credential::reset::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        console::debug!("credential::reset::view");
        match &self.state {
            State::TokenInput => self.view_token_input(ctx),
            State::WaitingForStatus | State::WaitingForCommit => self.view_waiting(ctx),
            State::Main { token, status } => self.view_main(ctx, token, status),
            State::Error { emsg, kopid } => self.view_error(ctx, emsg, kopid.as_deref()),
        }
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        console::debug!("credential::reset::destroy");
        remove_body_form_classes!();
    }
}

impl CredentialResetApp {
    fn view_token_input(&self, ctx: &Context<Self>) -> Html {
        html! {
        <main class="flex-shrink-0 form-signin">
            <center>
                <img src="/pkg/img/logo-square.svg" alt="Kanidm" class="kanidm_logo"/>
                // TODO: replace this with a call to domain info
                <h3>{ "Kanidm idm.example.com" } </h3>
            </center>
              <p>
                {"Enter your credential reset token"}
              </p>
            <form
                  onsubmit={ ctx.link().callback(|e: FocusEvent| {
                      console::debug!("credential::reset::view_token_input -> TokenInput - prevent_default()");
                      e.prevent_default();

                      Msg::TokenSubmit
                  } ) }
                  action="javascript:void(0);">
                  <input
                      id="autofocus"
                      type="text"
                      class="form-control"
                      value=""
                  />
                  <button type="submit" class="btn btn-dark">{" Submit "}</button><br />
              </form>
              <p>
              <a href="/"><button href="/" class="btn btn-dark" aria-label="Return home">{"Return to the home page"}</button></a>
              </p>

          </main>
        }
    }

    fn view_waiting(&self, _ctx: &Context<Self>) -> Html {
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

    fn view_main(&self, ctx: &Context<Self>, token: &CUSessionToken, status: &CUStatus) -> Html {
        remove_body_form_classes!();

        let displayname = status.displayname.clone();
        let spn = status.spn.clone();

        let can_commit = status.can_commit;

        // match on primary, get type_.
        // FUTURE: Need to work out based on policy if this is shown!

        let pw_html = match &status.primary {
            Some(CredentialDetail {
                uuid: _,
                type_: CredentialDetailType::Password,
            }) => {
                html! {
                    <>
                      <p>{ "Password Set" }</p>
                      <p>{ "Mfa Disabled" }</p>

                      <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#staticTotpCreate">
                        { "Add TOTP" }
                      </button>

                      <button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#staticDeletePrimaryCred">
                        { "Delete this Password" }
                      </button>
                    </>
                }
            }
            Some(CredentialDetail {
                uuid: _,
                type_: CredentialDetailType::GeneratedPassword,
            }) => {
                html! {
                  <>
                    <p>{ "Generated Password" }</p>
                    <button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#staticDeletePrimaryCred">
                      { "Delete this Password" }
                    </button>
                  </>
                }
            }
            Some(CredentialDetail {
                uuid: _,
                type_: CredentialDetailType::Passkey(_),
            }) => {
                html! {
                  <>
                    <p>{ "Webauthn Only - Will migrate to Passkeys in a future update" }</p>
                    <button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#staticDeletePrimaryCred">
                      { "Delete this Credential" }
                    </button>
                  </>
                }
            }
            Some(CredentialDetail {
                uuid: _,
                type_:
                    // TODO: review this and find out why we aren't using these variables
                    // Because I'm lazy 🙃
                    CredentialDetailType::PasswordMfa(
                        _totp_set,
                        _security_key_labels,
                        _backup_codes_remaining,
                    ),
            }) => {
                html! {
                    <>
                      <p>{ "Password Set" }</p>
                      <p>{ "Mfa Enabled" }</p>

                      <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#staticTotpCreate">
                        { "Reset TOTP" }
                      </button>

                      <button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#staticDeletePrimaryCred">
                        { "Delete this MFA Credential" }
                      </button>
                    </>
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

        let passkey_html = if status.passkeys.is_empty() {
            html! {
                <p>{ "No Passkeys Registered" }</p>
            }
        } else {
            html! {
                <div class="container">
                    <ul class="list-unstyled">
                        { for status.passkeys.iter()
                            .map(|detail|
                                PasskeyRemoveModalApp::render_button(&detail.tag, detail.uuid)
                            )
                        }
                    </ul>
                </div>
            }
        };

        let passkey_modals_html = html! {
            <>
                { for status.passkeys.iter()
                    .map(|detail|
                        html! { <PasskeyRemoveModalApp token={ token.clone() } tag={ detail.tag.clone() } uuid={ detail.uuid } /> }
                    )
                }
            </>
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

                    { passkey_html }

                    <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#staticPasskeyCreate">
                      { "Add Passkey" }
                    </button>

                    <hr class="my-4" />

                    { pw_html }

                    <hr class="my-4" />

                    <button class="w-50 btn btn-danger btn-lg" type="submit"
                        disabled=false
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::Cancel
                                })
                        }
                    >{ "Cancel" }</button>
                    <button class="w-50 btn btn-success btn-lg" type="submit"
                        disabled={ !can_commit }
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::Commit
                                })
                        }
                    >{ "Submit Changes" }</button>
                  </form>
              </div>
            </main>

            <PasskeyModalApp token={ token.clone() } />

            <PwModalApp token={ token.clone() } />

            <TotpModalApp token={ token.clone() }/>

            <DeleteApp token= { token.clone() }/>

            { passkey_modals_html }

          </div>
        }
    }

    fn view_error(&self, _ctx: &Context<Self>, msg: &str, kopid: Option<&str>) -> Html {
        html! {
          <main class="form-signin">

            <div class="alert alert-danger" role="alert">
              <h2>{ "An Error Occured 🥺" }</h2>
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
            </div>
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

    async fn end_session(token: CUSessionToken, url: &str) -> Result<Msg, FetchError> {
        let req_jsvalue = serde_json::to_string(&token)
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise session token");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);

        opts.body(Some(&req_jsvalue));

        let request = Request::new_with_str_and_init(url, &opts)?;
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
            Ok(Msg::Success)
        } else {
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(Msg::Error { emsg, kopid })
        }
    }

    async fn cancel_session(token: CUSessionToken) -> Result<Msg, FetchError> {
        Self::end_session(token, "/v1/credential/_cancel").await
    }

    async fn commit_session(token: CUSessionToken) -> Result<Msg, FetchError> {
        Self::end_session(token, "/v1/credential/_commit").await
    }
}
