use gloo::console;
use kanidm_proto::v1::{
    CUIntentToken, CUSessionToken, CUStatus, CredentialDetail, CredentialDetailType,
};
use uuid::Uuid;
use wasm_bindgen::{JsValue, UnwrapThrowExt};
use yew::prelude::*;
use yew_router::prelude::*;

use super::delete::DeleteApp;
use super::passkey::PasskeyModalApp;
use super::passkeyremove::PasskeyRemoveModalApp;
use super::pwmodal::PwModalApp;
use super::totpmodal::TotpModalApp;
use super::totpremove::TotpRemoveComp;
use crate::{do_request, error::*, RequestMethod};
use crate::{models, utils};

// use std::rc::Rc;

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum EventBusMsg {
    UpdateStatus { status: CUStatus },
    Error { emsg: String, kopid: Option<String> },
}

#[derive(PartialEq, Properties)]
pub struct ModalProps {
    pub token: CUSessionToken,
    pub cb: Callback<EventBusMsg>,
}

#[derive(PartialEq, Properties)]
pub struct TotpRemoveProps {
    pub token: CUSessionToken,
    pub label: String,
    pub cb: Callback<EventBusMsg>,
}

#[derive(PartialEq, Properties)]
pub struct PasskeyRemoveModalProps {
    pub token: CUSessionToken,
    pub tag: String,
    pub uuid: Uuid,
    pub cb: Callback<EventBusMsg>,
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
    cb: Callback<EventBusMsg>,
}

impl Component for CredentialResetApp {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("credential::reset::create");

        // On a page refresh/reload, should we restart a session that *may* have existed?
        // This could be achieved with local storage

        // Where did we come from?

        add_body_form_classes!();

        // Can we pre-load in a session token? This occurs when we are sent a
        // credential reset from the views UI.

        /* Were we given a token for the reset? */

        let location = ctx
            .link()
            .location()
            .expect_throw("Can't access current location");

        // TODO: the error here ... isn't always an error, when a user comes from the dashboard they don't set a cred token in the URL, probably should handle this with a *slightly* nicer error
        let query: Option<CUIntentToken> = location
            .query()
            .map_err(|e| {
                let e_msg = format!("error decoding URL parameters -> {:?}", e);
                console::error!(e_msg.as_str());
            })
            .ok();

        let m_session = models::get_cred_update_session();

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

        let cb = Callback::from({
            let link = ctx.link().clone();
            move |emsg| {
                let msg = match emsg {
                    EventBusMsg::UpdateStatus { status } => Msg::UpdateSession { status },
                    EventBusMsg::Error { emsg, kopid } => Msg::Error { emsg, kopid },
                };
                link.send_message(msg);
            }
        });

        CredentialResetApp { state, cb }
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("credential::reset::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("credential::reset::update");
        let next_state = match (msg, &self.state) {
            (Msg::Ignore, _) => None,
            (Msg::TokenSubmit, State::TokenInput) => {
                #[allow(clippy::expect_used)]
                let token = utils::get_value_from_element_id("token")
                    .expect("Unable to find an input with id=token");

                ctx.link().send_future(async {
                    match Self::exchange_intent_token(token).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                Some(State::WaitingForStatus)
            }
            (Msg::BeginSession { token, status }, State::WaitingForStatus) => {
                #[cfg(debug_assertions)]
                console::debug!(format!("begin session {:?}", status).as_str());
                Some(State::Main { token, status })
            }
            (Msg::UpdateSession { status }, State::Main { token, status: _ }) => {
                #[cfg(debug_assertions)]
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
            (Msg::Cancel, State::Main { token, status: _ }) => {
                #[cfg(debug_assertions)]
                console::debug!("msg::cancel");
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
                #[cfg(debug_assertions)]
                console::debug!(format!("Going to -> {:?}", loc));
                loc.goto(
                    &ctx.link()
                        .navigator()
                        .expect_throw("failed to read history"),
                );

                None
            }
            (Msg::Error { emsg, kopid }, _) => Some(State::Error { emsg, kopid }),
            (_, _) => {
                console::error!("CredentialResetApp state match fail on update.");
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
        #[cfg(debug_assertions)]
        console::debug!("credential::reset::rendered");
        // because sometimes bootstrap doesn't catch it, which is annoying.
        crate::utils::autofocus("token");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        #[cfg(debug_assertions)]
        console::debug!("credential::reset::view");
        match &self.state {
            State::TokenInput => self.view_token_input(ctx),
            State::WaitingForStatus | State::WaitingForCommit => self.view_waiting(ctx),
            State::Main { token, status } => self.view_main(ctx, token, status),
            State::Error { emsg, kopid } => self.view_error(ctx, emsg, kopid.as_deref()),
        }
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        #[cfg(debug_assertions)]
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
                <h2>{ "Credential Reset" } </h2>
                // TODO: replace this with a call to domain info
                // <h3>{ "idm.example.com" } </h3>
            </center>
            <form
                  onsubmit={ ctx.link().callback(|e: SubmitEvent| {
                      console::debug!("credential::reset::view_token_input -> TokenInput - prevent_default()");
                      e.prevent_default();

                      Msg::TokenSubmit
                  } ) }
                  action="javascript:void(0);">
                <p class="text-center">
                    <label for="token" class="form-label">
                    {"Enter your credential reset token."}
                    </label>
                  <input
                      id="token"
                      name="token"
                      autofocus=true
                      type="text"
                      class="form-control"
                      value=""
                  />
                </p>
                <p class="text-center">
                <button type="submit" class="btn btn-primary">{" Submit "}</button><br />
                </p>
                </form>
            <p class="text-center">
              <a href="/"><button href="/" class="btn btn-secondary" aria-label="Return home">{"Return to the home page"}</button></a>
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
        let cb = self.cb.clone();

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
                      <p>{ "✅ Password Set" }</p>
                      <p>
                        <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#staticPassword">
                          { "Change Password" }
                        </button>
                      </p>

                      <p>{ "❌ MFA Disabled" }</p>
                      <p>
                        <TotpModalApp token={ token.clone() } cb={ cb.clone() }/>
                      </p>

                      <p>
                        <button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#staticDeletePrimaryCred">
                          { "Delete this Insecure Password" }
                        </button>
                      </p>
                    </>
                }
            }
            Some(CredentialDetail {
                uuid: _,
                type_:
                    CredentialDetailType::PasswordMfa(
                        // Used for what TOTP the user has.
                        totp_set,
                        // Being deprecated.
                        _security_key_labels,
                        // Need to wire in backup codes.
                        _backup_codes_remaining,
                    ),
            }) => {
                html! {
                    <>
                      <p>{ "✅ Password Set" }</p>
                      <p>
                        <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#staticPassword">
                          { "Change Password" }
                        </button>
                      </p>

                      <p>{ "✅ MFA Enabled" }</p>

                      <>
                      { for totp_set.iter()
                          .map(|detail| html! { <TotpRemoveComp token={ token.clone() } label={ detail.clone() } cb={ cb.clone() } /> })
                      }
                      </>

                      <p>
                        <TotpModalApp token={ token.clone() } cb={ cb.clone() }/>
                      </p>

                      <p>
                        <button type="button" class="btn btn-warning" data-bs-toggle="modal" data-bs-target="#staticDeletePrimaryCred">
                          { "Delete this Legacy MFA Credential" }
                        </button>
                      </p>

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
                <>
                { for status.passkeys.iter()
                    .map(|detail|
                        PasskeyRemoveModalApp::render_button(&detail.tag, detail.uuid)
                    )
                }
                </>
            }
        };

        let passkey_modals_html = html! {
            <>
                { for status.passkeys.iter()
                    .map(|detail|
                        html! { <PasskeyRemoveModalApp token={ token.clone() } tag={ detail.tag.clone() } uuid={ detail.uuid } cb={ cb.clone() } /> }
                    )
                }
            </>
        };

        html! {
        <>
          <div class="d-flex align-items-start form-cred-reset-body">
            <main class="w-100">
              <div class="py-3 text-center">
                <h3>{ "Updating Credentials" }</h3>
                <p>{ displayname }</p>
                <p>{ spn }</p>
              </div>

              <div class="row g-3">
                  <form class="needs-validation" novalidate=true>
                    <hr class="my-4" />
                    <h4>{"Passkeys"}</h4>
                    <p>{ "Strong cryptographic authenticators with self contained multi-factor authentication." }</p>

                    { passkey_html }

                    <PasskeyModalApp token={ token.clone() } cb={ cb.clone() } />

                    <hr class="my-4" />

                    <h4>{"Password / TOTP"}</h4>
                    <p>{ "Legacy password paired with other authentication factors." }</p>
                    <p>{ "It is recommended you avoid setting these if possible, as these can be phished or exploited." }</p>
                    { pw_html }

                    <hr class="my-4" />

                    <button class="w-50 btn btn-danger btn-lg"
                        disabled=false
                        onclick={
                            ctx.link()
                            .callback(move |_| {
                                Msg::Cancel
                            })
                        }
                        >{ "Cancel" }</button>
                    <button
                        class="w-50 btn btn-success btn-lg"
                        disabled={ !can_commit }
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::Commit
                                })
                        }
                        type="submit"
                        >{ "Submit Changes" }</button>
                  </form>
              </div>
            </main>


            <PwModalApp token={ token.clone() } cb={ cb.clone() } />

            <DeleteApp token= { token.clone() } cb={ cb.clone() }/>

            { passkey_modals_html }

          </div>
          { crate::utils::do_footer() }
          </>
        }
    }

    fn view_error(&self, _ctx: &Context<Self>, msg: &str, kopid: Option<&str>) -> Html {
        html! {
          <main class="form-signin">
            <p class="text-center">
                <img src="/pkg/img/logo-square.svg" alt="Kanidm" class="kanidm_logo"/>
            </p>
            <div class="alert alert-danger" role="alert">
              <h2>{ "An Error Occurred 🥺" }</h2>
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
            <p class="text-center">
              <a href="/"><button href="/" class="btn btn-secondary" aria-label="Return home">{"Return to the home page"}</button></a>
            </p>
          </main>
        }
    }

    async fn exchange_intent_token(token: String) -> Result<Msg, FetchError> {
        let req_jsvalue = serde_json::to_string(&CUIntentToken { token })
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise intent request");

        let (kopid, status, value, _) = do_request(
            "/v1/credential/_exchange_intent",
            RequestMethod::POST,
            Some(req_jsvalue),
        )
        .await?;

        if status == 200 {
            let (token, status): (CUSessionToken, CUStatus) =
                serde_wasm_bindgen::from_value(value).expect_throw("Invalid response type");
            Ok(Msg::BeginSession { token, status })
        } else {
            let emsg = value.as_string().unwrap_or_default();
            Ok(Msg::Error { emsg, kopid })
        }
    }

    async fn end_session(token: CUSessionToken, url: &str) -> Result<Msg, FetchError> {
        let req_jsvalue = serde_json::to_string(&token)
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise session token");

        let (kopid, status, value, _) =
            do_request(url, RequestMethod::POST, Some(req_jsvalue)).await?;

        if status == 200 {
            Ok(Msg::Success)
        } else {
            let emsg = value.as_string().unwrap_or_default();
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
