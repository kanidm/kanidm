use gloo::console;
use kanidm_proto::internal::{
    CUCredState, CUExtPortal, CUIntentToken, CURegWarning, CUSessionToken, CUStatus,
    CredentialDetail, CredentialDetailType, PasskeyDetail,
};

use kanidmd_web_ui_shared::constants::URL_USER_HOME;
use kanidmd_web_ui_shared::models::{get_cred_update_session, pop_return_location};
use kanidmd_web_ui_shared::utils::{autofocus, do_footer};
use kanidmd_web_ui_shared::{add_body_form_classes, logo_img, remove_body_form_classes};
use serde::Serialize;
use uuid::Uuid;
use wasm_bindgen::UnwrapThrowExt;
use yew::prelude::*;
use yew_router::prelude::*;

use super::delete::DeleteApp;
use super::passkey::PasskeyModalApp;
use super::passkeyremove::PasskeyRemoveModalApp;
use super::pwmodal::PwModalApp;
use super::totpmodal::TotpModalApp;
use super::totpremove::TotpRemoveComp;
use kanidmd_web_ui_shared::ui::error_page;
use kanidmd_web_ui_shared::{do_request, error::FetchError, utils, RequestMethod};

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

#[derive(PartialEq)]
pub enum PasskeyClass {
    Any,
    Attested,
}

#[derive(PartialEq, Properties)]
pub struct PasskeyModalProps {
    pub token: CUSessionToken,
    pub class: PasskeyClass,
    pub allowed_devices: Option<Vec<String>>,
    pub cb: Callback<EventBusMsg>,
}

#[derive(PartialEq, Properties)]
pub struct PasskeyRemoveModalProps {
    pub token: CUSessionToken,
    pub class: PasskeyClass,
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

        let m_session = get_cred_update_session();

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
                let loc = pop_return_location();
                #[cfg(debug_assertions)]
                console::debug!(["Successful, redirecting to -> ", &loc].concat());
                let window = gloo_utils::window();
                window.location().set_href(&loc.to_string()).unwrap_throw();
                None
            }
            (Msg::Error { emsg, kopid }, _) => Some(State::Error { emsg, kopid }),
            (_, _) => {
                console::error!("CredentialResetApp state match fail on update!");
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
        autofocus("token");
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
                {logo_img()}
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
              <a href={URL_USER_HOME}><button href={URL_USER_HOME} class="btn btn-secondary" aria-label="Return home">{"Return to the home page"}</button></a>
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

        let CUStatus {
            spn,
            displayname,
            ext_cred_portal,
            mfaregstate: _,
            can_commit,
            warnings,
            primary,
            primary_state,
            passkeys,
            passkeys_state,
            attested_passkeys,
            attested_passkeys_state,
            attested_passkeys_allowed_devices,
            unixcred: _,
            unixcred_state: _,
        } = status;

        let (username, domain) = spn.split_once('@').unwrap_or(("", spn));
        let names = format!("{} ({})", displayname, username);
        let cb = self.cb.clone();

        let ext_cred_portal_html = match ext_cred_portal {
            CUExtPortal::None => html! { <></> },
            CUExtPortal::Hidden => html! {
                <>
                  <hr class="my-4" />
                  <p>{ "This account is externally managed. Some features may not be available." }</p>
                </>
            },
            CUExtPortal::Some(url) => {
                let url_str = url.as_str().to_string();
                html! {
                    <>
                      <hr class="my-4" />
                      <p>{ "This account is externally managed. Some features may not be available." }</p>
                      <a href={ url_str } >{ "Visit the external account portal" }</a>
                    </>
                }
            }
        };

        let pw_html = self.view_primary(token, primary, *primary_state);
        let passkey_html = self.view_passkeys(token, passkeys, *passkeys_state);
        let attested_passkey_html = self.view_attested_passkeys(
            token,
            attested_passkeys,
            *attested_passkeys_state,
            attested_passkeys_allowed_devices.as_slice(),
        );

        let warnings_html = if warnings.is_empty() {
            html! { <></> }
        } else {
            html! {
                <>
                    <hr class="my-4" />

                    { for warnings.iter()
                        .map(|warning|
                            match warning {
                                CURegWarning::MfaRequired => html! {
                                    <div class="alert alert-warning" role="alert">
                                        <p>{ "Multi-Factor Authentication is required for your account. Either add TOTP or remove your password in favour of passkeys to submit." }</p>
                                    </div>
                                },
                                CURegWarning::PasskeyRequired => html! {
                                    <div class="alert alert-warning" role="alert">
                                        <p>{ "Passkeys are required for your account." }</p>
                                    </div>
                                },
                                CURegWarning::AttestedPasskeyRequired => html! {
                                    <div class="alert alert-warning" role="alert">
                                        <p>{ "Attested Passkeys are required for your account." }</p>
                                    </div>
                                },
                                CURegWarning::AttestedResidentKeyRequired => html! {
                                    <div class="alert alert-warning" role="alert">
                                        <p>{ "Attested Resident Keys are required for your account." }</p>
                                    </div>
                                },
                                CURegWarning::WebauthnAttestationUnsatisfiable => html! {
                                    <div class="alert alert-danger" role="alert">
                                        <p>{ "A webauthn attestation policy conflict has occurred and you will not be able to save your credentials" }</p>
                                        <p>{ "Contact support IMMEDIATELY." }</p>
                                    </div>
                                },
                                CURegWarning::Unsatisfiable => html! {
                                    <div class="alert alert-danger" role="alert">
                                        <p>{ "An account policy conflict has occurred and you will not be able to save your credentials" }</p>
                                        <p>{ "Contact support IMMEDIATELY." }</p>
                                    </div>
                                },
                            }
                        )
                    }
                </>
            }
        };

        html! {
        <>
          <div class="d-flex align-items-start form-cred-reset-body">
            <main class="w-100">
              <div class="py-3 text-center">
                <h3>{ "Updating Credentials" }</h3>
                <p>{ names }</p>
                <p>{ domain }</p>
              </div>

              <div class="row g-3">
                  <form class="needs-validation" novalidate=true>

                    { ext_cred_portal_html }

                    { warnings_html }

                    { attested_passkey_html }

                    { passkey_html }

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

            <DeleteApp token= { token.clone() } cb={ cb.clone() }/>

          </div>
          { do_footer() }
          </>
        }
    }

    fn view_primary(
        &self,
        token: &CUSessionToken,
        primary: &Option<CredentialDetail>,
        primary_state: CUCredState,
    ) -> Html {
        let cb = self.cb.clone();

        // match on primary, get type_.
        let alt_auth_method_inner = if matches!(primary_state, CUCredState::Modifiable) {
            match primary {
                Some(CredentialDetail {
                    uuid: _,
                    type_: CredentialDetailType::Password,
                }) => {
                    html! {
                        <>
                          <h6> <b>{ "Password" }</b> </h6>
                          <p>
                            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#staticPassword">
                              { "Change Password" }
                            </button>
                          </p>
                          <h6> <b>{ "Time-based One Time Password (TOTP)" }</b> </h6>
                          <p>{ "TOTPs are 6 digit codes generated on-demand as a second authentication factor."}</p>
                          <p>
                            <TotpModalApp token={ token.clone() } cb={ cb.clone() }/>
                          </p>
                          <br/>
                          <p>
                            <button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#staticDeletePrimaryCred">
                              { "Delete Alternative Credentials" }
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
                          <h6> <b>{ "Password" }</b> </h6>
                          <p>
                            <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#staticPassword">
                              { "Change Password" }
                            </button>
                          </p>
                          <br/>
                          <h6> <b>{ "Time-based One Time Password (TOTP)" }</b></h6>
                          <p>{ "TOTPs are 6 digit codes generated on-demand as a second authentication factor."}</p>
                          <>
                          { for totp_set.iter()
                              .map(|detail| html! { <TotpRemoveComp token={ token.clone() } label={ detail.clone() } cb={ cb.clone() } /> })
                          }
                          </>

                          <p>
                            <TotpModalApp token={ token.clone() } cb={ cb.clone() }/>
                          </p>
                          <br/>
                          <br/>
                          <p>
                            <button type="button" class="btn btn-warning" data-bs-toggle="modal" data-bs-target="#staticDeletePrimaryCred">
                              { "Delete Alternative Credentials" }
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
                        <h6> <b>{ "Password" }</b> </h6>
                        <p>{ "In order to set up alternative authentication methods, you must delete the generated password." }</p>
                        <button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#staticDeletePrimaryCred">
                          { "Delete Generated Password" }
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
                        <p>{ "Webauthn Only - Will migrate to passkeys in a future update" }</p>
                        <button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#staticDeletePrimaryCred">
                          { "Delete Alternative Credentials" }
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
            }
        } else if matches!(primary_state, CUCredState::DeleteOnly) {
            html! {
              <p>
                <button type="button" class="btn btn-warning" data-bs-toggle="modal" data-bs-target="#staticDeletePrimaryCred">
                  { "Delete Legacy Credentials" }
                </button>
              </p>
            }
        } else {
            html! {<></>}
        };

        let alt_auth_method_warning = match primary_state {
            CUCredState::Modifiable => {
                html! {
                  <>
                    <p>{ "If possible, passkeys should be used instead, as they are phishing and exploit resistant." }</p>
                  </>
                }
            }
            CUCredState::DeleteOnly => {
                html! {
                  <>
                    <p>{ "If possible, passkeys should be used instead, as they are phishing and exploit resistant." }</p>
                    <p>{ "Account policy prevents you modifying these credentials, but you may remove them." }</p>
                  </>
                }
            }
            CUCredState::AccessDeny => {
                html! {
                    <>
                        <p>{ "You do not have access to modify these credentials." }</p>
                    </>
                }
            }
            CUCredState::PolicyDeny => {
                html! {
                    <>
                        <p>{ "Account policy prevents you from setting these credentials" }</p>
                    </>
                }
            }
        };

        html! {
           <>
            <hr class="my-4" />
            <h4>{"Alternative Authentication Methods" }</h4>
            { alt_auth_method_warning }
            { alt_auth_method_inner }

            <PwModalApp token={ token.clone() } cb={ cb } />
           </>
        }
    }

    fn view_passkeys(
        &self,
        token: &CUSessionToken,
        passkeys: &[PasskeyDetail],
        passkeys_state: CUCredState,
    ) -> Html {
        let cb = self.cb.clone();

        match passkeys_state {
            CUCredState::DeleteOnly | CUCredState::Modifiable => {
                html! {
                  <>
                    <hr class="my-4" />
                    <h4>{"Passkeys"}</h4>

                    <p>{ "Easy to use digital credentials with self-contained multi-factor authentication designed to replace passwords." }</p>
                    <p>
                      <a target="_blank" href="https://support.microsoft.com/en-us/windows/passkeys-in-windows-301c8944-5ea2-452b-9886-97e4d2ef4422">{ "Windows" }</a>
                      { ", " }
                      <a target="_blank" href="https://support.apple.com/guide/mac-help/create-a-passkey-mchl4af65d1a/mac">{ "MacOS" }</a>
                      { ", " }
                      <a target="_blank" href="https://support.google.com/android/answer/14124480?hl=en">{ "Android" }</a>
                      { ", and " }
                      <a target="_blank" href="https://support.apple.com/guide/iphone/use-passkeys-to-sign-in-to-apps-and-websites-iphf538ea8d0/ios">{ "iOS" }</a>
                      { " have built-in support for passkeys."}
                    </p>

                    { for passkeys.iter()
                        .map(|detail|
                            PasskeyRemoveModalApp::render_button(&detail.tag, detail.uuid)
                        )
                    }
                    { for passkeys.iter()
                        .map(|detail|
                            html! { <PasskeyRemoveModalApp token={ token.clone() } tag={ detail.tag.clone() } uuid={ detail.uuid } cb={ cb.clone() } class={ PasskeyClass::Any } /> }
                        )
                    }

                    { if passkeys_state == CUCredState::Modifiable {
                        html! { <PasskeyModalApp token={ token.clone() } cb={ cb.clone() } class={ PasskeyClass::Any } /> }
                    } else {
                        html! { <></> }
                    }}
                  </>
                }
            }
            CUCredState::AccessDeny => {
                html! { <></> }
            }
            CUCredState::PolicyDeny => {
                html! { <></> }
            }
        }
    }

    fn view_attested_passkeys(
        &self,
        token: &CUSessionToken,
        attested_passkeys: &[PasskeyDetail],
        attested_passkeys_state: CUCredState,
        attested_passkeys_allowed_devices: &[String],
    ) -> Html {
        let cb = self.cb.clone();

        match attested_passkeys_state {
            CUCredState::Modifiable => {
                html! {
                  <>
                    <hr class="my-4" />
                    <h4>{"Attested Passkeys"}</h4>
                    { for attested_passkeys.iter()
                        .map(|detail|
                            PasskeyRemoveModalApp::render_button(&detail.tag, detail.uuid)
                        )
                    }
                    { for attested_passkeys.iter()
                        .map(|detail|
                            html! { <PasskeyRemoveModalApp token={ token.clone() } tag={ detail.tag.clone() } uuid={ detail.uuid } cb={ cb.clone() } class={ PasskeyClass::Attested } /> }
                        )
                    }

                    <PasskeyModalApp token={ token.clone() } cb={ cb } class={ PasskeyClass::Attested } allowed_devices={ Some(attested_passkeys_allowed_devices.to_vec()) } />
                  </>
                }
            }
            CUCredState::DeleteOnly => {
                if attested_passkeys.is_empty() {
                    html! { <></> }
                } else {
                    html! {
                      <>
                        <hr class="my-4" />
                        <h4>{"Attested Passkeys"}</h4>

                        { for attested_passkeys.iter()
                            .map(|detail|
                                PasskeyRemoveModalApp::render_button(&detail.tag, detail.uuid)
                            )
                        }
                        { for attested_passkeys.iter()
                            .map(|detail|
                                html! { <PasskeyRemoveModalApp token={ token.clone() } tag={ detail.tag.clone() } uuid={ detail.uuid } cb={ cb.clone() } class={ PasskeyClass::Attested } /> }
                            )
                        }

                      </>
                    }
                }
            }
            CUCredState::AccessDeny | CUCredState::PolicyDeny => {
                // Don't display anything.
                html! { <></> }
            }
        }
    }

    fn view_error(&self, _ctx: &Context<Self>, msg: &str, kopid: Option<&str>) -> Html {
        html! {
          <main class="form-signin">
            { error_page(msg, kopid) }
          </main>
        }
    }

    async fn exchange_intent_token(token: String) -> Result<Msg, FetchError> {
        let request = CUIntentToken { token };
        let req_jsvalue = request
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .expect("Failed to serialise request");
        let req_jsvalue = js_sys::JSON::stringify(&req_jsvalue).expect_throw("failed to stringify");

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
        let req_jsvalue = token
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .expect("Failed to serialise request");
        let req_jsvalue = js_sys::JSON::stringify(&req_jsvalue).expect_throw("failed to stringify");

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
