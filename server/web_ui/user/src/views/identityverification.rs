#[cfg(debug_assertions)]
use gloo::console;
use kanidm_proto::internal::{IdentifyUserRequest, IdentifyUserResponse};
use kanidmd_web_ui_shared::logo_img;
use regex::Regex;
use wasm_bindgen::JsValue;
use yew::prelude::*;

use crate::components::totpdisplay::TotpDisplayApp;
use kanidmd_web_ui_shared::constants::{
    CLASS_DIV_LOGIN_BUTTON, CLASS_DIV_LOGIN_FIELD, CSS_ALERT_DANGER, URL_USER_HOME,
};

use crate::views::ViewProps;
use kanidmd_web_ui_shared::{do_request, error::FetchError, utils, RequestMethod};

#[derive(Clone, Debug, PartialEq)]
pub enum IdentifyUserState {
    Start,
    IdDisplayAndSubmit,
    SubmitCodeFirst {
        other_totp: Option<u32>,
        totp_valid: bool,
    },
    SubmitCodeSecond {
        other_totp: Option<u32>,
        totp_valid: bool,
    },
    DisplayCodeFirst {
        self_totp: u32,
        step: u32,
    },
    DisplayCodeSecond {
        self_totp: u32,
        step: u32,
    },
    Success,
    Error {
        msg: String,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum IdentifyUserTransition {
    UpdateSelfIdentity { spn: String },
    IdentityVerificationAvailable,
    ProvideCode { totp: u32, step: u32 },
    WaitForCode,
    Success,
    Error { msg: String },
    CheckInput { input: String },
    DoNothing,
}

pub(crate) static CORRUPT_STATE_ERROR: &str =
    "The identity verification flow is in a corrupt state, please abort and start again";

static UNAVAILABLE_IDENTITY_VERIFICATION_ERROR: &str =
    "The identity verification feature is currently unavailable for this account 😢";
static INVALID_USERID_ERROR: &str = "The provided UserID is invalid!";

lazy_static::lazy_static! {
    pub static ref VALIDATE_TOTP_RE: Regex = {
        #[allow(clippy::expect_used)]
        Regex::new(r"^\d{5,6}$").expect("Failed to parse VALIDATE_TOTP_RE") // TODO: add an error ID (internal error, restart)
    };
}

#[test]
fn totp_regex_test() {
    assert!(VALIDATE_TOTP_RE.is_match("123456"));
    assert!(VALIDATE_TOTP_RE.is_match("12345"));
    assert!(!VALIDATE_TOTP_RE.is_match("1234567"));
    assert!(!VALIDATE_TOTP_RE.is_match("1234"));
    assert!(!VALIDATE_TOTP_RE.is_match("12345a"));
    assert!(!VALIDATE_TOTP_RE.is_match("def not a totp"));
}

#[derive(Clone)]
pub struct IdentityVerificationApp {
    other_id: String,
    self_id: String,
    state: IdentifyUserState,
    cb: Callback<IdentifyUserTransition>,
}

impl From<FetchError> for IdentifyUserTransition {
    fn from(value: FetchError) -> Self {
        IdentifyUserTransition::Error {
            msg: value.to_string(),
        }
    }
}

impl From<IdentifyUserResponse> for IdentifyUserTransition {
    fn from(value: IdentifyUserResponse) -> Self {
        match value {
            IdentifyUserResponse::IdentityVerificationUnavailable => {
                IdentifyUserTransition::Error {
                    msg: UNAVAILABLE_IDENTITY_VERIFICATION_ERROR.to_string(),
                }
            }
            IdentifyUserResponse::IdentityVerificationAvailable => {
                IdentifyUserTransition::IdentityVerificationAvailable
            }
            IdentifyUserResponse::ProvideCode { totp, step } => {
                IdentifyUserTransition::ProvideCode { totp, step }
            }
            IdentifyUserResponse::WaitForCode => IdentifyUserTransition::WaitForCode,
            IdentifyUserResponse::Success => IdentifyUserTransition::Success,
            IdentifyUserResponse::CodeFailure => IdentifyUserTransition::Error {
                msg: "The code provided does not belong to the given user!".to_string(),
            },
            IdentifyUserResponse::InvalidUserId => IdentifyUserTransition::Error {
                msg: INVALID_USERID_ERROR.to_string(),
            },
        }
    }
}

impl Component for IdentityVerificationApp {
    type Message = IdentifyUserTransition;
    type Properties = ViewProps;

    fn create(ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("views::identity-verification::create");

        let id = Self::get_id(ctx);

        let state = IdentifyUserState::Start;
        ctx.link().send_future(Self::get_transition_from_start(
            state.to_owned(),
            id.clone(),
        ));
        ctx.link().send_future(Self::update_self_id(id.clone()));
        let cb = Callback::from({
            let link = ctx.link().clone();
            move |identify_user_transition| {
                link.send_message(identify_user_transition);
            }
        });
        IdentityVerificationApp {
            state,
            cb,
            other_id: String::new(),
            self_id: id.clone(),
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("views::identity-verification::update");
        match msg {
            IdentifyUserTransition::UpdateSelfIdentity { spn } => {
                #[cfg(debug_assertions)]
                console::debug!("identity-verification update self identity: {}", &spn);
                self.self_id = spn;
            }
            IdentifyUserTransition::IdentityVerificationAvailable => {
                if matches!(self.state, IdentifyUserState::Start) {
                    self.state = IdentifyUserState::IdDisplayAndSubmit
                } else {
                    self.set_state_to_corrupt_state_err()
                }
                // here the only thing to do is to display the page where the user can insert the ID
            }
            IdentifyUserTransition::ProvideCode { totp, step } => {
                // here we have two possibilities: we come from the 'IdDisplayAndSubmit' and therefore
                // we go into DisplayCodeFirst, or we come from SubmitCodeFirst and therefore we go to DisplayCodeSecond
                match &self.state {
                    IdentifyUserState::IdDisplayAndSubmit => {
                        self.state = IdentifyUserState::DisplayCodeFirst {
                            self_totp: totp,
                            step,
                        };
                    }
                    IdentifyUserState::SubmitCodeFirst { .. } => {
                        self.state = IdentifyUserState::DisplayCodeSecond {
                            self_totp: totp,
                            step,
                        };
                    }
                    _ => self.set_state_to_corrupt_state_err(),
                }
            }
            IdentifyUserTransition::WaitForCode => {
                // here again we have two possibilities: we either come from IdDisplayAndSubmit or from DisplayCodeFirst
                // if we are in the first case then we go to SubmitCodeFirst, otherwise we go to SubmitCodeSecond
                match &self.state {
                    IdentifyUserState::IdDisplayAndSubmit => {
                        self.state = IdentifyUserState::SubmitCodeFirst {
                            other_totp: None,
                            totp_valid: false,
                        };
                    }
                    IdentifyUserState::DisplayCodeFirst { .. } => {
                        self.state = IdentifyUserState::SubmitCodeSecond {
                            other_totp: None,
                            totp_valid: false,
                        };
                    }
                    _ => self.set_state_to_corrupt_state_err(),
                }
            }
            IdentifyUserTransition::Success => match self.state {
                IdentifyUserState::DisplayCodeSecond { .. }
                | IdentifyUserState::SubmitCodeSecond { .. } => {
                    self.state = IdentifyUserState::Success;
                }
                _ => self.set_state_to_corrupt_state_err(),
            },
            IdentifyUserTransition::DoNothing => return false,
            IdentifyUserTransition::CheckInput { input } => {
                // according to our beautiful state machine if CheckInput was called we must be in either IdDisplayAndSubmit, SubmitCodeFirst or SubmitCodeSecond.
                // if that's the case then we just update the valid_status accordingly
                // If we're in another state we'll land in the infamous invalid flow error!
                match &mut self.state {
                    IdentifyUserState::IdDisplayAndSubmit => self.other_id = input,
                    IdentifyUserState::SubmitCodeFirst {
                        other_totp,
                        totp_valid,
                    }
                    | IdentifyUserState::SubmitCodeSecond {
                        other_totp,
                        totp_valid,
                    } => {
                        *totp_valid = VALIDATE_TOTP_RE.is_match(&input);
                        #[cfg(debug_assertions)]
                        console::debug!(input.clone());
                        *other_totp = input.parse::<u32>().ok();
                    }
                    _ => self.set_state_to_corrupt_state_err(),
                }
            }
            IdentifyUserTransition::Error { msg } => self.state = IdentifyUserState::Error { msg },
        }
        true
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("views::identity-verification::changed");
        false
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.state {
            IdentifyUserState::Start => self.view_start(),
            IdentifyUserState::IdDisplayAndSubmit => self.view_id_submit_and_display(ctx),
            IdentifyUserState::SubmitCodeFirst {
                other_totp,
                totp_valid,
            }
            | IdentifyUserState::SubmitCodeSecond {
                other_totp,
                totp_valid,
            } => self.view_submit_code(ctx, *other_totp, *totp_valid),
            IdentifyUserState::DisplayCodeFirst { .. }
            | IdentifyUserState::DisplayCodeSecond { .. } => self.view_display_code(ctx),
            IdentifyUserState::Success => self.view_success(),
            IdentifyUserState::Error { msg } => self.view_error(msg),
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("views::apps::rendered");
    }
}

impl IdentityVerificationApp {
    fn view_start(&self) -> Html {
        html! {
            <>
              <div class="vert-center">
                <div class="spinner-border text-dark" role="status">
                  <span class="visually-hidden">{ "Loading..." }</span>
                </div>
              </div>
            </>
        }
    }

    fn view_id_submit_and_display(&self, ctx: &Context<Self>) -> Html {
        let self_clone = self.clone();
        let other_id = || self.other_id.clone();
        html! {
            <div class="identity-verification-container">
            <div class="container">
                 <p>{ "When asked for your ID, provide the following: "} <b>{ self.self_id.to_string() } </b></p>
            </div>
            <div class="container">
                <hr/>
            </div>
            <div class="container">
                <label for="ID" class="form-label"> {"Ask for the other person's ID, and insert it here:
        "}</label>
                <form
                onsubmit={ ctx.link().callback_future(move |e: SubmitEvent| {
                    #[cfg(debug_assertions)]
                    console::debug!("identity-verification::view_state -> Init - prevent_default()".to_string());
                    e.prevent_default();
                    self_clone.to_owned().get_transition_from_id_display_and_submit()
                } ) }
                >
                <div class={CLASS_DIV_LOGIN_FIELD}>
                    <input
                        autofocus=true
                        class="autofocus form-control"
                        id="other-user-id-input"
                        name="other-user-id-input"
                        type="text"
                        oninput={Self::input_callback(ctx, "other-user-id-input")}
                        autocomplete="ID"
                        value={ other_id() }
                    />
                </div>

                <div class={CLASS_DIV_LOGIN_BUTTON}>
                    <button
                        type="submit"
                        class="btn btn-primary"
                    >{" Continue "}</button>
                </div>
                </form>
            </div>
            </div>
        }
    }

    fn view_display_code(&self, _ctx: &Context<Self>) -> Html {
        let other_id = self.other_id.clone();

        html! {
          <div class="identity-verification-container">
            <div class="container">
                 <p>{ "Please provide the following code when asked!"} <b> </b></p>
            <TotpDisplayApp other_id = {other_id} state = { self.state.clone() } cb = {self.cb.clone()}  />
            </div>
          </div>
        }
    }

    fn view_submit_code(&self, ctx: &Context<Self>, totp: Option<u32>, totp_valid: bool) -> Html {
        let self_clone = self.clone();
        html! {
            <div class="identity-verification-container">
            <div class="container">
                <label for="ID" class="form-label"> {"Ask for "} { self.other_id.clone() }{ "'s code, and insert it here:"}</label>
                <form
                onsubmit={ ctx.link().callback_future(move |e: SubmitEvent| {
                    #[cfg(debug_assertions)]
                    console::debug!("identity-verification::view_state -> Init - prevent_default()".to_string());
                    e.prevent_default();
                    self_clone.to_owned().get_transition_from_submit_code()
                } ) }
                >
                <div class={CLASS_DIV_LOGIN_FIELD}>
                    <input
                        autofocus=true
                        class="autofocus form-control"
                        id="totp-code-input"
                        name="code"
                        type="number"
                        step="1"
                        max="999999"
                        min="0"
                        autocomplete="code"
                        oninput={Self::input_callback(ctx, "totp-code-input")}
                        value={ totp.map(|x| x.to_string()) }
                    />
                </div>

                <div class={CLASS_DIV_LOGIN_BUTTON}>
                    <button
                        type="submit"
                        class="btn btn-primary"
                        disabled={ !totp_valid }
                    >{" Continue "}</button>
                </div>
                </form>
            </div>
            </div>
        }
    }

    fn view_error(&self, error_message: &str) -> Html {
        html! {
          <>
            <p class="text-center">
                {logo_img()}
            </p>
            <div class={CSS_ALERT_DANGER} role="alert">
              <h2>{ "An Error Occurred 🥺" }</h2>
            <p>{ error_message }</p>
            </div>
            <p class="text-center">
              <a href={URL_USER_HOME}><button href={URL_USER_HOME} class="btn btn-secondary" aria-label="Return home">{"Return to the home page"}</button></a>
            </p>
          </>
        }
    }

    fn view_success(&self) -> Html {
        let other_id = self.other_id.clone();
        html! {
          <>
            <div class="alert alert-success" role="alert">
            <h4 class="alert-heading">{"Success 🎉🎉"}</h4>
            <p><b>{other_id}</b>{"'s identity has been successfully confirmed!"}</p>
            </div>
            <p class="text-center">
              <a href={URL_USER_HOME}><button href={URL_USER_HOME} class="btn btn-secondary" aria-label="Return home">{"Return to the home page"}</button></a>
            </p>
          </>
        }
    }

    // the purpose of the following functions is to get what to do next in the state machine.
    // each main view has its own function, that is the start view (even though it's displayed for few ms), the id_display_and_submit view
    // and the submit_code
    // we have to prefix
    async fn get_transition_from_start(
        _state: IdentifyUserState,
        self_id: String,
    ) -> IdentifyUserTransition {
        #[cfg(debug_assertions)]
        assert!(matches!(_state, IdentifyUserState::Start));
        // IdentifyUserRequest is hard coded as this function is called on start so that's the only possible state
        let response = match Self::do_typed_request(IdentifyUserRequest::Start, &self_id).await {
            Ok(res) => res,
            Err(s) => return IdentifyUserTransition::Error { msg: s.to_string() },
        };
        IdentifyUserTransition::from(response)
    }

    async fn get_transition_from_id_display_and_submit(self) -> IdentifyUserTransition {
        let request = match &self.state {
            IdentifyUserState::IdDisplayAndSubmit => IdentifyUserRequest::Start,
            _ => {
                return IdentifyUserTransition::Error {
                    msg: CORRUPT_STATE_ERROR.to_string(),
                }
            }
        };
        let response = match Self::do_typed_request(request, &self.other_id).await {
            Ok(res) => res,
            Err(s) => return IdentifyUserTransition::Error { msg: s.to_string() },
        };
        IdentifyUserTransition::from(response)
    }

    async fn get_transition_from_submit_code(self) -> IdentifyUserTransition {
        let request = match &self.state {
            IdentifyUserState::SubmitCodeFirst {
                other_totp,
                totp_valid,
            }
            | IdentifyUserState::SubmitCodeSecond {
                other_totp,
                totp_valid,
                // in no case this function should have been called with an invalid code, but if that's the case then we do nothing
            } => {
                if *totp_valid {
                    IdentifyUserRequest::SubmitCode {
                        // we know that the totp is valid so this should always be Some,
                        // if for some reason it's None then we are still covered
                        other_totp: other_totp.unwrap_or_default(),
                    }
                } else {
                    return IdentifyUserTransition::DoNothing;
                }
            }
            _ => {
                return IdentifyUserTransition::Error {
                    msg: CORRUPT_STATE_ERROR.to_string(),
                }
            }
        };
        let response = match Self::do_typed_request(request, &self.other_id).await {
            Ok(res) => res,
            Err(s) => return IdentifyUserTransition::Error { msg: s.to_string() },
        };
        IdentifyUserTransition::from(response)
    }

    async fn do_typed_request(
        request: IdentifyUserRequest,
        other_id: &str,
    ) -> Result<IdentifyUserResponse, String> {
        let uri = format!("/v1/person/{}/_identify_user", other_id);
        let request_as_jsvalue = serde_json::to_string(&request)
            .map(|s| JsValue::from(&s))
            .map_err(|_| "Invalid request!".to_string())?;
        let (_, status, response, _) =
            do_request(&uri, RequestMethod::POST, Some(request_as_jsvalue))
                .await
                .map_err(|e| e.to_string())?;
        if status != 200 {
            Err(format!(
                "The server responded with status code {status}, here is what went wrong: {}",
                response.as_string().unwrap_or_default()
            ))
        } else {
            serde_wasm_bindgen::from_value(response)
                .map_err(|_| "Invalid response from server!".to_string())
        }
    }

    async fn update_self_id(uuid: String) -> IdentifyUserTransition {
        let uri = format!("/v1/person/{}/_attr/spn", uuid);
        let outcome: Option<Vec<String>> =
            match do_request(&uri, RequestMethod::GET, None).await.ok() {
                None => None,
                Some((_, _, res, ..)) => serde_wasm_bindgen::from_value(res).ok(),
            };
        match outcome.and_then(|v| v.first().cloned()) {
            Some(spn) => IdentifyUserTransition::UpdateSelfIdentity { spn },
            None => IdentifyUserTransition::DoNothing,
        }
    }

    fn get_id(ctx: &Context<Self>) -> String {
        let uat = &ctx.props().current_user_uat;
        uat.uuid.to_string()
    }

    fn input_callback(ctx: &Context<Self>, element_id: &str) -> yew::Callback<web_sys::InputEvent> {
        let cloned_element_id = element_id.to_string();
        ctx.link().callback(move |_| {
            let input = utils::get_value_from_element_id(&cloned_element_id).unwrap_or_default();
            IdentifyUserTransition::CheckInput { input }
        })
    }

    fn set_state_to_corrupt_state_err(&mut self) {
        self.state = IdentifyUserState::Error {
            msg: CORRUPT_STATE_ERROR.to_string(),
        }
    }
}
