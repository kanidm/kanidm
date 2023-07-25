use gloo::console;
use gloo::console::console;
use gloo_timers::callback::{Interval, Timeout};
use js_sys::Array;
use kanidm_proto::internal::{IdentifyUserRequest, IdentifyUserResponse};
use wasm_bindgen::JsValue;
use wasm_timer::SystemTime;
use yew::prelude::*;

use crate::constants::ID_IDENTITY_VERIFICATION_SYSTEM_TOTP_MODAL;
use crate::utils::document;
use crate::views::identityverification::{
    IdentifyUserState, IdentifyUserTransition, CORRUPT_STATE_ERROR,
};
use crate::{do_request, utils, RequestMethod};

static DASH_ARRAY_SIZE: u16 = 188;

// Warning occurs at 10s
static WARNING_THRESHOLD: f32 = 0.5;
// Alert occurs at 5s
static ALERT_THRESHOLD: f32 = 0.25;

enum TotpStatus {
    Waiting,
    Secret(u32),
}

pub struct TotpDisplayApp {
    secret: TotpStatus,
    step: u32,
    main_timer: Option<Timeout>,
    ticks_timer: Option<Interval>,
    sync_timer: Option<Timeout>,
    ticks_left: u8,
}

pub enum Msg {
    FetchTotpAndResetTimer,
    NewTotp(u32),
    Tick,
    StartTicking,
    TotpConfirmed,
    TotpNotConfirmed,
    Cancel,
    InvalidState,
}

#[derive(Properties, PartialEq)]
pub struct TotpProps {
    pub state: IdentifyUserState,
    pub other_id: String,
    pub cb: Callback<IdentifyUserTransition>,
}

impl TotpDisplayApp {
    async fn renew_totp(other_id: String) -> Msg {
        let uri = format!("/v1/person/{}/_identify_user", other_id);
        let request = IdentifyUserRequest::DisplayCode;
        let Ok(state_as_jsvalue) = serde_json::to_string(&request)
            .map(|s| JsValue::from(&s))
             else {
            return Msg::Cancel
        };
        let response = match do_request(&uri, RequestMethod::POST, Some(state_as_jsvalue)).await {
            Ok((_, _, response, _)) => response,
            Err(_) => return Msg::Cancel,
        };
        console!(response.clone());
        match serde_wasm_bindgen::from_value(response) {
            // TODO: check how the backend encodes the totp when sending it
            Ok(IdentifyUserResponse::ProvideCode { totp, step: _ }) => Msg::NewTotp(totp),
            _ => Msg::Cancel,
        }
    }

    fn get_time_left_from_now(&self) -> u32 {
        #[allow(clippy::expect_used)]
        let dur = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("invalid duration from epoch now");
        let secs: u128 = dur.as_millis();
        let step = self.step as u128;
        (step * 1000 - secs % (step * 1000)) as u32
    }

    fn get_time_left_from_now_selfless(step: u128) -> u32 {
        #[allow(clippy::expect_used)]
        let dur = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("invalid duration from epoch now");
        let secs: u128 = dur.as_millis();
        (step * 1000 - secs % (step * 1000)) as u32
    }

    fn get_ring_color(&self, time_remaining: u32) -> AttrValue {
        // it's a bit hacky but we want it to be green starting from 0 (aka no totp ring) so by the next second
        // (aka when it goes to 30) it's already 100% green, since the transition takes 1s we have to start doing this from
        // time_remaining == 1
        AttrValue::from(if time_remaining <= 1 {
            "green"
        } else if time_remaining <= (ALERT_THRESHOLD * self.step as f32) as u32 {
            "red"
        } else if time_remaining <= (WARNING_THRESHOLD * self.step as f32) as u32 {
            "orange"
        } else {
            "green"
        })
    }

    // TODO! It's not remotely doing what I wanted to do, damned CSS
    fn no_transition_switch_from_red_to_green() {
        if let Some(el) = document().get_element_by_id("totp-timer-path-remaining") {
            let str_to_sys_array = |s: &str| Array::from(&JsValue::from(s));
            #[allow(clippy::expect_used)]
            el.class_list()
                .add(&str_to_sys_array("no-transition"))
                .expect("We should be able to add to the classlist of totp-timer-path-remaining");
            #[allow(clippy::expect_used)]
            el.class_list()
                .remove(&str_to_sys_array("red"))
                .expect("We should be able to remove the red class from totp-timer-path-remaining");
            #[allow(clippy::expect_used)]
            el.class_list()
                .add(&str_to_sys_array("green"))
                .expect("We should be able to add to the classlist of totp-timer-path-remaining");
            // I know this is super duper awful but turns out there is no better way to disable the transition
            // temporarily and re enable it afterwards
        };
    }

    fn reenable_transitions() {
        if let Some(el) = document().get_element_by_id("totp-timer-path-remaining") {
            let str_to_sys_array = |s: &str| Array::from(&JsValue::from(s));
            #[allow(clippy::expect_used)]
            el.class_list().remove(&str_to_sys_array("no-transition")).expect(
                "We should be able to remove the no-transition class from totp-timer-path-remaining",
            );
        };
    }
}

impl Component for TotpDisplayApp {
    type Message = Msg;
    type Properties = TotpProps;

    fn create(ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("totp modal create");

        ctx.link().send_message(Msg::FetchTotpAndResetTimer);
        let (totp, step) = match &ctx.props().state {
            IdentifyUserState::DisplayCodeFirst { self_totp, step }
            | IdentifyUserState::DisplayCodeSecond { self_totp, step } => (self_totp, step),
            _ => {
                ctx.link().send_message(Msg::InvalidState);
                (&0, &0)
            }
        };

        let time_left = Self::get_time_left_from_now_selfless(*step as u128);

        let handle = {
            let link = ctx.link().clone();
            Timeout::new(time_left, move || {
                link.send_message(Msg::FetchTotpAndResetTimer)
            })
        };
        ctx.link().send_message(Msg::NewTotp(*totp));

        TotpDisplayApp {
            secret: TotpStatus::Waiting,
            main_timer: Some(handle),
            ticks_left: 30u8,
            ticks_timer: None,
            sync_timer: None,
            step: *step,
        }
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("totp display::update");

        match msg {
            Msg::FetchTotpAndResetTimer => {
                self.secret = TotpStatus::Waiting;
                // when the timer is over we added the no-transition class, switch to green and remove the no-transition class
                Self::no_transition_switch_from_red_to_green();
                let time_left = self.get_time_left_from_now();

                let handle = {
                    let link = ctx.link().clone();
                    Timeout::new(time_left, move || {
                        link.send_message(Msg::FetchTotpAndResetTimer)
                    })
                };
                ctx.link()
                    .send_future(Self::renew_totp(ctx.props().other_id.clone()));
                self.main_timer = Some(handle);
            }
            Msg::NewTotp(totp) => {
                // once we get the new totp we update it and we call start_ticking on the next
                // even second
                let millis_to_next_second = self.get_time_left_from_now() % 1000;
                self.secret = TotpStatus::Secret(totp);

                let link = ctx.link().clone();
                self.sync_timer = Some(Timeout::new(millis_to_next_second, move || {
                    link.send_message(Msg::StartTicking)
                }));
            }
            Msg::StartTicking => {
                Self::reenable_transitions();
                self.ticks_left = (self.get_time_left_from_now() / 1000) as u8 + 1;
                self.ticks_timer = {
                    let link = ctx.link().clone();
                    Some(Interval::new(1000, move || link.send_message(Msg::Tick)))
                };
            }
            Msg::Tick => {
                // if the ticks are less than 0 it means the other timeout is also 0 and therefore
                // it will send a FetchTotpAndResetTimer message so we don't need to worry about that here
                if self.ticks_left > 0 {
                    self.ticks_left -= 1;
                }
            }
            Msg::Cancel => {
                self.main_timer = None;
                self.ticks_left = 100;
            }
            Msg::TotpConfirmed => {
                utils::modal_hide_by_id(ID_IDENTITY_VERIFICATION_SYSTEM_TOTP_MODAL);
                if let IdentifyUserState::DisplayCodeFirst { .. } = &ctx.props().state {
                    ctx.props().cb.emit(IdentifyUserTransition::WaitForCode)
                } else {
                    ctx.props().cb.emit(IdentifyUserTransition::Success)
                }
            }
            Msg::TotpNotConfirmed => {
                utils::modal_hide_by_id(ID_IDENTITY_VERIFICATION_SYSTEM_TOTP_MODAL);
            }
            Msg::InvalidState => {
                utils::modal_hide_by_id(ID_IDENTITY_VERIFICATION_SYSTEM_TOTP_MODAL);
                ctx.props().cb.emit(IdentifyUserTransition::Error {
                    msg: CORRUPT_STATE_ERROR.to_string(),
                })
            }
        }
        true
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("totp modal::change");
        false
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        #[cfg(debug_assertions)]
        console::debug!("totp modal::view");
        #[cfg(debug_assertions)]
        console::debug!(self.ticks_left);
        let step = self.step;
        let time_fraction = self.ticks_left as f32 / step as f32;
        let color_class = self.get_ring_color(self.ticks_left as u32);
        // at the first tick we remove the no-transition class if present!
        let classes = format!("totp-timer__path-remaining {}", color_class);
        let shortened_time_fraction = time_fraction - (1.0 / step as f32) * (1.0 - time_fraction);
        let attr_value = AttrValue::from(format!(
            "{} {}",
            shortened_time_fraction * DASH_ARRAY_SIZE as f32,
            DASH_ARRAY_SIZE
        ));
        let other_id = ctx.props().other_id.clone();
        html! {
                <>
                <div class="identity-verification-container">
                    <div class="totp-display-container">
                    { if let TotpStatus::Secret (totp) = &self.secret {
                         html!{
                             <span class="totp-display">
                                <b>{ totp } </b>
                             </span>
                         }
                     } else {
                         html! {
                             <p>
                                { "Fetching your totp..." }
                             </p>
                         }
                     } }
                    <div class="totp-timer">
                        <svg class="totp-timer__svg" viewBox="0 0 120 120" xmlns="http://www.w3.org/2000/svg">
                         <g class="totp-timer__circle">
                            <path
                            id="totp-timer-path-remaining"
                             stroke-dasharray={attr_value}
                            class={classes!(classes)}
                             d="
                                M 60, 60
                                m -30, 0
                                a 30,30 0 1,0 60,0
                                a 30,30 0 1,0 -60,0
                                "
                            ></path>
                         </g>
                        </svg>
                    </div>
                    </div>
                    <button
                        style="width: fit-content;"
                        class="btn btn-secondary"
                        data-bs-toggle="modal"
                        data-bs-target={format!("#{}", ID_IDENTITY_VERIFICATION_SYSTEM_TOTP_MODAL)}
                    >{" Continue "}</button>
                </div>
                <div class="modal fade" id={ID_IDENTITY_VERIFICATION_SYSTEM_TOTP_MODAL} tabindex="-1" role="dialog" aria-labelledby="exampleModalLabel" aria-hidden="true">
                  <div class="modal-dialog" role="document">
                    <div class="modal-content">
                      <div class="modal-body">
                        {"Did you confirm that "} {other_id} {"  correctly verified your code? If you proceed, you won't be able to go back."}
                      </div>
                      <div class="modal-footer">
                        <button type="button" class="btn btn-primary" onclick={  ctx.link()
                                .callback(move |_| Msg::TotpNotConfirmed)} >{"Go back"}</button>
                        <button type="button" class="btn btn-secondary" onclick={  ctx.link()
                                .callback(move |_| Msg::TotpConfirmed)}>{"Continue"}</button>
                      </div>
                    </div>
                  </div>
                </div>
                </>
        }
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("totp modal::rendered");
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        #[cfg(debug_assertions)]
        console::debug!("totp modal::destroy");
    }
}
