#[cfg(debug_assertions)]
use gloo::console;
use kanidm_proto::v1::UserAuthToken;
use yew::prelude::*;
use crate::utils;

enum State {
    Init,
    Waiting,
    Error { emsg: String, kopid: Option<String> },
}

#[allow(dead_code)]
pub enum Msg {
    // Ready,
    Dismiss,
    Error { emsg: String, kopid: Option<String> },
}

#[derive(PartialEq, Eq, Properties)]
pub struct Props {
    pub uat: UserAuthToken,
    pub enabled: bool,
}

pub struct CreateResetCode {
    state: State
}

impl Component for CreateResetCode {
    type Message = Msg;
    type Properties = Props;

    fn create(_ctx: &Context<Self>) -> Self {
        CreateResetCode {
            state: State::Waiting
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::Error { emsg, kopid } => {
                self.reset();
                self.state = State::Error { emsg, kopid };
                true
            }
            Msg::Dismiss => {
                self.reset();
                utils::modal_hide_by_id(crate::constants::ID_CRED_RESET_CODE);
                self.state = State::Init;
                true
            }
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let button_enabled = ctx.props().enabled;

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

        html! {
          <>
            <button type="button" class="btn btn-primary"
              disabled={ !button_enabled }
              data-bs-toggle="modal"
              data-bs-target={format!("#{}", crate::constants::ID_CRED_RESET_CODE)}
            >
              { "Update your Authentication Settings on Another Device" }
            </button>
            <div class="modal" tabindex="-1" role="dialog" id={crate::constants::ID_CRED_RESET_CODE}>
              <div class="modal-dialog" role="document">
                    <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{"Update your authentication settings"}</h5>
                    </div>

                    <div class="modal-body">
                        <p>{ "Update" }</p>
                        { flash }
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary"
                        onclick={
                          ctx.link().callback(|_e| {
                              Msg::Dismiss
                          })
                        }
                        >{"Cancel"}</button>
                    </div>
                  </div>
              </div>
            </div>
          </>
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        false
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {}

    fn destroy(&mut self, _ctx: &Context<Self>) {}
}

impl CreateResetCode {
    fn reset(&mut self) {
        
    }
}
