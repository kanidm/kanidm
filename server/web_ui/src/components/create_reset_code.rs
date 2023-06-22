#[cfg(debug_assertions)]
use gloo::console;
use kanidm_proto::v1::{UserAuthToken, CUIntentToken};
use yew::prelude::*;
use crate::utils;

use wasm_bindgen::UnwrapThrowExt;
use web_sys::Node;
use qrcode::render::svg;
use qrcode::QrCode;

enum State {
    Valid,
    Error { emsg: String, kopid: Option<String> },
}

#[allow(dead_code)]
enum CodeState {
    Waiting,
    Ready { token: CUIntentToken }
}

#[allow(dead_code)]
pub enum Msg {
    Activate,
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
    state: State,
    code_state: CodeState,
}

impl Component for CreateResetCode {
    type Message = Msg;
    type Properties = Props;

    fn create(_ctx: &Context<Self>) -> Self {
        CreateResetCode {
            state: State::Valid,
            code_state: CodeState::Waiting,
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::Activate => {
                #[cfg(debug_assertions)]
                console::debug!("modal activate");
                true
            }
            Msg::Error { emsg, kopid } => {
                self.reset();
                self.state = State::Error { emsg, kopid };
                true
            }
            Msg::Dismiss => {
                self.reset();
                utils::modal_hide_by_id(crate::constants::ID_CRED_RESET_CODE);
                self.state = State::Valid;
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

        let code_reset_state = match &self.code_state {
            CodeState::Waiting => html! {
                <div class="spinner-border text-dark" role="status">
                    <span class="visually-hidden">{ "Loading..." }</span>
                </div>
            },
            CodeState::Ready { token } => {
                let mut url = utils::origin();

                url.set_path("/ui/reset");
                url.query_pairs_mut()
                    .append_pair("token", token.token.as_str());

                let qr = QrCode::new(url.as_str()).unwrap_throw();

                let svg = qr.render::<svg::Color>().build();

                #[allow(clippy::unwrap_used)]
                let div = utils::document().create_element("div").unwrap();

                div.set_inner_html(svg.as_str());

                let node: Node = div.into();
                let svg_html = Html::VRef(node);

                let code = format!("Code: {}", token.token);

                html! {
                    <>
                      <div class="col-8">
                        { svg_html }
                      </div>
                      <div class="col-4">
                        <p>{ code }</p>
                      </div>
                    </>
                }
            }
        };

        html! {
          <>
            <button type="button" class="btn btn-primary"
              disabled={ !button_enabled }
              data-bs-toggle="modal"
              data-bs-target={format!("#{}", crate::constants::ID_CRED_RESET_CODE)}
              onclick={
                  ctx.link()
                      .callback(move |_| {
                          Msg::Activate
                      })
              }
            >
              { "Update your Authentication Settings on Another Device" }
            </button>
            <div class="modal" tabindex="-1" role="dialog" id={crate::constants::ID_CRED_RESET_CODE}>
              <div class="modal-dialog" role="document">
                    <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{"Update your authentication settings"}</h5>
                        <button
                            aria-label="Close"
                            class="btn-close"
                            onclick={
                                ctx.link()
                                    .callback(move |_| {
                                        Msg::Dismiss
                                    })
                            }
                            type="button"
                        ></button>
                    </div>

                    <div class="modal-body">
                        { flash }
                        <div class="container">
                          <div class="row">
                            { code_reset_state }
                          </div>
                        </div>
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
        self.code_state = CodeState::Waiting;
    }
}
