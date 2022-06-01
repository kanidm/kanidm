use crate::utils;

use super::eventbus::{EventBus, EventBusMsg};
use super::reset::{ModalProps, submit_cred_update};

use gloo::console;
use wasm_bindgen::UnwrapThrowExt;
use web_sys::Node;
use yew::prelude::*;

use qrcode::{render::svg, QrCode};

enum TotpState {
    Init,
    Waiting,
}

enum TotpCheck {
    Init,
    Invalid,
}

enum TotpSecret {
    Init,
    Value(String),
}

pub struct TotpModalApp {
    state: TotpState,
    check: TotpCheck,
    secret: TotpSecret,
}

pub enum Msg {
    TotpCancel,
    TotpSubmit,
    TotpSecretReady,
    TotpSuccess,
    TotpAcceptSha1,
}

impl TotpModalApp {
    fn reset_and_hide(&mut self) {
        utils::modal_hide_by_id("staticTotpCreate");
        self.state = TotpState::Init;
        self.check = TotpCheck::Init;
        self.secret = TotpSecret::Init;
    }
}

impl Component for TotpModalApp {
    type Message = Msg;
    type Properties = ModalProps;

    fn create(ctx: &Context<Self>) -> Self {
        console::log!("totp modal create");

        // SEND OFF A REQUEST TO GET THE TOTP STRING
        let token_c = ctx.props().token.clone();

        ctx.link().send_future(async {
            match submit_cred_update(token_c, CURequest::Password(pw)).await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });

        // Msg::TotpSecretReady

        TotpModalApp {
            state: TotpState::Init,
            check: TotpCheck::Init,
            secret: TotpSecret::Init,
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::log!("totp modal::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::log!("totp modal::update");
        match msg {
            Msg::TotpCancel => {
                self.reset_and_hide();
            }
            Msg::TotpSubmit => {
                // Send off the submit, lock the form.
                self.check = TotpCheck::Invalid;
            }
            Msg::TotpSecretReady => {
                // THIS IS WHATS CALLED WHEN THE SECRET IS BACK
                self.secret = TotpSecret::Value("Secret Value".to_string());
            }
            Msg::TotpAcceptSha1 => {
                
            }
            Msg::TotpSuccess => {
            }
        };
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        console::log!("totp modal::rendered");
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        console::log!("totp modal::destroy");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        console::log!("totp modal::view");

        let totp_class = match &self.check {
            TotpCheck::Invalid => classes!("form-control", "is-invalid"),
            _ => classes!("form-control"),
        };

        let submit_enabled = match &self.state {
            TotpState::Init => true,
            _ => false,
        };

        let qrcode = match &self.secret {
            TotpSecret::Init => {
                html! {
                    <button id="totp-submit" type="button" class="btn btn-primary"
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::TotpSecretReady
                                })
                        }
                    >{ "Submit" }</button>
                }
            }
            TotpSecret::Value(secret) => {
                let qr = QrCode::new(secret.as_str()).unwrap_throw();

                let svg = qr.render::<svg::Color>().build();

                let div = utils::document().create_element("div").unwrap();

                div.set_inner_html(svg.as_str());

                let node: Node = div.into();
                Html::VRef(node)
            }
        };

        html! {
            <div class="modal fade" id="staticTotpCreate" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticTotpCreate" aria-hidden="true">
              <div class="modal-dialog modal-lg">
                <div class="modal-content">
                  <div class="modal-header">
                    <h5 class="modal-title" id="staticTotpLabel">{ "Add a New TOTP Authenticator" }</h5>
                    <button type="button" class="btn-close" aria-label="Close"
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::TotpCancel
                                })
                        }
                    ></button>
                  </div>
                  <div class="modal-body">

                    <div>
                      <p>{ "Qr Code Go Where?" }</p>

                      { qrcode }
                    </div>

                    <form class="row g-3 needs-validation" novalidate=true>
                      <label for="totp" class="form-label">{ "Enter a TOTP" }</label>
                      <input
                        type="totp"
                        class={ totp_class }
                        id="totp"
                        placeholder=""
                        aria-describedby="totp-validation-feedback"
                        required=true
                      />
                      <div id="totp-validation-feedback" class="invalid-feedback">
                        { "Incorrect TOTP code - Please try again" }
                      </div>
                    </form>
                  </div>
                  <div class="modal-footer">
                    <button id="totp-cancel" type="button" class="btn btn-secondary"
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::TotpCancel
                                })
                        }
                    >{ "Cancel" }</button>
                    <button id="totp-submit" type="button" class="btn btn-primary"
                        disabled={ !submit_enabled }
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::TotpSubmit
                                })
                        }
                    >{ "Submit" }</button>
                  </div>
                </div>
              </div>
            </div>
        }
    }
}
