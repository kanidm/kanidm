use crate::error::*;
use crate::utils;

use super::eventbus::{EventBus, EventBusMsg};
use super::reset::ModalProps;

use gloo::console;
use web_sys::Node;
use yew::prelude::*;
use yew_agent::Dispatched;

use wasm_bindgen::{JsCast, JsValue, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use kanidm_proto::v1::{CURegState, CURequest, CUSessionToken, CUStatus, TotpSecret};
use qrcode::{render::svg, QrCode};

enum TotpState {
    Init,
    Waiting,
}

enum TotpCheck {
    Init,
    Invalid,
    Sha1Accept,
}

enum TotpValue {
    Init,
    Waiting,
    Secret(TotpSecret),
}

pub struct TotpModalApp {
    state: TotpState,
    check: TotpCheck,
    secret: TotpValue,
}

pub enum Msg {
    TotpGenerate,
    TotpCancel,
    TotpSubmit,
    TotpSecretReady(TotpSecret),
    TotpTryAgain,
    TotpInvalidSha1,
    Error { emsg: String, kopid: Option<String> },
    TotpAcceptSha1,
    TotpSuccess,
    TotpClearInvalid,
}

impl From<FetchError> for Msg {
    fn from(fe: FetchError) -> Self {
        Msg::Error {
            emsg: fe.as_string(),
            kopid: None,
        }
    }
}

impl TotpModalApp {
    fn reset_and_hide(&mut self) {
        utils::modal_hide_by_id("staticTotpCreate");
        self.state = TotpState::Init;
        self.check = TotpCheck::Init;
        self.secret = TotpValue::Init;
    }

    async fn submit_totp_update(token: CUSessionToken, req: CURequest) -> Result<Msg, FetchError> {
        let req_jsvalue = serde_json::to_string(&(req, token))
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise pw curequest");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);

        opts.body(Some(&req_jsvalue));

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

        let kopid = headers.get("x-kanidm-opid").ok().flatten();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let status: CUStatus = jsval.into_serde().expect_throw("Invalid response type");

            EventBus::dispatcher().send(EventBusMsg::UpdateStatus {
                status: status.clone(),
            });

            Ok(match status.mfaregstate {
                CURegState::Passkey(_) | CURegState::BackupCodes(_) => Msg::Error {
                    emsg: "Invalid TOTP mfa reg state response".to_string(),
                    kopid,
                },
                CURegState::None => Msg::TotpSuccess,
                CURegState::TotpCheck(secret) => Msg::TotpSecretReady(secret),
                CURegState::TotpTryAgain => Msg::TotpTryAgain,
                CURegState::TotpInvalidSha1 => Msg::TotpInvalidSha1,
            })
        } else {
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(Msg::Error { emsg, kopid })
        }
    }
}

impl Component for TotpModalApp {
    type Message = Msg;
    type Properties = ModalProps;

    fn create(ctx: &Context<Self>) -> Self {
        console::log!("totp modal create");

        TotpModalApp {
            state: TotpState::Init,
            check: TotpCheck::Init,
            secret: TotpValue::Init,
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::log!("totp modal::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::log!("totp modal::update");
        let token_c = ctx.props().token.clone();
        match msg {
            Msg::TotpCancel => {
                // Cancel the totp req!
                // Should end up with a success?
                ctx.link().send_future(async {
                    match Self::submit_totp_update(token_c, CURequest::CancelMFAReg).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                self.state = TotpState::Waiting;
            }
            Msg::TotpSubmit => {
                // Send off the submit, lock the form.
                let totp =
                    utils::get_value_from_element_id("totp").unwrap_or_else(|| "".to_string());

                match totp.trim().parse::<u32>() {
                    Ok(totp) => {
                        ctx.link().send_future(async move {
                            match Self::submit_totp_update(token_c, CURequest::TotpVerify(totp))
                                .await
                            {
                                Ok(v) => v,
                                Err(v) => v.into(),
                            }
                        });
                        self.state = TotpState::Waiting;
                    }
                    Err(_) => {
                        self.check = TotpCheck::Invalid;
                        self.state = TotpState::Init;
                    }
                }
            }
            Msg::TotpGenerate => {
                // SEND OFF A REQUEST TO GET THE TOTP STRING
                let token_c = ctx.props().token.clone();

                ctx.link().send_future(async {
                    match Self::submit_totp_update(token_c, CURequest::TotpGenerate).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                self.secret = TotpValue::Waiting;
            }
            Msg::TotpSecretReady(secret) => {
                // THIS IS WHATS CALLED WHEN THE SECRET IS BACK
                self.secret = TotpValue::Secret(secret);
            }
            Msg::TotpTryAgain => {
                self.check = TotpCheck::Invalid;
                self.state = TotpState::Init;
            }
            // TODO: which status do we want to return?
            Msg::TotpClearInvalid => {
                self.check = TotpCheck::Init;
            }
            // this was originally lower in the code
            // Msg::TotpClearInvalid => {
            //     self.check = TotpCheck::Invalid;
            // }
            Msg::TotpInvalidSha1 => {
                self.check = TotpCheck::Sha1Accept;
                self.state = TotpState::Init;
            }
            Msg::TotpAcceptSha1 => {
                ctx.link().send_future(async {
                    match Self::submit_totp_update(token_c, CURequest::TotpAcceptSha1).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                self.state = TotpState::Waiting;
            }
            Msg::TotpSuccess => {
                // Nothing to do but close and hide!
                self.reset_and_hide();
            }
            Msg::Error { emsg, kopid } => {
                // Submit the error to the parent.
                EventBus::dispatcher().send(EventBusMsg::Error { emsg, kopid });
                self.reset_and_hide();
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
            TotpCheck::Invalid | TotpCheck::Sha1Accept => classes!("form-control", "is-invalid"),
            _ => classes!("form-control"),
        };

        let invalid_text = match &self.check {
            TotpCheck::Sha1Accept => "Your authenticator appears to be broken, and uses Sha1, rather than Sha256. Are you sure you want to proceed? If you want to try with a new authenticator, enter a new code",
            _ => "Incorrect TOTP code - Please try again",

        };

        let submit_enabled = matches!(&self.state, TotpState::Init);

        let submit_button = match &self.check {
            TotpCheck::Sha1Accept => html! {
                <button id="totp-submit" type="button" class="btn btn-warning"
                    disabled={ !submit_enabled }
                    onclick={
                        ctx.link()
                            .callback(move |_| {
                                Msg::TotpAcceptSha1
                            })
                    }
                >{ "Accept Sha1 Token" }</button>
            },
            _ => html! {
                <button id="totp-submit" type="button" class="btn btn-primary"
                    disabled={ !submit_enabled }
                    onclick={
                        ctx.link()
                            .callback(move |_| {
                                Msg::TotpSubmit
                            })
                    }
                >{ "Submit" }</button>
            },
        };

        let totp_secret_state = match &self.secret {
            TotpValue::Init => {
                html! {
                    <button id="totp-generate" type="button" class="btn btn-secondary"
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::TotpGenerate
                                })
                        }
                    >{ "Generate TOTP" }</button>
                }
            }
            TotpValue::Waiting => {
                html! {
                      <div class="spinner-border text-dark" role="status">
                        <span class="visually-hidden">{ "Loading..." }</span>
                      </div>
                }
            }
            TotpValue::Secret(secret) => {
                let qr = QrCode::new(secret.to_uri().as_str()).unwrap_throw();

                let svg = qr.render::<svg::Color>().build();

                #[allow(clippy::unwrap_used)]
                let div = utils::document().create_element("div").unwrap();

                div.set_inner_html(svg.as_str());

                let node: Node = div.into();
                let svg_html = Html::VRef(node);

                let accountname = format!("Account Name: {}", secret.accountname);
                let issuer = format!("Issuer: {}", secret.issuer);
                let secret_b32 = format!("Secret: {}", secret.get_secret());
                let algo = format!("Algorithm: {}", secret.algo);
                let step = format!("Time Step: {}", secret.step);

                html! {
                    <>
                      <div class="col-8">
                        { svg_html }
                      </div>
                      <div class="col-4">
                        <p>{ accountname }</p>
                        <p>{ issuer }</p>
                        <p>{ secret_b32 }</p>
                        <p>{ algo }</p>
                        <p>{ step }</p>

                      </div>
                    </>
                }
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

                    <div class="container">
                      <div class="row">
                        { totp_secret_state }
                      </div>
                    </div>

                    <form class="row g-3 needs-validation" novalidate=true
                        onsubmit={ ctx.link().callback(|e: FocusEvent| {
                            e.prevent_default();
                            Msg::TotpSubmit
                        } ) }
                    >
                      <label for="totp" class="form-label">{ "Enter a TOTP" }</label>
                      <input
                        type="totp"
                        class={ totp_class }
                        id="totp"
                        placeholder=""
                        aria-describedby="totp-validation-feedback"
                        required=true
                        oninput={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::TotpClearInvalid
                                })
                        }
                      />
                      <div id="totp-validation-feedback" class="invalid-feedback">
                        { invalid_text }
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
                    { submit_button }
                  </div>
                </div>
              </div>
            </div>
        }
    }
}
