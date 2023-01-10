#[cfg(debug_assertions)]
use gloo::console;
use kanidm_proto::v1::{CURegState, CURequest, CUSessionToken, CUStatus, TotpSecret};
use qrcode::render::svg;
use qrcode::QrCode;
use wasm_bindgen::{JsCast, JsValue, UnwrapThrowExt};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Node, Request, RequestInit, RequestMode, Response};
use yew::prelude::*;

use super::reset::{EventBusMsg, ModalProps};
use crate::error::*;
use crate::utils;

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

    async fn submit_totp_update(
        token: CUSessionToken,
        req: CURequest,
        cb: Callback<EventBusMsg>,
    ) -> Result<Msg, FetchError> {
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
            let status: CUStatus =
                serde_wasm_bindgen::from_value(jsval).expect_throw("Invalid response type");

            cb.emit(EventBusMsg::UpdateStatus {
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
            let emsg = text.as_string().unwrap_or_default();
            Ok(Msg::Error { emsg, kopid })
        }
    }
}

impl Component for TotpModalApp {
    type Message = Msg;
    type Properties = ModalProps;

    fn create(_ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("totp modal create");

        TotpModalApp {
            state: TotpState::Init,
            check: TotpCheck::Init,
            secret: TotpValue::Init,
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("totp modal::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("totp modal::update");
        let token_c = ctx.props().token.clone();
        let cb = ctx.props().cb.clone();
        match msg {
            Msg::TotpCancel => {
                // Cancel the totp req!
                // Should end up with a success?
                ctx.link().send_future(async {
                    match Self::submit_totp_update(token_c, CURequest::CancelMFAReg, cb).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                self.state = TotpState::Waiting;
            }
            Msg::TotpSubmit => {
                // Send off the submit, lock the form.
                // default is empty str
                let totp = utils::get_value_from_element_id("totp").unwrap_or_default();

                match totp.trim().parse::<u32>() {
                    Ok(totp) => {
                        ctx.link().send_future(async move {
                            match Self::submit_totp_update(token_c, CURequest::TotpVerify(totp), cb)
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
                ctx.link().send_future(async {
                    match Self::submit_totp_update(token_c, CURequest::TotpGenerate, cb).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                self.secret = TotpValue::Waiting;
            }
            Msg::TotpSecretReady(secret) => {
                // THIS IS WHAT'S CALLED WHEN THE SECRET IS BACK
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
                    match Self::submit_totp_update(token_c, CURequest::TotpAcceptSha1, cb).await {
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
                cb.emit(EventBusMsg::Error { emsg, kopid });
                self.reset_and_hide();
            }
        };
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("totp modal::rendered");
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        #[cfg(debug_assertions)]
        console::debug!("totp modal::destroy");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        #[cfg(debug_assertions)]
        console::debug!("totp modal::view");

        let totp_class = match &self.check {
            TotpCheck::Invalid | TotpCheck::Sha1Accept => classes!("form-control", "is-invalid"),
            _ => classes!("form-control"),
        };

        let invalid_text = match &self.check {
            // TODO it'd be handy to link to some kind of explainer here.
            TotpCheck::Sha1Accept => "Your authenticator appears to be implemented in a way that uses SHA1, rather than SHA256. Are you sure you want to proceed? If you want to try with a new authenticator, enter a new code.",
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
                >{ "Accept SHA1 Token" }</button>
            },
            _ => html! {
                <button
                    class="btn btn-primary"
                    disabled={ !submit_enabled }
                    id="totp-submit"
                    onclick={
                        ctx.link()
                        .callback(move |_| {
                            Msg::TotpSubmit
                        })
                    }
                    type="button"
                >{ "Submit" }</button>
            },
        };

        let totp_secret_state = match &self.secret {
            // TODO: change this so it automagically starts the cred update session once the modal is created.
            TotpValue::Init => {
                html! {
                    <button
                        class="btn btn-secondary"
                        id="totp-generate"
                        type="button"
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::TotpGenerate
                                })
                        }
                    >{ "Click here to start the TOTP registration process" }</button>
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
                    <button
                        aria-label="Close"
                        class="btn-close"
                        onclick={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::TotpCancel
                                })
                        }
                        type="button"
                    ></button>
                  </div>
                  <div class="modal-body">

                    <div class="container">
                      <div class="row">
                        { totp_secret_state }
                      </div>
                    </div>

                    {
                    match &self.secret {
                        TotpValue::Secret(secret)  => {
                    html! {
                        <form class="row g-3 needs-validation" novalidate=true
                        onsubmit={ ctx.link().callback(|e: SubmitEvent| {
                            e.prevent_default();
                            Msg::TotpSubmit
                        } ) }
                    >
                    // TODO: the wording on this needs some improving.
                      <label for="totp_uri" class="form-label">{ "If your application accepts a URL, copy the one below" }</label>
                      <input
                        class="form-control"
                        required=false
                        type="text"
                        value={secret.to_uri()}
                       />

                      <label for="totp" class="form-label">{ "Enter a TOTP code to confirm it's working" }</label>
                      <input
                        aria-describedby="totp-validation-feedback"
                        class={ totp_class }
                        id="totp"
                        oninput={
                            ctx.link()
                                .callback(move |_| {
                                    Msg::TotpClearInvalid
                                })
                        }
                        placeholder=""
                        required=true
                        type="totp"
                      />
                      <div id="totp-validation-feedback" class="invalid-feedback">
                        { invalid_text }
                      </div>
                    </form>
                    }
                    },
                    _ => html!{}
                }
            }

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
