use crate::utils;
#[cfg(debug_assertions)]
use gloo::console;
use kanidm_proto::v1::{CUIntentToken, UserAuthToken};
use yew::prelude::*;

use qrcode::render::svg;
use qrcode::QrCode;
use wasm_bindgen::UnwrapThrowExt;
use web_sys::Node;

use crate::error::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestCredentials, RequestInit, RequestMode, Response};

enum State {
    Valid,
    Error { emsg: String, kopid: Option<String> },
}

#[allow(dead_code)]
enum CodeState {
    Waiting,
    Ready { token: CUIntentToken },
}

#[allow(dead_code)]
pub enum Msg {
    Activate,
    Ready { token: CUIntentToken },
    Dismiss,
    Error { emsg: String, kopid: Option<String> },
}

impl From<FetchError> for Msg {
    fn from(fe: FetchError) -> Self {
        Msg::Error {
            emsg: fe.as_string(),
            kopid: None,
        }
    }
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

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        match msg {
            Msg::Activate => {
                #[cfg(debug_assertions)]
                console::debug!("modal activate");

                let uat = &ctx.props().uat;
                let id = uat.uuid.to_string();

                ctx.link().send_future(async {
                    match Self::credential_get_update_intent_token(id).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                true
            }
            Msg::Error { emsg, kopid } => {
                self.code_state = CodeState::Waiting;
                self.state = State::Error { emsg, kopid };
                true
            }
            Msg::Dismiss => {
                self.code_state = CodeState::Waiting;
                self.state = State::Valid;
                utils::modal_hide_by_id(crate::constants::ID_CRED_RESET_CODE);
                true
            }
            Msg::Ready { token } => {
                self.state = State::Valid;
                self.code_state = CodeState::Ready { token };
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
                let reset_link = html! {
                    <a href={ url.to_string() }>{ url.to_string() }</a>
                };
                url.to_string();

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
                      <div class="col-6">
                        { svg_html }
                      </div>
                      <div class="col-5">
                        <p>{ reset_link }</p>
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
              <div class="modal-dialog modal-lg" role="document">
                    <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">{"Update your Authentication Settings on Another Device"}</h5>
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
                          <div class="row">
                            <p>{ "You can add another device to your account by scanning this qr code, or going to the url above and entering in the code." }</p>
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
    async fn credential_get_update_intent_token(id: String) -> Result<Msg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::SameOrigin);
        opts.credentials(RequestCredentials::SameOrigin);

        let uri = format!("/v1/person/{}/_credential/_update_intent?ttl=0", id);

        let request = Request::new_with_str_and_init(uri.as_str(), &opts)?;

        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
        let status = resp.status();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let token: CUIntentToken =
                serde_wasm_bindgen::from_value(jsval).expect_throw("Invalid response type");
            Ok(Msg::Ready { token })
        } else {
            let headers = resp.headers();
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_default();
            // let jsval_json = JsFuture::from(resp.json()?).await?;
            Ok(Msg::Error { emsg, kopid })
        }
    }
}
