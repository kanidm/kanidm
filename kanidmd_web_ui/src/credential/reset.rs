use gloo::console;
use yew::prelude::*;
use yew_router::prelude::*;
use crate::utils;

use wasm_bindgen::UnwrapThrowExt;
use kanidm_proto::v1::{CUIntentToken, CUSessionToken, CUStatus};

use crate::error::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, RequestRedirect, Response};

pub enum Msg {
    TokenSubmit,
    BeginSession { token: CUSessionToken, status: CUStatus },
    UpdateSession { status: CUStatus },
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

enum State {
    TokenInput,
    WaitingForStatus,
    Main { token: CUSessionToken, status: CUStatus },
    Error { emsg: String, kopid: Option<String> },
}

pub struct CredentialResetApp {
    state: State,
}

impl Component for CredentialResetApp {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        console::log!("credential::reset::create");

        // Inject our class to centre everything.
        if let Err(e) = crate::utils::body().class_list().add_1("form-signin-body") {
            console::log!(format!("class_list add error -> {:?}", e));
        };

        /* Were we given a token for the reset? */

        let location = ctx
            .link()
            .location()
            .expect_throw("Can't access current location");

        let query: Option<CUIntentToken> = location
            .query()
            .map_err(|e| {
                let e_msg = format!("query decode error -> {:?}", e);
                console::log!(e_msg.as_str());
            })
            .ok();

        let state = match query {
            Some(cu_intent) => {
                // Go straight to go! Collect 200!
                ctx.link().send_future(async {
                    match Self::exchange_intent_token(cu_intent.token).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });
                State::WaitingForStatus
            }
            None => State::TokenInput,
        };

        CredentialResetApp {
            state
        }
    }

    fn changed(&mut self, _ctx: &Context<Self>) -> bool {
        console::log!("credential::reset::change");
        false
    }

    fn update(&mut self, ctx: &Context<Self>, msg: Self::Message) -> bool {
        console::log!("credential::reset::update");
        let mut next_state = match (msg, &self.state) {
            (Msg::TokenSubmit, State::TokenInput) => {
                let token = utils::get_value_from_element_id("autofocus")
                    .expect("No token");

                ctx.link().send_future(async {
                    match Self::exchange_intent_token(token).await {
                        Ok(v) => v,
                        Err(v) => v.into(),
                    }
                });

                State::WaitingForStatus
            }
            (Msg::BeginSession { token, status }, State::WaitingForStatus) => {
                console::log!(format!("{:?}", status).as_str());

                State::Main { token, status }
            }
            (Msg::Error { emsg, kopid }, _) => State::Error { emsg, kopid },
            (_ , _) => unreachable!(),
        };

        std::mem::swap(&mut self.state, &mut next_state);
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        crate::utils::autofocus();
        console::log!("credential::reset::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        console::log!("credential::reset::view");
        match &self.state {
            State::TokenInput => self.view_token_input(ctx),
            State::WaitingForStatus => self.view_waiting(ctx),
            State::Main { token, status } => self.view_main(ctx, &status),
            State::Error{ emsg, kopid } => self.view_error(ctx, &emsg, kopid.as_deref()),
        }
    }

    fn destroy(&mut self, _ctx: &Context<Self>) {
        console::log!("credential::reset::destroy");
        if let Err(e) = crate::utils::body()
            .class_list()
            .remove_1("form-signin-body")
        {
            console::log!(format!("class_list remove error -> {:?}", e));
        }
    }
}

impl CredentialResetApp {
    fn view_token_input(&self, ctx: &Context<Self>) -> Html {
        html! {
          <main class="form-signin">
            <div class="container">
              <p>
                {"Enter your credential reset token"}
              </p>
            </div>
            <div class="container">
              <form
                  onsubmit={ ctx.link().callback(|e: FocusEvent| {
                      console::log!("credential::reset::view_token_input -> TokenInput - prevent_default()");
                      e.prevent_default();

                      Msg::TokenSubmit
                  } ) }
                  action="javascript:void(0);"
              >
                  <input
                      id="autofocus"
                      type="text"
                      class="form-control"
                      value=""
                  />
                  <button type="submit" class="btn btn-dark">{" Submit "}</button>
              </form>
            </div>
          </main>
        }
    }

    fn view_waiting(&self, ctx: &Context<Self>) -> Html {
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

    fn view_main(&self, ctx: &Context<Self>, status: &CUStatus) -> Html {
        html! {
          <main class="form-signin">
          </main>
        }
    }

    fn view_error(&self, ctx: &Context<Self>, msg: &str, kopid: Option<&str>) -> Html {
        html! {
          <main class="form-signin">
            <div class="container">
              <h2>{ "An Error Occured 🥺" }</h2>
            </div>
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
          </main>
        }
    }


    async fn exchange_intent_token(token: String) -> Result<Msg, FetchError> {
        let intentreq_jsvalue = serde_json::to_string(&CUIntentToken {
            token
        })
            .map(|s| JsValue::from(&s))
            .expect_throw("Failed to serialise intent request");

        let mut opts = RequestInit::new();
        opts.method("POST");
        opts.mode(RequestMode::SameOrigin);

        opts.body(Some(&intentreq_jsvalue));

        let request = Request::new_with_str_and_init("/v1/credential/_exchange_intent", &opts)?;
        request
            .headers()
            .set("content-type", "application/json")
            .expect_throw("failed to set header");

        let window = utils::window();
        let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
        let resp: Response = resp_value.dyn_into().expect_throw("Invalid response type");
        let status = resp.status();
        let headers = resp.headers();

        if status == 200 {
            let jsval = JsFuture::from(resp.json()?).await?;
            let (token, status): (CUSessionToken, CUStatus) = jsval.into_serde().expect_throw("Invalid response type");
            Ok(Msg::BeginSession { token, status })
        } else {
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_else(|| "".to_string());
            Ok(Msg::Error { emsg, kopid })
        }
    }
}



