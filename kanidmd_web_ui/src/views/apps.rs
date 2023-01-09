#[cfg(debug_assertions)]
use gloo::console;
use yew::prelude::*;

use crate::constants::{CSS_CARD, CSS_LINK_DARK_STRETCHED, CSS_PAGE_HEADER};
use crate::error::FetchError;
use crate::utils;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestCredentials, RequestInit, RequestMode, Response};

use kanidm_proto::internal::AppLink;

pub enum Msg {
    Ready { apps: Vec<AppLink> },
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

pub enum State {
    Waiting,
    Ready { apps: Vec<AppLink> },
    Error { emsg: String, kopid: Option<String> },
}

pub struct AppsApp {
    state: State,
}

impl Component for AppsApp {
    type Message = Msg;
    type Properties = ();

    fn create(ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("views::apps::create");

        ctx.link().send_future(async {
            match Self::fetch_user_apps().await {
                Ok(v) => v,
                Err(v) => v.into(),
            }
        });

        let state = State::Waiting;

        AppsApp { state }
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("views::apps::changed");
        false
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("views::apps::update");
        match msg {
            Msg::Ready { apps } => self.state = State::Ready { apps },
            Msg::Error { emsg, kopid } => self.state = State::Error { emsg, kopid },
        }

        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("views::apps::rendered");
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        match &self.state {
            State::Waiting => self.view_waiting(),
            State::Ready { apps } => self.view_ready(ctx, apps.as_slice()),
            State::Error { emsg, kopid } => self.view_error(ctx, emsg, kopid.as_deref()),
        }
    }
}

impl AppsApp {
    fn view_waiting(&self) -> Html {
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

    fn view_ready(&self, _ctx: &Context<Self>, apps: &[AppLink]) -> Html {
        // Please help me, I don't know how to make a grid look nice 🥺
        html! {
            <>
        <div class={CSS_PAGE_HEADER}>
        <h2>{ "Applications list" }</h2>
        </div>
          if !apps.is_empty() {
            <div class="row row-cols-1 row-cols-sm-2 row-cols-md-3 g-3">
                {
                    apps.iter().map(|applink| {
                    match &applink {
                        AppLink::Oauth2 {
                            name: _,
                            display_name,
                            redirect_url,
                            icon: _,
                        } => {
                            let redirect_url = redirect_url.to_string();
                            html!{
                                <div class="col-md-3">
                                    <div class={CSS_CARD}>
                                    <a href={ redirect_url.clone() } class={CSS_LINK_DARK_STRETCHED}>
                                    <img src={"/pkg/img/icon-oauth2.svg"} />
                                    </a>
                                        <h5>{ display_name }</h5>
                                    </div>
                                </div>
                            }
                        }
                    }
                    }).collect::<Html>()
                }
                </div>
            }
        </>
        }
    }

    fn view_error(&self, _ctx: &Context<Self>, msg: &str, kopid: Option<&str>) -> Html {
        html! {
          <>
            <p class="text-center">
                <img src="/pkg/img/logo-square.svg" alt="Kanidm" class="kanidm_logo"/>
            </p>
            <div class="alert alert-danger" role="alert">
              <h2>{ "An Error Occurred 🥺" }</h2>
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
            </div>
            <p class="text-center">
              <a href="/"><button href="/" class="btn btn-secondary" aria-label="Return home">{"Return to the home page"}</button></a>
            </p>
          </>
        }
    }

    async fn fetch_user_apps() -> Result<Msg, FetchError> {
        let mut opts = RequestInit::new();
        opts.method("GET");
        opts.mode(RequestMode::SameOrigin);
        opts.credentials(RequestCredentials::SameOrigin);

        let request = Request::new_with_str_and_init("/v1/self/_applinks", &opts)?;

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
            let apps: Vec<AppLink> = serde_wasm_bindgen::from_value(jsval)
                .expect_throw("Invalid response type - auth_init::AuthResponse");
            Ok(Msg::Ready { apps })
        } else {
            let headers = resp.headers();
            let kopid = headers.get("x-kanidm-opid").ok().flatten();
            let text = JsFuture::from(resp.text()?).await?;
            let emsg = text.as_string().unwrap_or_default();
            Ok(Msg::Error { emsg, kopid })
        }
    }
}
