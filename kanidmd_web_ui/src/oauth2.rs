use anyhow::Error;
use yew::format::{Json, Nothing};
use yew::prelude::*;
use yew_services::fetch::{FetchOptions, FetchService, FetchTask, Redirect, Request, Response};
use yew_services::ConsoleService;

use crate::manager::Route;
use crate::models;

pub use kanidm_proto::oauth2::{
    AccessTokenRequest, AccessTokenResponse, AuthorisationRequest, CodeChallengeMethod,
    ConsentRequest, ErrorResponse,
};

enum State {
    // We don't have a token, or something is invalid.
    LoginRequired,
    // We are in the process of check the auth token to be sure we can proceed.
    TokenCheck(String, FetchTask),
    // Token check done, lets do it.
    SubmitAuthReq(String, FetchTask),
    Consent(String, ConsentRequest),
    ConsentGranted(FetchTask),
    ErrInvalidRequest,
}

pub struct Oauth2App {
    link: ComponentLink<Self>,
    state: State,
}

pub enum Oauth2Msg {
    LoginProceed,
    ConsentGranted,
    TokenValid,
    Consent(ConsentRequest),
    Redirect(String),
    Error { emsg: String, kopid: Option<String> },
}

impl Oauth2App {
    fn fetch_token_valid(token: &str, link: &ComponentLink<Self>) -> Result<FetchTask, String> {
        let callback = link.callback(move |response: Response<Result<String, Error>>| {
            let (parts, body) = response.into_parts();

            if parts.status.is_success() {
                Oauth2Msg::TokenValid
            } else if parts.status == 401 {
                Oauth2Msg::LoginProceed
            } else {
                Oauth2Msg::Error {
                    emsg: body.unwrap_or_else(|_| "".to_string()),
                    kopid: parts
                        .headers
                        .get("x-kanidm-opid")
                        .map(|id| id.to_str().unwrap().to_string()),
                }
            }
        });

        Request::get("/v1/auth/valid")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", token))
            .body(Nothing)
            .map_err(|e| format!("{:?}", e))
            .and_then(|request| {
                FetchService::fetch(request, callback).map_err(|e| format!("{:?}", e))
            })
    }

    fn fetch_authreq(
        token: &str,
        authreq: &AuthorisationRequest,
        link: &ComponentLink<Self>,
    ) -> Result<FetchTask, String> {
        let callback = link.callback(
            move |response: Response<Json<Result<ConsentRequest, Error>>>| {
                let (parts, body) = response.into_parts();

                match body {
                    Json(Ok(state)) => Oauth2Msg::Consent(state),
                    Json(Err(e)) => Oauth2Msg::Error {
                        emsg: format!("{:?}", e),
                        kopid: parts
                            .headers
                            .get("x-kanidm-opid")
                            .map(|id| id.to_str().unwrap().to_string()),
                    },
                }
            },
        );

        Request::post("/oauth2/authorise")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", token))
            .body(Json(authreq))
            .map_err(|e| format!("{:?}", e))
            .and_then(|request| {
                FetchService::fetch_binary(request, callback).map_err(|e| format!("{:?}", e))
            })
    }

    fn fetch_consent_token(
        token: &str,
        consent_token: String,
        link: &ComponentLink<Self>,
    ) -> Result<FetchTask, String> {
        let callback = link.callback(move |response: Response<Result<Vec<u8>, Error>>| {
            let (parts, _body) = response.into_parts();

            let kopid = parts
                .headers
                .get("x-kanidm-opid")
                .map(|id| id.to_str().unwrap().to_string());

            if parts.status == 200 {
                if let Some(loc) = parts
                    .headers
                    .get("location")
                    .and_then(|hv| hv.to_str().ok().map(str::to_string))
                {
                    Oauth2Msg::Redirect(loc)
                } else {
                    Oauth2Msg::Error {
                        emsg: "no location header".to_string(),
                        kopid,
                    }
                }
            } else {
                Oauth2Msg::Error {
                    emsg: "Redirect error".to_string(),
                    kopid,
                }
            }
        });

        let options = FetchOptions {
            cache: None,
            credentials: None,
            redirect: Some(Redirect::Manual),
            mode: None,
            referrer: None,
            referrer_policy: None,
            integrity: None,
        };

        Request::post("/oauth2/authorise/permit")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", token))
            .body(Json(&consent_token))
            .map_err(|e| format!("{:?}", e))
            .and_then(|request| {
                FetchService::fetch_binary_with_options(request, options, callback)
                    .map_err(|e| format!("{:?}", e))
            })
    }
}

impl Component for Oauth2App {
    type Message = Oauth2Msg;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        ConsoleService::log("oauth2::create");

        // Do we have a query here?
        // Did we get sent a valid Oauth2 request?
        let query: Option<AuthorisationRequest> = yew_router::parse_query()
            .map_err(|e| {
                let e_msg = format!("lstorage error -> {:?}", e);
                ConsoleService::log(e_msg.as_str());
            })
            .ok()
            .or_else(|| {
                ConsoleService::log("pop_oauth2_authorisation_request");
                models::pop_oauth2_authorisation_request()
            });

        // If we have neither we need to say that we can not proceed at all.
        let query = match query {
            Some(q) => q,
            None => {
                return Oauth2App {
                    link,
                    state: State::ErrInvalidRequest,
                };
            }
        };

        let e_msg = format!("{:?}", query);
        ConsoleService::log(e_msg.as_str());

        // Push the request down. This covers if we move to LoginRequired.
        models::push_oauth2_authorisation_request(query);

        match models::get_bearer_token() {
            Some(token) => {
                // Start the fetch req.
                // Put the fetch handle into the consent type.
                match Self::fetch_token_valid(token.as_str(), &link) {
                    Ok(ft) => Oauth2App {
                        link,
                        state: State::TokenCheck(token, ft),
                    },
                    Err(e_msg) => {
                        ConsoleService::log(e_msg.as_str());
                        Oauth2App {
                            link,
                            state: State::ErrInvalidRequest,
                        }
                    }
                }
            }
            None => Oauth2App {
                link,
                state: State::LoginRequired,
            },
        }
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        ConsoleService::log("oauth2::change");
        false
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        ConsoleService::log("oauth2::update");

        match msg {
            Oauth2Msg::LoginProceed => {
                models::push_return_location(models::Location::Oauth2);
                yew_router::push_route(Route::Login);
                // Don't need to redraw as we are yolo-ing out.
                false
            }
            Oauth2Msg::TokenValid => {
                // Okay we can proceed, pop the query.
                let ar = models::pop_oauth2_authorisation_request();

                self.state = match (&self.state, ar) {
                    (State::TokenCheck(token, _), Some(ar)) => {
                        match Self::fetch_authreq(&token, &ar, &self.link) {
                            Ok(ft) => State::SubmitAuthReq(token.clone(), ft),
                            Err(e_msg) => {
                                ConsoleService::log(e_msg.as_str());
                                State::ErrInvalidRequest
                            }
                        }
                    }
                    _ => {
                        ConsoleService::log("Invalid state transition");
                        State::ErrInvalidRequest
                    }
                };
                true
            }
            Oauth2Msg::Consent(consent_req) => {
                self.state = match &self.state {
                    State::SubmitAuthReq(token, _) => State::Consent(token.clone(), consent_req),
                    _ => {
                        ConsoleService::log("Invalid state transition");
                        State::ErrInvalidRequest
                    }
                };
                true
            }
            Oauth2Msg::ConsentGranted => {
                self.state = match &self.state {
                    State::Consent(token, consent_req) => {
                        match Self::fetch_consent_token(
                            &token,
                            consent_req.consent_token.clone(),
                            &self.link,
                        ) {
                            Ok(ft) => State::ConsentGranted(ft),
                            Err(e) => {
                                ConsoleService::log(e.as_str());
                                State::ErrInvalidRequest
                            }
                        }
                    }
                    _ => {
                        ConsoleService::log("Invalid state transition");
                        State::ErrInvalidRequest
                    }
                };
                // We need to send off fetch task here.
                true
            }
            Oauth2Msg::Error { emsg, kopid } => {
                self.state = State::ErrInvalidRequest;
                ConsoleService::log(format!("{:?}", kopid).as_str());
                ConsoleService::log(emsg.as_str());
                true
            }
            Oauth2Msg::Redirect(loc) => {
                ConsoleService::log(format!("Redirecting to {}", loc).as_str());
                // Send the location here, and then update will trigger the redir via
                // https://docs.rs/web-sys/0.3.51/web_sys/struct.Location.html#method.replace
                // see https://developer.mozilla.org/en-US/docs/Web/API/Location/replace
                let location = yew::utils::window().location();
                match location.replace(loc.as_str()) {
                    // No need to redraw, we are leaving.
                    Ok(_) => false,
                    Err(e) => {
                        // Something went bang, opps.
                        ConsoleService::log(format!("{:?}", e).as_str());
                        self.state = State::ErrInvalidRequest;
                        true
                    }
                }
            }
        }
    }

    fn rendered(&mut self, _first_render: bool) {
        ConsoleService::log("oauth2::rendered");
    }

    fn view(&self) -> Html {
        match &self.state {
            State::LoginRequired => {
                html! {
                    <body class="html-body form-body">
                    <main class="form-signin">
                      <form>
                        <h1 class="h3 mb-3 fw-normal">{" Sign in to proceed" }</h1>
                        <button class="w-100 btn btn-lg btn-primary" type="submit" onclick=self.link.callback(|_| Oauth2Msg::LoginProceed)>{ "Sign in" }</button>
                      </form>
                    </main>
                    </body>
                }
            }
            State::Consent(_, query) => {
                let client_name = query.client_name.clone();

                html! {
                    <body class="html-body form-body">
                    <main class="form-signin">
                      <form>
                        <h1 class="h3 mb-3 fw-normal">{"Consent to Proceed to " }{ client_name }</h1>
                        <button class="w-100 btn btn-lg btn-primary" type="submit" onclick=self.link.callback(|_| Oauth2Msg::ConsentGranted)>{ "Proceed" }</button>
                      </form>
                    </main>
                    </body>
                }
            }
            State::ConsentGranted(_) | State::SubmitAuthReq(_, _) | State::TokenCheck(_, _) => {
                html! { <body> <h1>{ " ... " }</h1>  </body> }
            }
            State::ErrInvalidRequest => {
                html! { <body> <h1>{ " ❌ " }</h1>  </body> }
            }
        }
    }

    fn destroy(&mut self) {
        ConsoleService::log("oauth2::destroy");
    }
}
