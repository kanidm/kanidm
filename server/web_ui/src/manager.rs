//! This is the top level router of the web ui for kanidm. It decides based on the incoming
//! request, where to direct this too, and if the requirements for that request have been
//! met before rendering. For example, if you land here with an oauth request, but you are
//! not authenticated, this will determine that and send you to authentication first, then
//! will allow you to proceed with the oauth flow.

use std::rc::Rc;

use gloo::console;
use i18n_embed::LanguageLoader;
use i18n_embed::unic_langid::LanguageIdentifier;
use i18n_embed_fl::fl;
use serde::{Deserialize, Serialize};
use wasm_bindgen::UnwrapThrowExt;
use yew::functional::*;
use yew::prelude::*;
use yew_router::prelude::*;

use crate::credential::reset::CredentialResetApp;
use crate::login::{LoginApp, LoginWorkflow};
use crate::oauth2::Oauth2App;
use crate::views::{ViewRoute, ViewsApp};

use i18n_embed::{WebLanguageRequester, fluent::{
    FluentLanguageLoader, fluent_language_loader
}};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "i18n"]
struct Localizations;

// router to decide on state.
#[derive(Routable, PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub enum Route {
    #[at("/ui")]
    Landing,

    #[at("/ui/login")]
    Login,

    #[at("/ui/reauth")]
    Reauth,

    #[at("/ui/oauth2")]
    Oauth2,

    #[at("/ui/reset")]
    CredentialReset,

    #[not_found]
    #[at("/ui/404")]
    NotFound,

    #[at("/ui/*")]
    Views,
}

#[function_component(Landing)]
fn landing() -> Html {
    #[cfg(debug_assertions)]
    console::debug!("manager::landing");
    // Do this to allow use_navigator to work because lol.
    yew_router::hooks::use_navigator()
        .expect_throw("Unable to access history")
        .push(&ViewRoute::Apps);
    html! { <main></main> }
}

#[function_component]
fn NotFound() -> Html {
    let i18n = use_context::<Rc<I18n>>().unwrap();

    html! {
        <>
        <main class="flex-shrink-0 form-signin text-center">
                <img src="/pkg/img/logo-square.svg" alt="Kanidm" class="kanidm_logo"/>
                // TODO: replace this with a call to domain info
                <h3>{ fl!(i18n.i18n, "page-not-found") }</h3>

                <div class="container">
                <Link<ViewRoute> to={ ViewRoute::Apps }>
                { fl!(i18n.i18n, "goto-home") }
                </Link<ViewRoute>>
                </div>
        </main>
        { crate::utils::do_footer() }
        </>
    }
}

// Needed for yew to pass by value
#[allow(clippy::needless_pass_by_value)]
fn switch(route: Route) -> Html {
    #[cfg(debug_assertions)]
    console::debug!(format!("manager::switch -> {:?}", route).as_str());
    match route {
        #[allow(clippy::let_unit_value)]
        Route::Landing => html! { <Landing /> },
        #[allow(clippy::let_unit_value)]
        Route::Login => html! { <LoginApp workflow={ LoginWorkflow::Login } /> },
        #[allow(clippy::let_unit_value)]
        Route::Reauth => html! { <LoginApp workflow={ LoginWorkflow::Reauth } /> },
        #[allow(clippy::let_unit_value)]
        Route::Oauth2 => html! { <Oauth2App /> },
        #[allow(clippy::let_unit_value)]
        Route::Views => html! { <ViewsApp /> },
        #[allow(clippy::let_unit_value)]
        Route::CredentialReset => html! { <CredentialResetApp /> },
        Route::NotFound => {
            add_body_form_classes!();

            html! { <NotFound /> }
        }
    }
}

#[derive(Clone, Debug)]
pub struct I18n {
    pub i18n: Rc<FluentLanguageLoader>
}

impl I18n {
    fn new() -> I18n {
        let loader: FluentLanguageLoader = fluent_language_loader!();
        let requested_languages = {
            let mut it = WebLanguageRequester::requested_languages();
            it.push(loader.fallback_language().clone());
            it
        };

        let languages_vec = requested_languages.iter().map(|it| it).collect::<Vec<&LanguageIdentifier>>();
        let languages = languages_vec.as_slice();
        let _ = loader
            .load_languages(&Localizations, &languages)
            .map_err(|err| {
                console::warn!("issue loading i18n: {}", err.to_string());
            });

        I18n { i18n: loader.into() }
    }
}

impl PartialEq for I18n {
    fn eq(&self, _rhs: &I18n) -> bool {
        true
    }
}

pub struct ManagerApp {
    i18n: Rc<I18n>
}

impl Component for ManagerApp {
    type Message = ();
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        #[cfg(debug_assertions)]
        console::debug!("manager::create");
        ManagerApp { i18n: I18n::new().into() }
    }

    fn changed(&mut self, _ctx: &Context<Self>, _props: &Self::Properties) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("manager::change");
        false
    }

    fn update(&mut self, _ctx: &Context<Self>, _msg: Self::Message) -> bool {
        #[cfg(debug_assertions)]
        console::debug!("manager::update");
        true
    }

    fn rendered(&mut self, _ctx: &Context<Self>, _first_render: bool) {
        #[cfg(debug_assertions)]
        console::debug!("manager::rendered");
        // Can only access the current_route AFTER it renders.
        // console::debug!(format!("{:?}", yew_router::current_route::<Route>()).as_str())
    }

    fn view(&self, _ctx: &Context<Self>) -> Html {
        html! {
            <ContextProvider<Rc<I18n>> context={self.i18n.clone()}>
                <BrowserRouter>
                    <Switch<Route> render={ switch } />
                </BrowserRouter>
            </ContextProvider<Rc<I18n>>>
        }
    }
}
