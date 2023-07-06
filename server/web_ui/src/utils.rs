use gloo::console;
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, UnwrapThrowExt};
pub use web_sys::InputEvent;
use web_sys::{Document, HtmlElement, HtmlInputElement, Window};
use yew::virtual_dom::VNode;
use yew::{html, Html};

pub fn window() -> Window {
    web_sys::window().expect_throw("Unable to retrieve window")
}

pub fn document() -> Document {
    window()
        .document()
        .expect_throw("Unable to retrieve document")
}

pub fn body() -> HtmlElement {
    document().body().expect_throw("Unable to retrieve body")
}

pub fn origin() -> Url {
    let uri_string = document()
        .document_uri()
        .expect_throw("Unable to access document uri");
    let mut url = Url::parse(&uri_string).expect_throw("Unable to parse document uri");
    url.set_path("/");
    url
}

pub fn autofocus(target: &str) {
    // If an element with an id attribute matching 'target' exists, focus it.
    let doc = document();
    if let Some(element) = doc.get_element_by_id(target) {
        if let Ok(htmlelement) = element.dyn_into::<web_sys::HtmlElement>() {
            if htmlelement.focus().is_err() {
                console::warn!(
                    "unable to autofocus element, couldn't find target with id '{}'",
                    target
                );
            }
        }
    }
}

// pub fn get_value_from_input_event(e: InputEvent) -> String {
//     let event: Event = e.dyn_into().unwrap_throw();
//     let event_target = event.target().unwrap_throw();
//     let target: HtmlInputElement = event_target.dyn_into().unwrap_throw();
//     target.value()
// }

// pub fn get_element_by_id(id: &str) -> Option<HtmlElement> {
//     document()
//         .get_element_by_id(id)
//         .and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok())
// }

// pub fn get_buttonelement_by_id(id: &str) -> Option<HtmlButtonElement> {
//     document()
//         .get_element_by_id(id)
//         .and_then(|element| element.dyn_into::<web_sys::HtmlButtonElement>().ok())
// }

pub fn get_inputelement_by_id(id: &str) -> Option<HtmlInputElement> {
    document()
        .get_element_by_id(id)
        .and_then(|element| element.dyn_into::<web_sys::HtmlInputElement>().ok())
}

pub fn get_value_from_element_id(id: &str) -> Option<String> {
    document()
        .get_element_by_id(id)
        .and_then(|element| element.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|element| element.value())
}

#[wasm_bindgen(raw_module = "/pkg/wasmloader.js")]
extern "C" {
    pub fn modal_hide_by_id(m: &str);
}

/// Returns the footer node for the UI
pub fn do_footer() -> VNode {
    html! {
        <footer class="footer mt-auto py-3 bg-light text-end">
            <div class="container">
                <span class="text-muted">{ "Powered by "  }<a href="https://kanidm.com">{ "Kanidm" }</a></span>
            </div>
        </footer>
    }
}

pub fn do_alert_error(alert_title: &str, alert_message: Option<&str>) -> Html {
    html! {
    <div class="container">
        <div class="row justify-content-md-center">
            <div class="alert alert-danger" role="alert">
                <p><strong>{ alert_title }</strong></p>
                if let Some(value) = alert_message {
                    <p>{ value }</p>
                }
            </div>
        </div>
    </div>
    }
}

pub fn do_page_header(page_title: &str) -> Html {
    html! {
        <div class={crate::constants::CSS_PAGE_HEADER}>
            <h2>{ page_title }</h2>
        </div>
    }
}
