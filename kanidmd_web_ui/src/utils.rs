use gloo::console;
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, UnwrapThrowExt};
pub use web_sys::InputEvent;
use web_sys::{Document, Event, /*HtmlButtonElement,*/ HtmlElement, HtmlInputElement, Window};

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

pub fn autofocus() {
    // Once rendered if an element with id autofocus exists, focus it.
    let doc = document();
    if let Some(element) = doc.get_element_by_id("autofocus") {
        if let Ok(htmlelement) = element.dyn_into::<web_sys::HtmlElement>() {
            if htmlelement.focus().is_err() {
                console::log!("unable to autofocus.");
            }
        }
    }
}

pub fn get_value_from_input_event(e: InputEvent) -> String {
    let event: Event = e.dyn_into().unwrap_throw();
    let event_target = event.target().unwrap_throw();
    let target: HtmlInputElement = event_target.dyn_into().unwrap_throw();
    target.value()
}

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

// pub fn get_inputelement_by_id(id: &str) -> Option<HtmlInputElement> {
//     document()
//         .get_element_by_id(id)
//         .and_then(|element| element.dyn_into::<web_sys::HtmlInputElement>().ok())
// }

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
