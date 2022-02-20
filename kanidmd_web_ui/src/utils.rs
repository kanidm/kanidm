use gloo::console;
use wasm_bindgen::{JsCast, UnwrapThrowExt};
pub use web_sys::InputEvent;
use web_sys::{Document, Event, HtmlElement, HtmlInputElement, Window};

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
