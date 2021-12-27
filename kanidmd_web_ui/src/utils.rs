use wasm_bindgen::JsCast;
use yew_services::ConsoleService;

pub fn autofocus() {
    // Once rendered if an element with id autofocus exists, focus it.
    let doc = yew::utils::document();
    if let Some(element) = doc.get_element_by_id("autofocus") {
        if let Ok(htmlelement) = element.dyn_into::<web_sys::HtmlElement>() {
            if htmlelement.focus().is_err() {
                ConsoleService::log("unable to autofocus.");
            }
        }
    }
}
