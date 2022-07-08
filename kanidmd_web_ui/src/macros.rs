///! Macros for the web UI

/// Adds a default set of CSS classes to the body element
#[macro_export]
macro_rules! add_ui_form_classes  {
    () => {
        for x in $crate::constants::CSS_CLASSES_UI_FORM {
            if let Err(e) = crate::utils::body().class_list().add_1(x) {
                console::log!(format!("class_list add error -> {:?}", e));
            };
        }
    };
}

/// Removes the default set of CSS classes from the body element
#[macro_export]
macro_rules! remove_ui_form_classes  {
    () => {
        for x in $crate::constants::CSS_CLASSES_UI_FORM {
            if let Err(e) = crate::utils::body().class_list().remove_1(x) {
                console::log!(format!("class_list removal error -> {:?}", e));
            };
        }
    };
}
