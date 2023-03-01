///! Macros for the web UI

/// Adds a set of CSS classes to the body element when we're presenting a full-page form
#[macro_export]
macro_rules! add_body_form_classes {
    () => {
        for x in $crate::constants::CSS_CLASSES_BODY_FORM {
            if let Err(e) = $crate::utils::body().class_list().add_1(x) {
                console::error!(format!("class_list add error -> {:?}", e));
            };
        }
    };
}

/// Removes the set of CSS classes from the body element after we're presenting a full-page form
#[macro_export]
macro_rules! remove_body_form_classes {
    () => {
        for x in $crate::constants::CSS_CLASSES_BODY_FORM {
            if let Err(e) = $crate::utils::body().class_list().remove_1(x) {
                console::error!(format!("class_list removal error -> {:?}", e));
            };
        }
    };
}
