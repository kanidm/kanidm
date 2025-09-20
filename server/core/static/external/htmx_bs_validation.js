htmx.defineExtension("bs-validation", {
    onEvent: function (name, evt) {
        let form = evt.detail.elt;
        // Htmx propagates attributes onto children like button, which would break those buttons, so we return if not a form.
        if (form.tagName !== "FORM") return;

        // check if trigger attribute and submit event exists
        // for the form
        if (!form.hasAttribute("hx-trigger")) {
            // set trigger for custom event bs-send
            form.setAttribute("hx-trigger", "bs-send");

            // and attach the event only once
            form.addEventListener("submit", function (event) {
                if (form.checkValidity()) {
                    // trigger custom event hx-trigger="bs-send"
                    htmx.trigger(form, "bsSend");
                }

                // focus the first :invalid field
                let invalidField = form.querySelector(":invalid");
                if (invalidField) {
                    invalidField.focus();
                }

                console.log("prevented htmx send, form was invalid")
                event.preventDefault()
                event.stopPropagation()

                form.classList.add("was-validated")
            }, false)
        }
    }
});