// This file will contain js helpers to have some interactivity on forms that we can't achieve with pure html.
function rehook_string_list_removers() {
    const buttons = document.getElementsByClassName("kanidm-remove-list-entry");
    for (let i = 0; i < buttons.length; i++) {
        const button = buttons.item(i)
        if (button.getAttribute("kanidm_hooked") !== null) continue

        button.addEventListener("click", (e) => {
            // Expected html nesting: div.email-entry > div.input-group > button.kanidm-remove-list-entry
            let li = button.parentElement?.parentElement;
            if (li && li.classList.contains("email-entry")) {
                li.remove();
            }
        })
        button.setAttribute("kanidm_hooked", "")
    }
}

window.onload = function () {
    rehook_string_list_removers();
    document.body.addEventListener("addEmailSwapped", () => {
        rehook_string_list_removers();
    })
};

