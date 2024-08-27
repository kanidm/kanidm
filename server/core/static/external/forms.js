// This file will contain js helpers to have some interactivity on forms that we can't achieve with pure html.
function remove_list_item(event){

}

function rehook_string_list_removers() {
    let buttons = document.getElementsByClassName("kanidm-remove-list-entry");
    for (let i = 0; i < buttons.length; i++) {
        let button = buttons.item(i)
        button.addEventListener("click", ()=> {
            // Expected html nesting: li > div.input-group > button.kanidm-remove-list-entry
            let li = button.parentElement?.parentElement;
            if (li && li.tag === "li") {
                li.remove();
            }
        })
    }
}

document.onload = () => {
  document.addEventListener("rehookThin", () => {
      rehook_string_list_removers();
  })
};

