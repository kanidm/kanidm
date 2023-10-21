// This is easier to have in JS than in WASM
export function modal_hide_by_id(m) {
    var elem = document.getElementById(m);
    var modal = bootstrap.Modal.getInstance(elem);
    modal.hide();
};