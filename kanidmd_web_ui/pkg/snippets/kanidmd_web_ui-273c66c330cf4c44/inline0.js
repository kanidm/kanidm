export function modal_hide(m) {
    var elem = document.getElementById(m);
    var modal = bootstrap.Modal.getInstance(elem);
    modal.hide();
}