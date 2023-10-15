
function modal_hide_by_id(m) {
    var elem = document.getElementById(m);
    var modal = bootstrap.Modal.getInstance(elem);
    modal.hide();
};