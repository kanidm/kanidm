// loads the module which loads the WASM. It's loaders all the way down.
import init, { run_app } from '/pkg/kanidmd_web_ui.js';
async function main() {
    await init('/pkg/kanidmd_web_ui_bg.wasm');
    run_app();
}
main()

export function modal_hide_by_id(m) {
    var elem = document.getElementById(m);
    var modal = bootstrap.Modal.getInstance(elem);
    modal.hide();
};

