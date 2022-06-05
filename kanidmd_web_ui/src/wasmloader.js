// loads the module which loads the WASM. It's loaders all the way down.
import init, { run_app } from '/pkg/kanidmd_web_ui.js';
async function main() {
    await init('/pkg/kanidmd_web_ui_bg.wasm');
    run_app();
}
main()