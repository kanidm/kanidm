import init, { run_app } from '../pkg/kanidmd_web_ui.js';
async function main() {
   await init('/pkg/kanidmd_web_ui_bg.wasm');
   run_app();
}
main()
