import init, { run_login_app } from '../pkg/kanidmd_web_ui.js';
async function main() {
   await init('/pkg/kanidmd_web_ui_bg.wasm');
   run_login_app();
}
main()
