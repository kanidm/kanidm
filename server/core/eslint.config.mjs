import globals from "globals";
import pluginJs from "@eslint/js";


/** @type {import('eslint').Linter.Config[]} */
export default [
  {
    languageOptions: {
      globals: {
        ...globals.browser,
        Base64 : "writeable" // to feed the Base64 class into the global scope
      }
    }
  },
  pluginJs.configs.recommended,
];