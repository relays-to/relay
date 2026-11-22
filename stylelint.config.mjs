import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

// pre-commit exposes the hook's packages through NODE_PATH. Stylelint 17 and
// later resolve shareable configs and plugins without reading NODE_PATH, so
// resolve them here, where createRequire still honours it.
const require = createRequire(import.meta.url);

function resolve(name) {
  try {
    return require.resolve(name);
  } catch {
    // ESM-only packages such as stylelint-config-standard cannot be resolved
    // by require, so point Stylelint at their index.js instead.
    return (
      require.resolve
        .paths(name)
        ?.map((dir) => path.join(dir, name, "index.js"))
        .find((file) => fs.existsSync(file)) ?? name
    );
  }
}

export default {
  extends: [
    resolve("stylelint-config-standard"),
    resolve("stylelint-plugin-logical-css/configs/recommended"),
  ],
  rules: {
    "at-rule-no-unknown": [
      true,
      {
        ignoreAtRules: [
          "apply",
          "config",
          "custom-variant",
          "plugin",
          "reference",
          "screen",
          "source",
          "tailwind",
          "theme",
          "utility",
          "variant",
        ],
      },
    ],
    "at-rule-prelude-no-invalid": [
      true,
      {
        ignoreAtRules: ["apply"],
      },
    ],
    "import-notation": "string",
    "no-invalid-position-at-import-rule": [
      true,
      {
        ignoreAtRules: ["plugin", "source", "tailwind"],
      },
    ],
    "selector-id-pattern": "^(?:django_cmdbar|(?:[a-z][a-z0-9]*)(?:-[a-z0-9]+)*)$",
  },
};
