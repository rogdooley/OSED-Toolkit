const esbuild = require("esbuild");

esbuild
  .build({
    entryPoints: ["src/index.ts"],
    outfile: "dist/osed.js",
    bundle: true,
    platform: "neutral",
    target: ["es2017"],
    format: "iife",
    globalName: "osed_bundle",
    footer: {
      js: "if (typeof this !== 'undefined' && this.osed_bundle && this.osed_bundle.initializeScript) { this.initializeScript = this.osed_bundle.initializeScript; }",
    },
    sourcemap: false,
    external: [],
    logLevel: "info",
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
