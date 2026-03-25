const esbuild = require("esbuild");

esbuild
  .build({
    entryPoints: ["src/index.ts"],
    outfile: "dist/osed.js",
    bundle: true,
    platform: "neutral",
    target: ["es2017"],
    format: "cjs",
    sourcemap: false,
    external: [],
    logLevel: "info",
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
