#!/usr/bin/env node
/** Bundles the CLI to a single file so `npx secretgate` has nothing to install. */
import { build } from "esbuild";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT = join(ROOT, "dist", "cli.js");

const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

await build({
  entryPoints: [join(ROOT, "src", "cli", "index.ts")],
  outfile: OUT,
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  minify: false, // a security tool people are meant to audit should stay readable
  sourcemap: false,
  // No shebang banner: esbuild preserves the one already on the entry point,
  // and adding a second puts a `#!` on line 2, which is a syntax error. The
  // build still "succeeds", so only running the artifact catches it.
  define: { __SECRETGATE_VERSION__: JSON.stringify(pkg.version) },
  // Keep node builtins external; bundle everything else so there are no deps.
  external: ["node:*"],
  logLevel: "info",
});

try {
  chmodSync(OUT, 0o755);
} catch {
  /* windows has no execute bit */
}

const source = readFileSync(OUT, "utf8");

// Smoke-test the artifact rather than trusting that a successful build means a
// working binary. A duplicated shebang got through here once, and the build
// reported success every time.
const shebangs = source.split("\n").filter((l) => l.startsWith("#!")).length;
if (shebangs !== 1) {
  console.error(`build produced ${shebangs} shebang line(s); expected exactly 1`);
  process.exit(1);
}
if (!source.startsWith("#!")) {
  console.error("build output does not start with a shebang");
  process.exit(1);
}

const { execFileSync } = await import("node:child_process");
const version = execFileSync(process.execPath, [OUT, "--version"], { encoding: "utf8" }).trim();
if (version !== pkg.version) {
  console.error(`built binary reports version ${version}, package.json says ${pkg.version}`);
  process.exit(1);
}

console.log(`built ${OUT} (${(source.length / 1024).toFixed(0)} KB), runs and reports v${version}`);
