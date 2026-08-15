#!/usr/bin/env node
/**
 * Fails the build if anything under src/core or src/hooks can reach the network.
 *
 * This is not lint pedantry. "runs entirely on your machine" is the single
 * claim secretgate makes that the alternatives cannot, and a claim nobody
 * checks is a claim that quietly stops being true. Enforcing it mechanically
 * means the README stays honest without anyone having to remember.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

// src/cli is exempt: it is the process entry point and never runs inside an
// agent's hot path. It still must not make requests, but it is allowed to
// import node:child_process to shell out to git.
const GUARDED = ["src/core", "src/hooks"];

const BANNED_IMPORTS = [
  "node:http",
  "node:https",
  "node:net",
  "node:tls",
  "node:dgram",
  "node:dns",
  "http",
  "https",
  "net",
  "tls",
  "dgram",
  "dns",
  "axios",
  "node-fetch",
  "undici",
  "got",
  "superagent",
  "ws",
];

const BANNED_GLOBALS = [
  { pattern: /\bfetch\s*\(/, name: "fetch()" },
  { pattern: /\bXMLHttpRequest\b/, name: "XMLHttpRequest" },
  { pattern: /\bWebSocket\b/, name: "WebSocket" },
  { pattern: /\bnavigator\.sendBeacon\b/, name: "navigator.sendBeacon" },
];

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) yield* walk(full);
    else if (full.endsWith(".ts")) yield full;
  }
}

const violations = [];

for (const guarded of GUARDED) {
  for (const file of walk(join(ROOT, guarded))) {
    const source = readFileSync(file, "utf8");
    const rel = relative(ROOT, file).replace(/\\/g, "/");

    const importRe = /(?:^|\n)\s*import[^;]*?from\s*["']([^"']+)["']|require\(\s*["']([^"']+)["']\s*\)|import\(\s*["']([^"']+)["']\s*\)/g;
    let m;
    while ((m = importRe.exec(source)) !== null) {
      const mod = m[1] ?? m[2] ?? m[3];
      if (BANNED_IMPORTS.includes(mod)) violations.push(`${rel}: imports ${mod}`);
    }

    for (const { pattern, name } of BANNED_GLOBALS) {
      // Ignore matches inside comments, so prose about fetch() does not fail CI.
      const stripped = source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
      if (pattern.test(stripped)) violations.push(`${rel}: uses ${name}`);
    }
  }
}

if (violations.length > 0) {
  console.error("\nno-network check FAILED\n");
  for (const v of violations) console.error(`  ${v}`);
  console.error(
    "\nsecretgate promises it never phones home. If a network call is genuinely\n" +
      "needed, it does not belong in src/core or src/hooks, and the README claim\n" +
      "has to change with it.\n",
  );
  process.exit(1);
}

console.log(`no-network check passed (${GUARDED.join(", ")})`);
