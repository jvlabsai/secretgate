/**
 * Converts an upstream gitleaks.toml into src/core/rules/generated.ts.
 *
 * Run by a maintainer, never at install time and never at runtime — the whole
 * point of generating a committed .ts file is that a user's machine never has
 * to fetch anything. Download gitleaks.toml yourself and point this at it:
 *
 *   npm run sync-rules -- ./gitleaks.toml
 *
 * Gitleaks is MIT-licensed; see NOTICE for attribution.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "core", "rules", "generated.ts");

interface ParsedRule {
  id: string;
  description: string;
  regex: string;
  keywords: string[];
  entropy?: number;
  secretGroup?: number;
}

/**
 * A deliberately small TOML reader: gitleaks.toml is a flat list of [[rules]]
 * tables with string, number and string-array values. Pulling in a TOML parser
 * for a file only a maintainer ever reads is not worth the dependency.
 */
function parseGitleaksToml(source: string): ParsedRule[] {
  const rules: ParsedRule[] = [];
  let current: Partial<ParsedRule> | null = null;

  const pushCurrent = () => {
    if (current?.id && current.regex) {
      rules.push({
        id: current.id,
        description: current.description ?? current.id,
        regex: current.regex,
        keywords: current.keywords ?? [],
        entropy: current.entropy,
        secretGroup: current.secretGroup,
      });
    }
    current = null;
  };

  for (const raw of source.split("\n")) {
    const line = raw.trim();
    if (line === "[[rules]]") {
      pushCurrent();
      current = {};
      continue;
    }
    if (line.startsWith("[") && line !== "[[rules]]") {
      // Some other table (allowlist, extend). Stop collecting until the next rule.
      pushCurrent();
      continue;
    }
    if (!current || !line || line.startsWith("#")) continue;

    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();

    switch (key) {
      case "id":
        current.id = stripQuotes(value);
        break;
      case "description":
        current.description = stripQuotes(value);
        break;
      case "regex":
        current.regex = stripQuotes(value);
        break;
      case "entropy":
        current.entropy = Number(value);
        break;
      case "secretGroup":
        current.secretGroup = Number(value);
        break;
      case "keywords":
        current.keywords = value
          .replace(/^\[|\]$/g, "")
          .split(",")
          .map((s) => stripQuotes(s.trim()))
          .filter(Boolean);
        break;
      default:
        break;
    }
  }
  pushCurrent();
  return rules;
}

function stripQuotes(v: string): string {
  const m = v.match(/^'''([\s\S]*)'''$/) ?? v.match(/^"""([\s\S]*)"""$/) ?? v.match(/^'([\s\S]*)'$/) ?? v.match(/^"([\s\S]*)"$/);
  return m?.[1] ?? v;
}

/**
 * Go's RE2 accepts a few things JavaScript does not. Rules we cannot translate
 * are dropped with a warning rather than silently mangled — a regex that
 * compiles but means something else is worse than a rule we do not ship.
 */
function toJsRegex(goRegex: string): string | null {
  let out = goRegex;
  // (?i) and friends are leading flags in RE2; JS wants them on the literal.
  out = out.replace(/^\(\?i\)/, "");
  if (/\(\?[a-zA-Z]+\)/.test(out)) return null; // any other inline flag group
  if (out.includes("(?P<")) out = out.replace(/\(\?P</g, "(?<");
  try {
    new RegExp(out, "g");
  } catch {
    return null;
  }
  return out;
}

function providerFor(id: string): string {
  return id.split("-")[0] ?? "generic";
}

const input = process.argv[2];
if (!input) {
  console.error("usage: npm run sync-rules -- <path-to-gitleaks.toml>");
  process.exit(2);
}

const parsed = parseGitleaksToml(readFileSync(input, "utf8"));
const converted: string[] = [];
const skipped: string[] = [];

for (const rule of parsed) {
  const js = toJsRegex(rule.regex);
  if (!js) {
    skipped.push(rule.id);
    continue;
  }
  const caseInsensitive = /^\(\?i\)/.test(rule.regex);
  converted.push(
    [
      "  {",
      `    id: ${JSON.stringify(`gl-${rule.id}`)},`,
      `    provider: ${JSON.stringify(providerFor(rule.id))},`,
      `    description: ${JSON.stringify(rule.description)},`,
      `    regex: new RegExp(${JSON.stringify(js)}, ${JSON.stringify(caseInsensitive ? "gi" : "g")}),`,
      rule.keywords.length ? `    prefilter: ${JSON.stringify(rule.keywords)},` : "",
      rule.secretGroup ? `    group: ${rule.secretGroup},` : "",
      rule.entropy ? `    entropyMin: ${rule.entropy},` : "",
      `    confidence: "medium",`,
      "  },",
    ]
      .filter(Boolean)
      .join("\n"),
  );
}

const header = `// GENERATED FILE — do not edit by hand.
// Produced by scripts/sync-rules.ts from an upstream gitleaks.toml.
// Gitleaks is MIT-licensed; see NOTICE for attribution.
//
// Regenerate with: npm run sync-rules -- <path-to-gitleaks.toml>

import type { Rule } from "../types.js";

export const generatedRules: Rule[] = [
`;

writeFileSync(OUT, `${header}${converted.join("\n")}\n];\n`);

console.log(`wrote ${converted.length} rules to ${OUT}`);
if (skipped.length) {
  console.log(`skipped ${skipped.length} rule(s) whose RE2 syntax has no JavaScript equivalent:`);
  for (const id of skipped.slice(0, 20)) console.log(`  - ${id}`);
  if (skipped.length > 20) console.log(`  ... and ${skipped.length - 20} more`);
}
