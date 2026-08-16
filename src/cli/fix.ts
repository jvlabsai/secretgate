import { readFileSync, writeFileSync, existsSync, appendFileSync } from "node:fs";
import { basename, dirname, join, relative } from "node:path";
import { scan, blocking } from "../core/scan.js";
import type { Config, Finding } from "../core/types.js";

/**
 * Lifts a hardcoded credential out of source and into `.env`.
 *
 * Every other command here stops at "there is a secret on line 12", which
 * leaves the developer with the actual work still to do: pick a variable name,
 * move the value, add the lookup, remember `.env.example`, remember to check
 * `.env` is gitignored. That is the moment people give up and add a pragma
 * instead, and a suppressed finding is a secret that is still in the repo.
 *
 * Dry run by default. It rewrites source, so it asks before it acts.
 */

type Language = "js" | "python" | "ruby" | "go" | "php" | "shell" | "unknown";

function languageOf(path: string): Language {
  const p = path.toLowerCase();
  if (/\.(ts|tsx|js|jsx|mjs|cjs|mts|cts)$/.test(p)) return "js";
  if (/\.py$/.test(p)) return "python";
  if (/\.rb$/.test(p)) return "ruby";
  if (/\.go$/.test(p)) return "go";
  if (/\.php$/.test(p)) return "php";
  if (/\.(sh|bash|zsh)$/.test(p)) return "shell";
  return "unknown";
}

function envLookup(language: Language, name: string): string | null {
  switch (language) {
    case "js":
      return `process.env.${name}`;
    case "python":
      return `os.environ["${name}"]`;
    case "ruby":
      return `ENV["${name}"]`;
    case "go":
      return `os.Getenv("${name}")`;
    case "php":
      return `getenv("${name}")`;
    case "shell":
      return `"$${name}"`;
    default:
      return null;
  }
}

/**
 * Prefers the identifier the value was already assigned to, since that is what
 * the developer has been calling it. Falls back to the provider.
 */
/**
 * Names have to be assigned across the whole run, not per file.
 *
 * With a per-file counter, two files that both call their constant `apiKey`
 * each derive `API_KEY`. The first write wins in `.env`, the second is skipped
 * as a duplicate — and the second file, already rewritten to
 * `process.env.API_KEY`, now silently reads the *first* file's credential while
 * its own is lost entirely. Wrong value at runtime and data loss, with nothing
 * in the output to suggest it happened.
 *
 * So: one registry for the run. The same value always maps to the same name,
 * which is the correct dedupe. Different values never share a name, even when
 * the surrounding code calls them the same thing.
 */
export interface NameRegistry {
  byValue: Map<string, string>;
  taken: Set<string>;
}

/** Seeded from any existing .env so we neither collide with nor duplicate it. */
export function createRegistry(envPath: string): NameRegistry {
  const registry: NameRegistry = { byValue: new Map(), taken: new Set() };
  if (!existsSync(envPath)) return registry;

  for (const line of readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const match = line.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match) continue;
    const name = match[1]!;
    const value = (match[2] ?? "").replace(/^["']|["']$/g, "");
    registry.taken.add(name);
    if (value && !registry.byValue.has(value)) registry.byValue.set(value, name);
  }
  return registry;
}

export function deriveEnvName(source: string, finding: Finding, taken: Set<string>, spanStart?: number): string {
  // Names come from the assignment, so start looking from the whole literal
  // rather than from the secret. Otherwise `postgres://svc:pw@host` yields
  // "SVC", picked out of the URI's userinfo, instead of "DATABASE_URL".
  const anchor = spanStart ?? finding.start;
  const lineStart = source.lastIndexOf("\n", anchor) + 1;
  const before = source.slice(lineStart, anchor);

  const identifier =
    before.match(/([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*["'`]?\s*$/)?.[1] ??
    before.match(/["']([A-Za-z_][A-Za-z0-9_]*)["']\s*:\s*$/)?.[1];

  let base = identifier
    ? identifier
        .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
        .replace(/[^A-Za-z0-9]+/g, "_")
        .toUpperCase()
        .replace(/^_+|_+$/g, "")
    : `${finding.provider}_${finding.ruleId.includes("token") ? "TOKEN" : "SECRET"}`
        .replace(/[^A-Za-z0-9]+/g, "_")
        .toUpperCase();

  if (!base || /^\d/.test(base)) base = `SECRETGATE_${base}`;

  let name = base;
  let n = 2;
  while (taken.has(name)) name = `${base}_${n++}`;
  taken.add(name);
  return name;
}

export interface FixEdit {
  name: string;
  value: string;
  line: number;
  replacement: string;
}

export interface FixResult {
  path: string;
  language: Language;
  edits: FixEdit[];
  updated: string;
  /** Why nothing was done, when nothing was done. */
  skipped?: string;
  /** Findings deliberately left alone, with the reason. */
  manual: { line: number; reason: string }[];
}

/**
 * The bounds of the string literal containing `index`, if there is one.
 *
 * This is what stops the command generating broken code. A connection string
 * holds its password *inside* a larger literal, and swapping just the password
 * for `process.env.X` produces
 * `"postgres://svc:process.env.X@host/db"` — a lookup that never evaluates,
 * silently, in code that still compiles. The whole literal has to move.
 */
export function enclosingLiteral(source: string, index: number): { start: number; end: number; quote: string } | null {
  const lineStart = source.lastIndexOf("\n", index) + 1;
  let lineEnd = source.indexOf("\n", index);
  if (lineEnd === -1) lineEnd = source.length;
  const line = source.slice(lineStart, lineEnd);
  const offset = index - lineStart;

  for (const quote of ['"', "'", "`"]) {
    let cursor = 0;
    while (cursor < line.length) {
      const open = line.indexOf(quote, cursor);
      if (open === -1) break;
      let close = line.indexOf(quote, open + 1);
      // Step over an escaped quote.
      while (close !== -1 && line[close - 1] === "\\") close = line.indexOf(quote, close + 1);
      if (close === -1) break;

      if (offset > open && offset < close) {
        return { start: lineStart + open, end: lineStart + close + 1, quote };
      }
      cursor = close + 1;
    }
  }
  return null;
}

export function planFix(path: string, source: string, config: Config, registry?: NameRegistry): FixResult {
  const language = languageOf(path);
  const findings = blocking(scan(source, { ...config, path }).findings, config);

  if (findings.length === 0) return { path, language, edits: [], updated: source, manual: [] };
  if (language === "unknown") {
    return { path, language, edits: [], updated: source, skipped: "unsupported file type", manual: [] };
  }

  const names = registry ?? { byValue: new Map<string, string>(), taken: new Set<string>() };
  const edits: FixEdit[] = [];
  const manual: { line: number; reason: string }[] = [];
  let updated = source;

  // Right to left, so earlier offsets stay valid as the text changes length.
  for (const finding of [...findings].sort((a, b) => b.start - a.start)) {
    const line = source.slice(0, finding.start).split("\n").length;
    const literal = enclosingLiteral(source, finding.start);

    if (!literal) {
      // Not inside a string, so there is nothing safe to swap — a bare value in
      // a config block, say. Report it rather than guessing at the syntax.
      manual.push({ line, reason: "not inside a string literal" });
      continue;
    }

    const contents = source.slice(literal.start + 1, literal.end - 1);

    if (literal.quote === "`" && contents.includes("${")) {
      // Moving this would drop the interpolation and change behaviour.
      manual.push({ line, reason: "template literal with interpolation" });
      continue;
    }

    // The same secret in two places is one variable; two different secrets are
    // never allowed to become one, whatever the surrounding code calls them.
    const name = names.byValue.get(contents) ?? deriveEnvName(source, finding, names.taken, literal.start);
    names.byValue.set(contents, name);

    const lookup = envLookup(language, name);
    if (!lookup) continue;

    // The whole literal moves, not just the matched span. For a connection
    // string that means DATABASE_URL holds the entire URI, which is both what
    // the developer wants and the only version that actually works.
    updated = updated.slice(0, literal.start) + lookup + updated.slice(literal.end);
    edits.push({ name, value: contents, line, replacement: lookup });
  }

  edits.reverse();
  manual.reverse();
  return { path, language, edits, updated, manual };
}

export interface EnvWrite {
  envPath: string;
  examplePath: string;
  added: string[];
  gitignoreWarning: string | undefined;
}

/**
 * Where `.env` belongs: the project root, not beside whichever file happened to
 * contain the secret. Dropping a `src/.env` is both useless to the runtime and
 * a new place for credentials to hide.
 */
export function findProjectRoot(start: string): string {
  const markers = ["package.json", ".git", "go.mod", "pyproject.toml", "Cargo.toml", "composer.json", "Gemfile"];
  let dir = start;
  for (let i = 0; i < 12; i++) {
    if (markers.some((m) => existsSync(join(dir, m)))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return start;
}

export function applyEnvFiles(path: string, edits: FixEdit[], write: boolean): EnvWrite {
  const dir = findProjectRoot(dirname(path));
  const envPath = join(dir, ".env");
  const examplePath = join(dir, ".env.example");

  const existing = existsSync(envPath) ? readFileSync(envPath, "utf8") : "";
  const added: string[] = [];
  let envAppend = "";
  let exampleAppend = "";

  for (const edit of edits) {
    if (new RegExp(`^${edit.name}=`, "m").test(existing)) continue;
    envAppend += `${edit.name}=${edit.value}\n`;
    exampleAppend += `${edit.name}=\n`;
    added.push(edit.name);
  }

  if (write && envAppend) {
    const prefix = existing && !existing.endsWith("\n") ? "\n" : "";
    appendFileSync(envPath, `${prefix}${envAppend}`);

    const example = existsSync(examplePath) ? readFileSync(examplePath, "utf8") : "";
    const examplePrefix = example && !example.endsWith("\n") ? "\n" : "";
    appendFileSync(examplePath, `${examplePrefix}${exampleAppend}`);
  }

  // Moving a secret from source into an untracked-but-uncommitted .env is not
  // an improvement, so say so rather than leaving them to find out.
  let gitignoreWarning: string | undefined;
  const gitignorePath = findGitignore(dir);
  if (!gitignorePath) {
    gitignoreWarning = "no .gitignore found — make sure .env is not committed";
  } else {
    const rules = readFileSync(gitignorePath, "utf8");
    if (!/^\s*\.env\s*$/m.test(rules) && !/^\s*\*?\.env\*?\s*$/m.test(rules)) {
      gitignoreWarning = `${relative(process.cwd(), gitignorePath) || basename(gitignorePath)} does not ignore .env — add it before committing`;
    }
  }

  return { envPath, examplePath, added, gitignoreWarning };
}

function findGitignore(start: string): string | undefined {
  let dir = start;
  for (let i = 0; i < 12; i++) {
    const candidate = join(dir, ".gitignore");
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return undefined;
}

export function writeSource(path: string, contents: string): void {
  writeFileSync(path, contents);
}
