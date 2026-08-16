import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { parseSimpleYaml } from "./yaml.js";
import type { Config } from "../core/types.js";

export const CONFIG_FILENAMES = ["secretgate.yml", "secretgate.yaml", ".secretgate.yml"];
export const BASELINE_FILENAME = ".secretgate-baseline.json";

export function defaultConfig(): Config {
  return {
    mode: "redact",
    entropy: { enabled: true, threshold: 4.0, action: "warn" },
    rules: { disable: [] },
    allowlist: { paths: [], patterns: [] },
    // On by default because redact mode does not function without it: hooks run
    // one process per event, so a purely in-memory vault has already exited by
    // the time an agent's edit comes back to be restored.
    vault: { persist: true },
  };
}

/** Walk up from `start` looking for a config file, stopping at the FS root. */
export function findUp(filenames: string[], start: string = process.cwd()): string | undefined {
  let dir = resolve(start);
  for (;;) {
    for (const name of filenames) {
      const candidate = join(dir, name);
      if (existsSync(candidate)) return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) return undefined;
    dir = parent;
  }
}

export interface BaselineFile {
  version: 1;
  salt: string;
  /** fingerprint -> a human-readable hint, never the secret itself. */
  accepted: Record<string, string>;
}

function loadBaseline(configDir: string, config: Config): void {
  const path = join(configDir, BASELINE_FILENAME);
  if (!existsSync(path)) return;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as BaselineFile;
    if (parsed?.version !== 1 || typeof parsed.salt !== "string") return;
    config.baselineSalt = parsed.salt;
    config.baseline = new Set(Object.keys(parsed.accepted ?? {}));
  } catch {
    // A corrupt baseline must not take the scanner down with it. Failing open
    // here means more findings, never fewer, so it is the safe direction.
  }
}

export function loadConfig(cwd: string = process.cwd()): Config {
  const config = defaultConfig();
  const configPath = findUp(CONFIG_FILENAMES, cwd);
  const rootDir = configPath ? dirname(configPath) : cwd;

  if (configPath) {
    try {
      const raw = parseSimpleYaml(readFileSync(configPath, "utf8")) as any;
      if (raw.mode === "redact" || raw.mode === "block" || raw.mode === "warn") config.mode = raw.mode;
      if (raw.entropy) {
        if (typeof raw.entropy.enabled === "boolean") config.entropy.enabled = raw.entropy.enabled;
        if (typeof raw.entropy.threshold === "number") config.entropy.threshold = raw.entropy.threshold;
        if (["block", "redact", "warn", "ignore"].includes(raw.entropy.action)) {
          config.entropy.action = raw.entropy.action;
        }
      }
      if (Array.isArray(raw.rules?.disable)) config.rules.disable = raw.rules.disable.map(String);
      if (Array.isArray(raw.allowlist?.paths)) config.allowlist.paths = raw.allowlist.paths.map(String);
      if (Array.isArray(raw.allowlist?.patterns)) config.allowlist.patterns = raw.allowlist.patterns.map(String);
      if (typeof raw.vault?.persist === "boolean") config.vault.persist = raw.vault.persist;
    } catch (err) {
      process.stderr.write(`secretgate: could not read ${configPath}, using defaults (${String(err)})\n`);
    }
  }

  loadBaseline(rootDir, config);
  return config;
}

export const SAMPLE_CONFIG = `# secretgate configuration
# https://github.com/jvlabsai/secretgate

# redact  - swap secrets for placeholders, put them back locally (default)
# block   - refuse the operation and tell the developer what was found
# warn    - report and continue
mode: redact

entropy:
  enabled: true
  threshold: 4.0
  # Entropy is a heuristic, not evidence. Blocking on it alone is how a
  # scanner gets uninstalled, so the default stops at a warning.
  action: warn

rules:
  disable: []

allowlist:
  paths:
    - "**/fixtures/**"
    - "**/testdata/**"
  patterns:
    - "EXAMPLE_.*"

vault:
  # Required for redact mode to work. Agent hooks run one process per event, so
  # the mapping has to outlive the process that made it or a secret can be
  # swapped out and never restored. Entries live in ~/.secretgate/vault.json
  # (0600), expire after 12 hours, and clear with \`secretgate vault --clear\`.
  # Set false only if you would rather no secret ever touched disk — in which
  # case use \`mode: block\`, since redaction will no longer round-trip.
  persist: true
`;
