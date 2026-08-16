#!/usr/bin/env node
import { parseArgs } from "node:util";
import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join, relative, resolve, dirname, basename } from "node:path";
import { randomBytes } from "node:crypto";
import { loadConfig, defaultConfig, SAMPLE_CONFIG, CONFIG_FILENAMES, BASELINE_FILENAME, findUp } from "../config/index.js";
import { scan, blocking } from "../core/scan.js";
import { fingerprint } from "../core/suppress.js";
import { allRules } from "../core/rules/index.js";
import { runClaudeCodeHook } from "../hooks/claude-code.js";
import { runCursorHook } from "../hooks/cursor.js";
import { runFilter } from "../hooks/generic.js";
import { runPreCommit } from "../hooks/git.js";
import { runMcpProxy } from "../hooks/mcp-proxy.js";
import { planFix, applyEnvFiles, writeSource, createRegistry, findProjectRoot } from "./fix.js";
import { detectAgents, installClaudeCode, installCursor, installGitHook, uninstallAll, installedRecords, STATE_DIR } from "./install.js";
import { clearStore, storeStatus, VAULT_PATH } from "../core/vault-store.js";
import { readHeartbeat, agentHealth, humanAge, clearHeartbeat } from "../core/heartbeat.js";
import { isSecretStore, assessStore, type StoreVerdict } from "./secret-store.js";
import { lockEnvFile, unlockEnvFile, BACKUP_DIR } from "./lock.js";

// No colour library. Five SGR codes are the whole requirement, and they go
// quiet when stdout is not a terminal or NO_COLOR is set.
const tty = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR;
const ESC = String.fromCharCode(27);
const paint =
  (code: number) =>
  (s: string): string =>
    tty ? `${ESC}[${code}m${s}${ESC}[0m` : s;
const c = {
  bold: paint(1),
  dim: paint(2),
  red: paint(31),
  green: paint(32),
  yellow: paint(33),
};

// Substituted by esbuild at build time; falls back when running from source.
declare const __SECRETGATE_VERSION__: string | undefined;
const VERSION = typeof __SECRETGATE_VERSION__ === "string" ? __SECRETGATE_VERSION__ : "0.1.0-dev";
const USAGE = `${c.bold("secretgate")} — keep credentials out of your AI coding agent

  secretgate init              detect installed agents and wire every hook
  secretgate scan [path]       scan a file or directory
  secretgate fix [path]        move hardcoded secrets into .env (--write to apply)
  secretgate lock [path]       blank out .env values so ANY agent reads placeholders
  secretgate unlock [path]     put the real values back
  secretgate filter            stdin -> stdout, redacted (--rehydrate to reverse)
  secretgate baseline          accept every current finding
  secretgate doctor            check what is wired up and whether it is firing
  secretgate uninstall         restore every config file we touched
  secretgate rules             list detection rules
  secretgate vault             show the local placeholder store (--clear to wipe)

  secretgate mcp-proxy -- <cmd>  guard an MCP server's stdio in both directions
  secretgate hook claude-code    hook entry point (not for humans)
  secretgate hook cursor         hook entry point (not for humans)
  secretgate hook pre-commit     git hook entry point

Options
  --mode <redact|block|warn>   override the configured mode
  --json                       machine-readable output
  --quiet                      suppress informational output
  --help, --version

Everything runs locally. No account, no network, no telemetry.
`;

function out(s = ""): void {
  process.stdout.write(`${s}\n`);
}

// --- scan -----------------------------------------------------------------

// `.secretgate` is in here for a reason worth remembering: without it, `lock`
// walked into its own backup directory, treated the backup as another .env, and
// locked it too. The one copy of the real values was then placeholders, so
// `unlock` had nothing to fall back on and the secret was gone.
const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".secretgate",
  "dist",
  "build",
  "out",
  ".next",
  "vendor",
  "target",
  ".venv",
  "__pycache__",
]);
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const NUL = String.fromCharCode(0);

function* walk(root: string): Generator<string> {
  const stack = [root];
  while (stack.length) {
    const current = stack.pop()!;
    let entries;
    try {
      entries = readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(full);
      } else if (entry.isFile()) {
        yield full;
      }
    }
  }
}

function cmdScan(target: string, opts: { json?: boolean; mode?: string }): number {
  const root = resolve(target);
  if (!existsSync(root)) {
    process.stderr.write(`secretgate: no such path: ${target}\n`);
    return 2;
  }

  const config = loadConfig(statSync(root).isDirectory() ? root : process.cwd());
  if (opts.mode === "redact" || opts.mode === "block" || opts.mode === "warn") config.mode = opts.mode;

  const files = statSync(root).isDirectory() ? [...walk(root)] : [root];
  const rows: { file: string; line: number; ruleId: string; provider: string; confidence: string }[] = [];
  const stores: StoreVerdict[] = [];
  let scanned = 0;

  for (const file of files) {
    let content: string;
    try {
      if (statSync(file).size > MAX_FILE_BYTES) continue;
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (content.indexOf(NUL) !== -1) continue;
    scanned++;

    const { findings } = scan(content, { ...config, path: file });
    const hits = blocking(findings, config);

    // A .env holding credentials is the file doing its job. The only question
    // worth asking about it is whether git is about to publish it.
    if (isSecretStore(file)) {
      if (hits.length > 0) stores.push(assessStore(file, hits.length));
      continue;
    }

    for (const f of hits) {
      rows.push({
        file: relative(process.cwd(), file) || file,
        line: content.slice(0, f.start).split("\n").length,
        ruleId: f.ruleId,
        provider: f.provider,
        confidence: f.confidence,
      });
    }
  }

  const exposed = stores.filter((s) => s.exposed);

  if (opts.json) {
    out(JSON.stringify({ scanned, findings: rows, secretStores: stores }, null, 2));
    return rows.length > 0 || exposed.length > 0 ? 1 : 0;
  }

  if (rows.length === 0 && stores.length === 0) {
    out(`${c.green("clean")}  ${scanned} file(s) scanned, nothing found`);
    return 0;
  }

  out("");
  for (const r of rows) {
    out(`  ${c.red("!")} ${c.bold(`${r.file}:${r.line}`)}  ${r.ruleId} ${c.dim(`(${r.provider})`)}`);
  }

  if (rows.length > 0) {
    out("");
    out(`${c.red(`${rows.length} credential(s)`)} hardcoded in ${scanned} scanned file(s)`);
    out(c.dim(`  secretgate fix .            move them into .env`));
    out(c.dim(`  # secretgate:allow          if a line is a false positive`));
    out(c.dim(`  secretgate baseline         accept everything currently flagged`));
  }

  if (stores.length > 0) {
    out("");
    out(c.bold("  secrets files"));
    for (const s of stores) {
      const name = relative(process.cwd(), s.path) || s.path;
      if (s.status === "ignored") {
        out(`    ${c.green("ok")}      ${name.padEnd(24)} ${c.dim(`${s.credentials} credential(s), ignored by git`)}`);
      } else if (s.status === "no-repo") {
        out(`    ${c.dim("—")}       ${name.padEnd(24)} ${c.dim(`${s.credentials} credential(s), not a git repo`)}`);
      } else {
        out(`    ${c.red("EXPOSED")} ${c.bold(name.padEnd(24))} ${c.red(`${s.credentials} credential(s) and NOT ignored by git`)}`);
      }
    }
    if (exposed.length > 0) {
      out("");
      out(c.red(`  ${exposed.length} secrets file(s) would be committed.`));
      for (const s of exposed) {
        out(c.dim(`    echo '${basename(s.path)}' >> .gitignore`));
      }
      out(c.dim(`    If it is already committed, the credentials must be rotated — removing`));
      out(c.dim(`    the file does not remove it from git history.`));
    } else {
      out(c.dim("    Credentials belong here. Nothing to do."));
    }
  }

  out("");
  return rows.length > 0 || exposed.length > 0 ? 1 : 0;
}

// --- fix -------------------------------------------------------------------

function cmdFix(target: string, write: boolean): number {
  const root = resolve(target);
  if (!existsSync(root)) {
    process.stderr.write(`secretgate: no such path: ${target}\n`);
    return 2;
  }

  const config = loadConfig(statSync(root).isDirectory() ? root : process.cwd());
  const files = statSync(root).isDirectory() ? [...walk(root)] : [root];

  // One registry for the whole run, seeded from any existing .env. Naming per
  // file would let two files that both say `apiKey` collapse onto one variable,
  // and the second file would end up reading the first one's credential.
  const projectRoot = findProjectRoot(statSync(root).isDirectory() ? root : dirname(root));
  const registry = createRegistry(join(projectRoot, ".env"));

  let touched = 0;
  let total = 0;
  const warnings = new Set<string>();

  for (const file of files) {
    let source: string;
    try {
      if (statSync(file).size > MAX_FILE_BYTES) continue;
      source = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (source.indexOf(NUL) !== -1) continue;

    const plan = planFix(file, source, config, registry);
    if (plan.edits.length === 0 && plan.manual.length === 0) continue;

    const shown = relative(process.cwd(), file) || file;
    out("");
    out(`  ${c.bold(shown)} ${c.dim(`(${plan.language})`)}`);

    for (const edit of plan.edits) {
      out(`    ${c.dim(`line ${edit.line}`)}  ${c.red("- ")}hardcoded value`);
      out(`               ${c.green("+ ")}${edit.replacement}   ${c.dim(`# ${edit.name} added to .env`)}`);
    }
    for (const m of plan.manual) {
      out(`    ${c.dim(`line ${m.line}`)}  ${c.yellow("! ")}left alone — ${m.reason}`);
    }

    if (plan.edits.length === 0) continue;
    touched++;
    total += plan.edits.length;

    const env = applyEnvFiles(file, plan.edits, write);
    if (env.gitignoreWarning) warnings.add(env.gitignoreWarning);
    if (write) writeSource(file, plan.updated);
  }

  out("");
  if (touched === 0) {
    out(`${c.green("nothing to fix")}  no hardcoded credentials in a supported file type`);
    return 0;
  }

  if (write) {
    out(`${c.green(`moved ${total} secret(s)`)} out of ${touched} file(s) and into .env`);
    out(c.dim("  .env.example was updated with the key names and empty values"));
    out(c.dim("  scan will still report these — they are in .env now, which is the point"));
  } else {
    out(`${c.yellow(`${total} secret(s)`)} in ${touched} file(s) can be moved into .env`);
    out(c.dim("  this was a dry run — nothing changed. Re-run with --write to apply."));
  }

  for (const w of warnings) out(`  ${c.yellow("warning")}  ${w}`);
  out("");
  return 0;
}

// --- lock / unlock ---------------------------------------------------------

function envFilesIn(dir: string): string[] {
  const found: string[] = [];
  for (const file of walk(dir)) {
    if (isSecretStore(file)) found.push(file);
  }
  return found;
}

function cmdLock(target: string): number {
  const root = resolve(target);
  const config = loadConfig(statSync(root).isDirectory() ? root : process.cwd());
  const files = statSync(root).isDirectory() ? envFilesIn(root) : [root];

  if (files.length === 0) {
    out(`${c.yellow("no .env files found")} under ${relative(process.cwd(), root) || root}`);
    return 0;
  }

  out("");
  let locked = 0;
  for (const file of files) {
    const result = lockEnvFile(file, config);
    const name = relative(process.cwd(), file) || file;

    if (result.alreadyLocked) {
      out(`  ${c.dim("=")} ${name.padEnd(24)} ${c.dim("already locked")}`);
    } else if (result.skipped) {
      out(`  ${c.dim("-")} ${name.padEnd(24)} ${c.dim(result.skipped)}`);
    } else {
      locked += result.locked;
      out(`  ${c.green("+")} ${name.padEnd(24)} ${c.green(`${result.locked} value(s) replaced with placeholders`)}`);
    }
  }

  out("");
  if (locked > 0) {
    out(`${c.green("locked")}  the agent now reads placeholders, not credentials`);
    out(c.dim(`  real values are in ${VAULT_PATH}, outside this project`));
    out(c.dim(`  backups are in ${BACKUP_DIR}`));
    out("");
    out(c.yellow("  Your app will not run until you unlock — the environment holds"));
    out(c.yellow("  placeholders now. Run: secretgate unlock"));
  } else {
    out(c.dim("  nothing to do"));
  }
  out("");
  return 0;
}

function cmdUnlock(target: string): number {
  const root = resolve(target);
  const files = statSync(root).isDirectory() ? envFilesIn(root) : [root];

  out("");
  let restored = 0;
  let problems = 0;

  for (const file of files) {
    const result = unlockEnvFile(file);
    const name = relative(process.cwd(), file) || file;

    if (result.skipped) {
      out(`  ${c.dim("-")} ${name.padEnd(24)} ${c.dim(result.skipped)}`);
      continue;
    }
    if (result.usedBackup) {
      restored++;
      out(`  ${c.green("+")} ${name.padEnd(24)} ${c.yellow("restored from backup")}`);
      continue;
    }
    if (result.warnings.length > 0) {
      problems++;
      out(`  ${c.red("!")} ${name.padEnd(24)} ${c.red("could not fully restore")}`);
      for (const w of result.warnings) out(`      ${c.dim(w)}`);
      continue;
    }
    restored++;
    out(`  ${c.green("+")} ${name.padEnd(24)} ${c.green(`${result.restored} value(s) restored`)}`);
  }

  out("");
  out(restored > 0 ? c.green(`unlocked  ${restored} file(s)`) : c.dim("  nothing was locked"));
  out("");
  return problems > 0 ? 1 : 0;
}

// --- baseline -------------------------------------------------------------

function cmdBaseline(target: string): number {
  const root = resolve(target);
  const config = loadConfig(root);
  const salt = randomBytes(16).toString("hex");
  const accepted: Record<string, string> = {};

  for (const file of statSync(root).isDirectory() ? walk(root) : [root]) {
    let content: string;
    try {
      if (statSync(file).size > MAX_FILE_BYTES) continue;
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    if (content.indexOf(NUL) !== -1) continue;

    // Deliberately baselining against a config with no existing baseline, so
    // re-running rebuilds the whole file rather than layering onto itself.
    const { findings } = scan(content, { ...config, path: file, baseline: undefined, baselineSalt: undefined });
    for (const f of blocking(findings, config)) {
      const line = content.slice(0, f.start).split("\n").length;
      // The hint never contains the secret — just where to look for it.
      // Forward slashes always: this file is committed and read back on Linux,
      // macOS and Windows, and a backslash path would churn the diff.
      const where = relative(root, file).replace(/\\/g, "/");
      accepted[fingerprint(f.match, salt)] = `${where}:${line} ${f.ruleId}`;
    }
  }

  const file = join(root, BASELINE_FILENAME);
  writeFileSync(file, `${JSON.stringify({ version: 1, salt, accepted }, null, 2)}\n`);

  // Count entries, not findings: one secret used in three places is one
  // fingerprint, and reporting a number the file does not back up is the kind
  // of small dishonesty that makes people distrust the big numbers too.
  const count = Object.keys(accepted).length;

  out(`${c.green("baseline written")}  ${file}`);
  out(`  ${count} distinct secret(s) accepted. Commit this file.`);
  out(c.dim("  Values are salted hashes; the secrets themselves are not stored."));
  return 0;
}

// --- init / doctor / uninstall -------------------------------------------

function cmdInit(): number {
  out("");
  out(c.bold("secretgate init"));
  out("");

  const agents = detectAgents();
  let wired = 0;

  for (const agent of agents) {
    if (!agent.present) {
      out(`  ${c.dim("-")} ${agent.name.padEnd(14)} ${c.dim("not installed")}`);
      continue;
    }
    if (!agent.supported) {
      out(`  ${c.yellow("~")} ${agent.name.padEnd(14)} ${c.yellow("detected, no adapter yet")}`);
      if (agent.note) out(`      ${c.dim(agent.note)}`);
      continue;
    }

    const result = agent.id === "cursor" ? installCursor() : installClaudeCode();
    if (result.changed) wired++;
    const mark = result.changed ? c.green("+") : c.dim("=");
    out(`  ${mark} ${agent.name.padEnd(14)} ${result.changed ? c.green(result.note) : c.dim(result.note)}`);
  }

  const repoRoot = findGitRoot(process.cwd());
  if (repoRoot) {
    const git = installGitHook(repoRoot);
    if (git.changed) wired++;
    const mark = git.changed ? c.green("+") : c.dim("=");
    out(`  ${mark} ${"git pre-commit".padEnd(14)} ${git.changed ? c.green(git.note) : c.dim(git.note)}`);
  }

  const configPath = findUp(CONFIG_FILENAMES);
  if (!configPath) {
    const dest = join(repoRoot ?? process.cwd(), "secretgate.yml");
    writeFileSync(dest, SAMPLE_CONFIG);
    out(`  ${c.green("+")} ${"secretgate.yml".padEnd(14)} ${c.green("created")}`);
  } else {
    out(`  ${c.dim("=")} ${"secretgate.yml".padEnd(14)} ${c.dim(`already at ${configPath}`)}`);
  }

  out("");
  out(wired > 0 ? c.green(`  done — ${wired} hook(s) wired`) : c.dim("  everything was already wired"));
  out(c.dim(`  undo at any time with "secretgate uninstall"`));

  // The failure mode this exists to prevent: someone installs secretgate,
  // sees it succeed, and assumes they are covered — while the agent they
  // actually use has no adapter and reads .env freely. Silence here reads as
  // protection, so say it out loud.
  const unsupported = agents.filter((a) => a.present && !a.supported);
  out("");
  out(c.bold("  Important: hooks only work for Claude Code and Cursor."));
  if (unsupported.length > 0) {
    out(c.yellow(`  You also have ${unsupported.map((a) => a.name).join(", ")} installed, which secretgate cannot hook.`));
  }
  out(c.dim("  For any other agent — Gemini, Copilot, Codex, Windsurf, Aider — there is"));
  out(c.dim("  no hook to intercept the read, so .env is NOT protected. Use instead:"));
  out("");
  out(`    ${c.bold("secretgate lock")}     blank out .env values before letting the agent work`);
  out(`    ${c.bold("secretgate unlock")}   put them back when you are done`);
  out("");
  out(c.dim(`  Check whether hooks are really firing with: secretgate doctor`));
  out("");
  return 0;
}

function findGitRoot(start: string): string | undefined {
  let dir = resolve(start);
  for (;;) {
    if (existsSync(join(dir, ".git"))) return dir;
    const parent = resolve(dir, "..");
    if (parent === dir) return undefined;
    dir = parent;
  }
}

function cmdDoctor(): number {
  const config = loadConfig();
  const configPath = findUp(CONFIG_FILENAMES);
  const records = installedRecords();

  out("");
  out(c.bold("secretgate doctor"));
  out("");
  out(`  ${"rules".padEnd(18)} ${allRules.length} loaded`);
  out(`  ${"mode".padEnd(18)} ${config.mode}`);
  out(`  ${"entropy".padEnd(18)} ${config.entropy.enabled ? `on, threshold ${config.entropy.threshold}, action ${config.entropy.action}` : "off"}`);
  out(`  ${"config".padEnd(18)} ${configPath ?? c.dim("defaults (no secretgate.yml found)")}`);
  out(`  ${"baseline".padEnd(18)} ${config.baseline ? `${config.baseline.size} accepted` : c.dim("none")}`);
  out(`  ${"vault persist".padEnd(18)} ${config.vault.persist ? c.yellow("on") : "off (in-memory only)"}`);
  out(`  ${"state dir".padEnd(18)} ${STATE_DIR}`);
  out("");

  const beats = agentHealth(readHeartbeat());

  out(c.bold("  agents"));
  for (const agent of detectAgents()) {
    const record = records.find((r) => r.agent === agent.id);
    const beat = beats.find((b) => b.agent === agent.id);

    let status: string;
    // A heartbeat outranks directory detection: if the hook has fired, the
    // agent plainly exists, whatever the filesystem looks like from here.
    if (beat?.lastSeen) status = c.green(`firing, last seen ${humanAge(beat.lastSeen)}`);
    else if (!agent.present) status = c.dim("not installed");
    else if (record)
      // The distinction this whole heartbeat exists for. Configured is not the
      // same as working, and only one of them protects you.
      status = c.yellow("wired, but has never fired — start a session and check again");
    else if (agent.supported) status = c.yellow('detected, not wired — run "secretgate init"');
    else status = c.yellow("detected, no adapter yet");

    out(`    ${agent.name.padEnd(14)} ${status}`);
    if (beat) {
      for (const e of beat.events.slice(0, 4)) {
        out(`      ${c.dim(`${e.event.padEnd(18)} ${humanAge(e.at).padEnd(9)} ${e.count}x`)}`);
      }
    }
  }

  const gitRoot = findGitRoot(process.cwd());
  const gitHook = gitRoot ? join(gitRoot, ".git", "hooks", "pre-commit") : undefined;
  const gitWired = gitHook && existsSync(gitHook) && readFileSync(gitHook, "utf8").includes("secretgate");
  out(`    ${"git pre-commit".padEnd(14)} ${gitWired ? c.green("wired") : c.yellow(gitRoot ? "not wired" : "not a git repo")}`);
  out("");

  // The headline verdict, before any detail. "Installed" and "protecting you"
  // are different states, and only one of them matters.
  const anyFiring = beats.some((b) => b.lastSeen !== undefined);
  out("");
  if (anyFiring) {
    out(`  ${c.green("PROTECTED")}  a hook has fired, so secretgate is in the path`);
  } else {
    out(`  ${c.red("NOT PROTECTED")}  no hook has ever fired on this machine`);
    out(c.dim("    Either you have not used a supported agent yet, or the agent you use"));
    out(c.dim("    has no adapter. Only Claude Code and Cursor can be hooked today."));
    out(c.dim("    For anything else, use: secretgate lock  /  secretgate unlock"));
  }

  // Prove the engine actually works right now rather than merely being present.
  // Built from fragments so this file contains no contiguous key-shaped string:
  // every scanner our users run would otherwise flag secretgate's own source.
  const canary = `aws_access_key_id = "${["AKIA", "4KTNQ7VZL2WXMP3D"].join("")}"`;
  const works = blocking(scan(canary, defaultConfig()).findings, defaultConfig()).length === 1;
  out(`  ${"self-test".padEnd(18)} ${works ? c.green("engine detects a known-shape key") : c.red("FAILED — the engine is not detecting a test key")}`);
  out("");
  return works ? 0 : 1;
}

function cmdUninstall(): number {
  const { restored, removed, problems } = uninstallAll();
  // Removing the tool must not leave its cache of real credentials behind.
  const vaultCleared = clearStore();
  clearHeartbeat();
  out("");
  if (vaultCleared) out(`  ${c.green("cleared")}  ${VAULT_PATH}`);
  for (const f of restored) out(`  ${c.green("restored")} ${f}`);
  for (const f of removed) out(`  ${c.green("removed")}  ${f}`);
  for (const p of problems) out(`  ${c.yellow("note")}     ${p}`);
  if (restored.length + removed.length + problems.length === 0) out(c.dim("  nothing to undo"));
  out("");
  out(c.dim("  secretgate.yml and .secretgate-baseline.json were left alone; delete them if you want."));
  out("");
  return 0;
}

function cmdVault(clear: boolean): number {
  if (clear) {
    const removed = clearStore();
    out(removed ? `${c.green("cleared")} ${VAULT_PATH}` : c.dim("nothing to clear"));
    return 0;
  }

  const status = storeStatus();
  out("");
  out(`  ${"path".padEnd(12)} ${status.path}`);
  out(`  ${"exists".padEnd(12)} ${status.exists ? "yes" : "no"}`);
  out(`  ${"entries".padEnd(12)} ${status.entries}`);
  out("");
  out(c.dim("  Holds the placeholder -> value mapping so redacted text can be"));
  out(c.dim("  restored after the agent hands it back. Entries expire after 12h."));
  out(c.dim("  File mode 0600. Wipe it now with: secretgate vault --clear"));
  out("");
  return 0;
}

function cmdRules(json: boolean): number {
  if (json) {
    out(JSON.stringify(allRules.map((r) => ({ id: r.id, provider: r.provider, description: r.description, confidence: r.confidence ?? "medium" })), null, 2));
    return 0;
  }
  const byProvider = new Map<string, typeof allRules>();
  for (const r of allRules) {
    const list = byProvider.get(r.provider) ?? [];
    list.push(r);
    byProvider.set(r.provider, list);
  }
  out("");
  for (const [provider, list] of [...byProvider.entries()].sort()) {
    out(`  ${c.bold(provider)}`);
    for (const r of list) out(`    ${r.id.padEnd(34)} ${c.dim(r.description)}`);
  }
  out("");
  out(c.dim(`  ${allRules.length} rules. Disable any of them by id or provider in secretgate.yml.`));
  out("");
  return 0;
}

// --- entry ----------------------------------------------------------------

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    strict: false,
    options: {
      help: { type: "boolean", short: "h" },
      version: { type: "boolean", short: "v" },
      json: { type: "boolean" },
      quiet: { type: "boolean", short: "q" },
      mode: { type: "string" },
      rehydrate: { type: "boolean" },
      clear: { type: "boolean" },
      write: { type: "boolean" },
    },
  });

  const [command = "", arg] = positionals as string[];

  // Version first: `secretgate --version` has no positional, so an
  // empty-command check ahead of this one swallows it and prints usage.
  if (values.version) {
    out(VERSION);
    return 0;
  }
  if (values.help || command === "help" || command === "") {
    out(USAGE);
    return 0;
  }

  switch (command) {
    case "init":
      return cmdInit();
    case "scan":
      return cmdScan(arg ?? ".", { json: !!values.json, mode: values.mode as string | undefined });
    case "fix":
      return cmdFix(arg ?? ".", !!values.write);
    case "lock":
      return cmdLock(arg ?? ".");
    case "unlock":
      return cmdUnlock(arg ?? ".");
    case "mcp-proxy": {
      // Everything after `--` is the server command, untouched.
      const sep = process.argv.indexOf("--");
      const upstream = sep === -1 ? (positionals as string[]).slice(1) : process.argv.slice(sep + 1);
      return runMcpProxy(upstream);
    }
    case "filter":
      return runFilter({ rehydrate: !!values.rehydrate, quiet: !!values.quiet });
    case "baseline":
      return cmdBaseline(arg ?? ".");
    case "doctor":
      return cmdDoctor();
    case "uninstall":
      return cmdUninstall();
    case "rules":
      return cmdRules(!!values.json);
    case "vault":
      return cmdVault(!!values.clear);
    case "hook": {
      if (arg === "claude-code") return runClaudeCodeHook();
      if (arg === "cursor") return runCursorHook();
      if (arg === "pre-commit") return runPreCommit();
      process.stderr.write(`secretgate: unknown hook "${arg ?? ""}"\n`);
      return 2;
    }
    default:
      process.stderr.write(`secretgate: unknown command "${command}"\n\n${USAGE}`);
      return 2;
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    // Hooks must never take the agent down with them. Report and get out of
    // the way; a broken guardrail that blocks all work gets uninstalled.
    process.stderr.write(`secretgate: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(2);
  },
);
