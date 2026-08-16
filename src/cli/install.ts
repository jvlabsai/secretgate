/**
 * Wiring and unwiring other tools' config files.
 *
 * The rule this file exists to enforce: never leave someone's editor config in
 * a state they did not choose. Every write is preceded by a backup, every
 * change is recorded in a manifest, and `uninstall` restores from that manifest
 * rather than trying to guess what it once looked like.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, chmodSync, rmSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join, dirname } from "node:path";

export const STATE_DIR = join(homedir(), ".secretgate");
const MANIFEST = join(STATE_DIR, "install.json");
const HOOK_COMMAND = "secretgate hook claude-code";

export interface InstallRecord {
  agent: string;
  file: string;
  backup?: string;
  /** The file did not exist before us, so uninstall deletes it outright. */
  created?: boolean;
}

export interface Manifest {
  version: 1;
  installedAt: string;
  records: InstallRecord[];
}

function readManifest(): Manifest {
  if (!existsSync(MANIFEST)) return { version: 1, installedAt: "", records: [] };
  try {
    return JSON.parse(readFileSync(MANIFEST, "utf8")) as Manifest;
  } catch {
    return { version: 1, installedAt: "", records: [] };
  }
}

function writeManifest(manifest: Manifest): void {
  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(MANIFEST, `${JSON.stringify(manifest, null, 2)}\n`);
}

function backup(file: string, stamp: string): string {
  const dest = `${file}.secretgate-backup-${stamp}`;
  copyFileSync(file, dest);
  return dest;
}

// --- agent detection ------------------------------------------------------

export interface DetectedAgent {
  id: string;
  name: string;
  /** The config file we would touch. */
  file: string;
  present: boolean;
  supported: boolean;
  note?: string;
}

export function detectAgents(): DetectedAgent[] {
  const home = homedir();
  const win = platform() === "win32";

  const claudeDir = join(home, ".claude");
  const cursorDir = win ? join(home, "AppData", "Roaming", "Cursor") : join(home, ".cursor");
  const codexDir = join(home, ".codex");
  const windsurfDir = join(home, ".codeium", "windsurf");
  const aiderConf = join(home, ".aider.conf.yml");

  return [
    {
      id: "claude-code",
      name: "Claude Code",
      file: join(claudeDir, "settings.json"),
      present: existsSync(claudeDir),
      supported: true,
    },
    {
      id: "cursor",
      name: "Cursor",
      file: join(cursorDir, "hooks.json"),
      present: existsSync(cursorDir),
      supported: true,
    },
    {
      id: "codex",
      name: "Codex",
      file: join(codexDir, "config.toml"),
      present: existsSync(codexDir),
      supported: false,
      note: "Adapter not written yet. Use `secretgate filter`.",
    },
    {
      id: "windsurf",
      name: "Windsurf",
      file: join(windsurfDir, "settings.json"),
      present: existsSync(windsurfDir),
      supported: false,
      note: "Adapter not written yet. Use `secretgate filter`.",
    },
    {
      id: "aider",
      name: "Aider",
      file: aiderConf,
      present: existsSync(aiderConf),
      supported: false,
      note: "Adapter not written yet. Use `secretgate filter`.",
    },
  ];
}

// --- claude code ----------------------------------------------------------

interface HookEntry {
  type: string;
  command: string;
}
interface HookMatcher {
  matcher?: string;
  hooks: HookEntry[];
}

function hasOurHook(matchers: HookMatcher[] | undefined): boolean {
  return (matchers ?? []).some((m) => (m.hooks ?? []).some((h) => h.command?.includes("secretgate")));
}

function addHook(settings: Record<string, any>, event: string, matcher?: string): boolean {
  settings.hooks ??= {};
  const existing: HookMatcher[] = settings.hooks[event] ?? [];
  if (hasOurHook(existing)) return false;

  const entry: HookMatcher = matcher
    ? { matcher, hooks: [{ type: "command", command: HOOK_COMMAND }] }
    : { hooks: [{ type: "command", command: HOOK_COMMAND }] };

  settings.hooks[event] = [...existing, entry];
  return true;
}

export function installClaudeCode(): { changed: boolean; file: string; note: string } {
  const file = join(homedir(), ".claude", "settings.json");
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const existed = existsSync(file);

  let settings: Record<string, any> = {};
  if (existed) {
    const raw = readFileSync(file, "utf8");
    try {
      settings = raw.trim() ? JSON.parse(raw) : {};
    } catch {
      // Refuse to touch a file we cannot parse. Rewriting it would mean
      // discarding settings we failed to read, which is unforgivable.
      return {
        changed: false,
        file,
        note: `could not parse ${file}; left untouched. Fix the JSON and re-run.`,
      };
    }
  }

  const before = JSON.stringify(settings);
  addHook(settings, "UserPromptSubmit");
  addHook(settings, "PreToolUse", "*");
  addHook(settings, "PostToolUse", "*");
  const after = JSON.stringify(settings);

  if (before === after) return { changed: false, file, note: "already wired" };

  const manifest = readManifest();
  const record: InstallRecord = { agent: "claude-code", file };

  mkdirSync(dirname(file), { recursive: true });
  if (existed) record.backup = backup(file, stamp);
  else record.created = true;

  writeFileSync(file, `${JSON.stringify(settings, null, 2)}\n`);

  manifest.records = manifest.records.filter((r) => r.file !== file);
  manifest.records.push(record);
  manifest.installedAt = new Date().toISOString();
  writeManifest(manifest);

  return { changed: true, file, note: existed ? `wired (backup: ${record.backup})` : "wired (file created)" };
}

// --- cursor ---------------------------------------------------------------

const CURSOR_EVENTS = ["beforeSubmitPrompt", "beforeShellExecution", "beforeReadFile", "afterFileEdit"];
const CURSOR_COMMAND = "secretgate hook cursor";

export function installCursor(): { changed: boolean; file: string; note: string } {
  const win = platform() === "win32";
  const dir = win ? join(homedir(), "AppData", "Roaming", "Cursor") : join(homedir(), ".cursor");
  const file = join(dir, "hooks.json");
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const existed = existsSync(file);

  let settings: Record<string, any> = {};
  if (existed) {
    const raw = readFileSync(file, "utf8");
    try {
      settings = raw.trim() ? JSON.parse(raw) : {};
    } catch {
      return { changed: false, file, note: `could not parse ${file}; left untouched. Fix the JSON and re-run.` };
    }
  }

  settings.version ??= 1;
  settings.hooks ??= {};

  const before = JSON.stringify(settings);
  for (const event of CURSOR_EVENTS) {
    const existing: { command?: string }[] = settings.hooks[event] ?? [];
    if (existing.some((h) => h.command?.includes("secretgate"))) continue;
    settings.hooks[event] = [...existing, { command: CURSOR_COMMAND }];
  }
  const after = JSON.stringify(settings);

  if (before === after) return { changed: false, file, note: "already wired" };

  const manifest = readManifest();
  const record: InstallRecord = { agent: "cursor", file };

  mkdirSync(dirname(file), { recursive: true });
  if (existed) record.backup = backup(file, stamp);
  else record.created = true;

  writeFileSync(file, `${JSON.stringify(settings, null, 2)}\n`);

  manifest.records = manifest.records.filter((r) => r.file !== file);
  manifest.records.push(record);
  manifest.installedAt = new Date().toISOString();
  writeManifest(manifest);

  return { changed: true, file, note: existed ? `wired (backup: ${record.backup})` : "wired (file created)" };
}

// --- git pre-commit -------------------------------------------------------

const GIT_HOOK_BODY = `#!/bin/sh
# installed by secretgate
exec secretgate hook pre-commit
`;

export function installGitHook(repoRoot: string): { changed: boolean; file: string; note: string } {
  const hooksDir = join(repoRoot, ".git", "hooks");
  const file = join(hooksDir, "pre-commit");

  if (!existsSync(join(repoRoot, ".git"))) return { changed: false, file, note: "not a git repository" };

  if (existsSync(file)) {
    const current = readFileSync(file, "utf8");
    if (current.includes("secretgate")) return { changed: false, file, note: "already wired" };

    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const manifest = readManifest();
    const saved = backup(file, stamp);
    // Chain rather than clobber: whatever was there runs first, and we only
    // add our check on top.
    const chained = `${current.trimEnd()}\n\n# added by secretgate\nsecretgate hook pre-commit || exit 1\n`;
    writeFileSync(file, chained);
    try {
      chmodSync(file, 0o755);
    } catch {
      /* windows has no execute bit */
    }
    manifest.records = manifest.records.filter((r) => r.file !== file);
    manifest.records.push({ agent: "git", file, backup: saved });
    manifest.installedAt = new Date().toISOString();
    writeManifest(manifest);
    return { changed: true, file, note: `appended to existing hook (backup: ${saved})` };
  }

  mkdirSync(hooksDir, { recursive: true });
  writeFileSync(file, GIT_HOOK_BODY);
  try {
    chmodSync(file, 0o755);
  } catch {
    /* windows has no execute bit */
  }

  const manifest = readManifest();
  manifest.records = manifest.records.filter((r) => r.file !== file);
  manifest.records.push({ agent: "git", file, created: true });
  manifest.installedAt = new Date().toISOString();
  writeManifest(manifest);

  return { changed: true, file, note: "hook created" };
}

// --- uninstall ------------------------------------------------------------

export function uninstallAll(): { restored: string[]; removed: string[]; problems: string[] } {
  const manifest = readManifest();
  const restored: string[] = [];
  const removed: string[] = [];
  const problems: string[] = [];

  for (const record of manifest.records) {
    try {
      if (record.backup && existsSync(record.backup)) {
        copyFileSync(record.backup, record.file);
        rmSync(record.backup, { force: true });
        restored.push(record.file);
      } else if (record.created) {
        rmSync(record.file, { force: true });
        removed.push(record.file);
      } else {
        problems.push(`${record.file}: no backup recorded, left as-is`);
      }
    } catch (err) {
      problems.push(`${record.file}: ${String(err)}`);
    }
  }

  rmSync(MANIFEST, { force: true });
  return { restored, removed, problems };
}

export function installedRecords(): InstallRecord[] {
  return readManifest().records;
}
