import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, chmodSync, readdirSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { scan, blocking } from "../core/scan.js";
import { getVault } from "../core/redact.js";
import { STATE_DIR, VAULT_PATH } from "../core/vault-store.js";
import type { Config } from "../core/types.js";

/**
 * Lock and unlock a .env in place.
 *
 * The hooks only work for agents we have an adapter for. Everyone else — and
 * that is most people — asks a fair question: if the agent can see the whole
 * project folder, what stops it opening .env? Nothing does. There is no hook to
 * intercept the read.
 *
 * So instead of hiding the file, empty it. `lock` swaps every value in .env for
 * the same placeholder the redaction path uses and moves the real values to
 * ~/.secretgate — outside the workspace, where a project-scoped agent cannot
 * reach. The agent reads .env and finds SECRETGATE_LINKEDIN_TOKEN_A3F4. There is
 * nothing to leak because the secret is not there.
 *
 * The cost is real and has to be stated plainly: your app cannot run while
 * locked, because the environment now holds placeholders. This is a "let the
 * agent work on it" mode, not something to leave on.
 *
 * Backups go outside the workspace too, and are written before anything is
 * modified. Losing someone's only copy of a credential would be far worse than
 * the leak this prevents.
 */

const BACKUP_DIR = join(STATE_DIR, "backups");

function backupPathFor(envPath: string): string {
  const hash = createHash("sha256").update(resolve(envPath)).digest("hex").slice(0, 16);
  return join(BACKUP_DIR, `${basename(envPath)}.${hash}.bak`);
}

export interface LockResult {
  path: string;
  locked: number;
  alreadyLocked: boolean;
  backup: string | undefined;
  skipped?: string;
}

export function isLocked(contents: string): boolean {
  return /^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*SECRETGATE_[A-Z0-9_]+\s*$/m.test(contents);
}

export function lockEnvFile(envPath: string, config: Config): LockResult {
  // Last line of defence. Even if a caller hands us a path inside our own state
  // directory, never write to it — that is where the only copy of the real
  // values lives, and locking it would destroy them.
  if (resolve(envPath).startsWith(resolve(STATE_DIR))) {
    return { path: envPath, locked: 0, alreadyLocked: false, backup: undefined, skipped: "inside secretgate state" };
  }

  const original = readFileSync(envPath, "utf8");

  if (isLocked(original)) {
    return { path: envPath, locked: 0, alreadyLocked: true, backup: undefined };
  }

  const findings = blocking(scan(original, { ...config, path: envPath }).findings, config);
  if (findings.length === 0) {
    return { path: envPath, locked: 0, alreadyLocked: false, backup: undefined, skipped: "no credentials found" };
  }

  // Backup first, outside the workspace, before a single byte is changed.
  mkdirSync(BACKUP_DIR, { recursive: true });
  const backup = backupPathFor(envPath);
  writeFileSync(backup, original, { mode: 0o600 });
  try {
    chmodSync(backup, 0o600);
  } catch {
    /* windows has no POSIX mode bits */
  }

  const vault = getVault(VAULT_PATH);
  const { text } = vault.redact(original, findings);
  writeFileSync(envPath, text);

  return { path: envPath, locked: findings.length, alreadyLocked: false, backup };
}

export interface UnlockResult {
  path: string;
  restored: number;
  warnings: string[];
  usedBackup: boolean;
  skipped?: string;
}

export function unlockEnvFile(envPath: string): UnlockResult {
  const current = readFileSync(envPath, "utf8");

  if (!isLocked(current)) {
    return { path: envPath, restored: 0, warnings: [], usedBackup: false, skipped: "not locked" };
  }

  const vault = getVault(VAULT_PATH);
  const { text, substituted, warnings } = vault.rehydrate(current);

  if (substituted > 0 && warnings.length === 0) {
    writeFileSync(envPath, text);
    return { path: envPath, restored: substituted, warnings: [], usedBackup: false };
  }

  // The vault could not fully restore it — expired entries, a cleared vault, a
  // different machine. The backup is the reason this is recoverable at all.
  const backup = backupPathFor(envPath);
  if (existsSync(backup)) {
    writeFileSync(envPath, readFileSync(backup, "utf8"));
    return {
      path: envPath,
      restored: -1,
      warnings: warnings.map((w) => w.message),
      usedBackup: true,
    };
  }

  return {
    path: envPath,
    restored: substituted,
    warnings: [
      ...warnings.map((w) => w.message),
      `No backup found at ${backup}. Some values could not be restored — you will need to re-enter them.`,
    ],
    usedBackup: false,
  };
}

/** Backups outlive the vault's 12h expiry, so they need their own cleanup. */
export function clearBackups(): number {
  if (!existsSync(BACKUP_DIR)) return 0;
  let removed = 0;
  for (const file of readdirSafe(BACKUP_DIR)) {
    rmSync(join(BACKUP_DIR, file), { force: true });
    removed++;
  }
  return removed;
}

function readdirSafe(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

export { BACKUP_DIR };
