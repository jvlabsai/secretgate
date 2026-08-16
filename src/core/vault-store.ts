import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";

/**
 * On-disk backing for the vault.
 *
 * Why this has to exist at all: every hook invocation is its own process.
 * Claude Code runs `secretgate hook claude-code` once for UserPromptSubmit and
 * again for PostToolUse, so an in-memory vault is already gone by the time the
 * agent hands an edit back. Without a store, redact mode can swap a secret out
 * and can never put it back, which makes the whole feature decorative.
 *
 * The trade this makes, stated plainly rather than buried: while a session is
 * live, secrets sit in a file under the user's home directory. That file is
 * 0600, entries expire, and `secretgate vault --clear` removes it. The
 * justification is narrow — anything able to read it already has the user's
 * privileges and could read ~/.aws/credentials or the .env directly, so the
 * store does not meaningfully widen the attack surface. It is still a real
 * trade, and anyone who does not want to make it should run `mode: block`.
 *
 * Deliberately not encrypted. Any key we could store would have to live beside
 * the ciphertext on the same disk with the same permissions, which buys
 * approximately nothing and invites a security claim we could not defend. An
 * OS-keychain-backed key would be genuinely better and needs a native
 * dependency; it is tracked, not pretended.
 */

export const STATE_DIR = join(homedir(), ".secretgate");
export const VAULT_PATH = join(STATE_DIR, "vault.json");

/** Entries older than this are dropped on load. */
export const DEFAULT_TTL_MS = 12 * 60 * 60 * 1000;

interface StoredEntry {
  secret: string;
  /** Epoch millis, for expiry. */
  at: number;
}

export interface StoredVault {
  version: 1;
  /**
   * HMAC key for placeholder suffixes. Persisted so the same secret maps to the
   * same placeholder across processes — without that, every hook invocation
   * would mint a new name for a value the model has already seen.
   */
  key: string;
  entries: Record<string, StoredEntry>;
}

export function emptyStore(key: string): StoredVault {
  return { version: 1, key, entries: {} };
}

export function loadStore(path: string = VAULT_PATH, ttlMs: number = DEFAULT_TTL_MS): StoredVault | null {
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as StoredVault;
    if (parsed?.version !== 1 || typeof parsed.key !== "string" || !parsed.entries) return null;

    const cutoff = Date.now() - ttlMs;
    const fresh: Record<string, StoredEntry> = {};
    for (const [placeholder, entry] of Object.entries(parsed.entries)) {
      if (entry && typeof entry.secret === "string" && typeof entry.at === "number" && entry.at >= cutoff) {
        fresh[placeholder] = entry;
      }
    }
    return { version: 1, key: parsed.key, entries: fresh };
  } catch {
    // A corrupt store must not break the agent. Starting fresh means
    // rehydration fails loudly for old placeholders, which is the safe
    // direction — it never substitutes the wrong value.
    return null;
  }
}

export function saveStore(store: StoredVault, path: string = VAULT_PATH): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(store), { mode: 0o600 });
  try {
    // writeFileSync only applies mode when creating; enforce it either way.
    chmodSync(path, 0o600);
  } catch {
    /* windows has no POSIX mode bits */
  }
}

export function clearStore(path: string = VAULT_PATH): boolean {
  if (!existsSync(path)) return false;
  rmSync(path, { force: true });
  return true;
}

export function storeStatus(path: string = VAULT_PATH): { exists: boolean; entries: number; path: string } {
  const store = loadStore(path);
  return { exists: existsSync(path), entries: store ? Object.keys(store.entries).length : 0, path };
}
