import { createHmac, randomBytes } from "node:crypto";
import { inspect } from "node:util";
import type { Finding } from "./types.js";
import { loadStore, saveStore, emptyStore, type StoredVault } from "./vault-store.js";

/**
 * Placeholder shape: SECRETGATE_<PROVIDER>_<KIND>_<suffix>
 *
 * Constraints that drove the shape, all of them learned the hard way:
 *  - uppercase, digits and underscores only, so no language, shell, JSON or
 *    YAML parser will quote, escape or reflow it
 *  - no leading digit, so it is a valid identifier nearly everywhere
 *  - provider and kind are preserved, so the model can still reason about what
 *    the code does ("this is an AWS key") without holding the key
 *  - the suffix is derived from an HMAC under a per-session key, so the same
 *    secret maps to the same placeholder all conversation long, and nothing
 *    about the secret leaks through the placeholder
 */
const PLACEHOLDER_PREFIX = "SECRETGATE_";

// Deliberately greedy and case-insensitive after the prefix: we want to capture
// a mangled placeholder in full so we can refuse it loudly, rather than match a
// clean prefix of it and substitute into garbage.
const PLACEHOLDER_SCAN = /SECRETGATE_[A-Za-z0-9_]*/g;

// Order matters: the first pattern that matches wins, so the specific cases sit
// above the generic ones. Getting this right is not cosmetic — the kind is the
// only thing telling the model what the redacted value *was*, and a connection
// string's password labelled URL reads as though the whole URI went missing.
const KIND_BY_RULE: [RegExp, string][] = [
  [/private-key|pem|ssh|putty/, "PEM"],
  [/jwt/, "JWT"],
  [/webhook/, "URL"],
  [/connection-string|jdbc|basic-auth|password|passwd/, "PASSWORD"],
  [/pat|token|authtoken/, "TOKEN"],
  [/secret/, "SECRET"],
  [/key/, "KEY"],
];

function kindFor(ruleId: string): string {
  for (const [re, kind] of KIND_BY_RULE) {
    if (re.test(ruleId)) return kind;
  }
  return "SECRET";
}

function sanitize(part: string): string {
  const cleaned = part.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "");
  return cleaned || "UNKNOWN";
}

export interface RedactResult {
  text: string;
  /** placeholder -> the finding it stands in for, for reporting. */
  replacements: { placeholder: string; finding: Finding }[];
}

export interface RehydrateWarning {
  kind: "mangled" | "unknown";
  token: string;
  message: string;
}

export interface RehydrateResult {
  text: string;
  substituted: number;
  warnings: RehydrateWarning[];
}

export class Vault {
  /**
   * Keyed material for placeholder suffixes. When the vault is backed by a
   * store this comes from disk, so the same secret keeps the same placeholder
   * across the separate processes each hook invocation runs in.
   */
  #sessionKey: Buffer = randomBytes(32);
  readonly #bySecret = new Map<string, string>();
  readonly #byPlaceholder = new Map<string, string>();
  #wiped = false;
  /** Set when this vault reads and writes an on-disk store. */
  #storePath: string | undefined;

  get size(): number {
    return this.#byPlaceholder.size;
  }

  /**
   * Back this vault with a file, loading whatever is already there.
   *
   * Without this, redact mode is broken in exactly the setup it exists for:
   * the agent hooks run one process per event, so the vault that redacts a
   * prompt has already exited by the time an edit comes back to be restored.
   */
  attachStore(path: string): void {
    this.#storePath = path;
    const store = loadStore(path);
    if (!store) return;

    this.#sessionKey = Buffer.from(store.key, "hex");
    for (const [placeholder, entry] of Object.entries(store.entries)) {
      this.#byPlaceholder.set(placeholder, entry.secret);
      this.#bySecret.set(entry.secret, placeholder);
    }
  }

  #persist(): void {
    if (!this.#storePath || this.#wiped) return;
    const store: StoredVault = emptyStore(this.#sessionKey.toString("hex"));
    const at = Date.now();
    for (const [placeholder, secret] of this.#byPlaceholder) {
      store.entries[placeholder] = { secret, at };
    }
    saveStore(store, this.#storePath);
  }

  /**
   * Stable for the lifetime of this vault: ask twice for the same secret and
   * you get the same placeholder, which is what keeps a multi-turn conversation
   * coherent for the model.
   */
  placeholderFor(finding: Finding): string {
    const existing = this.#bySecret.get(finding.match);
    if (existing) return existing;

    const stem = `${PLACEHOLDER_PREFIX}${sanitize(finding.provider)}_${kindFor(finding.ruleId)}`;
    // Uppercase so the whole placeholder is a single-case identifier. Mixed
    // case invites a model to "tidy" it, and a tidied placeholder is one we
    // have to refuse to rehydrate.
    const digest = createHmac("sha256", this.#sessionKey).update(finding.match).digest("hex").toUpperCase();

    // Four hex characters collide about once in 65k within a single stem.
    // Lengthening on collision keeps the mapping injective, which the whole
    // rehydration story depends on.
    let placeholder = `${stem}_${digest.slice(0, 4)}`;
    for (let len = 6; this.#byPlaceholder.has(placeholder) && len <= digest.length; len += 2) {
      placeholder = `${stem}_${digest.slice(0, len)}`;
    }
    if (this.#byPlaceholder.has(placeholder)) {
      throw new Error("secretgate: exhausted placeholder space for a single secret stem");
    }

    this.#bySecret.set(finding.match, placeholder);
    this.#byPlaceholder.set(placeholder, finding.match);
    return placeholder;
  }

  /** Outbound: swap every finding for its placeholder. */
  redact(text: string, findings: Finding[]): RedactResult {
    const replacements: { placeholder: string; finding: Finding }[] = [];

    // Right to left, so earlier offsets stay valid as the string changes length.
    const ordered = [...findings].sort((a, b) => b.start - a.start);
    let out = text;
    for (const finding of ordered) {
      const placeholder = this.placeholderFor(finding);
      out = out.slice(0, finding.start) + placeholder + out.slice(finding.end);
      replacements.push({ placeholder, finding });
    }

    replacements.reverse();
    if (replacements.length > 0) this.#persist();
    return { text: out, replacements };
  }

  /**
   * Inbound: put the real values back before anything is written to disk.
   *
   * Anything that looks like one of ours but is not an exact match is reported
   * and left alone. Substituting into a placeholder the model reformatted or
   * invented would write a real credential into a location nobody chose, which
   * is a worse outcome than the edit failing.
   */
  rehydrate(text: string): RehydrateResult {
    const warnings: RehydrateWarning[] = [];
    let substituted = 0;

    const out = text.replace(PLACEHOLDER_SCAN, (token) => {
      const value = this.#byPlaceholder.get(token);
      if (value !== undefined) {
        substituted++;
        return value;
      }

      const mangled = this.#looksMangled(token);
      warnings.push(
        mangled
          ? {
              kind: "mangled",
              token,
              message: `"${token}" resembles a secretgate placeholder but does not match one exactly. The value was left as-is; the agent probably truncated or reformatted it. Check the edit before applying.`,
            }
          : {
              kind: "unknown",
              token,
              message: `"${token}" is not a placeholder this session issued. Nothing was substituted. If this came from an agent, it invented it.`,
            },
      );
      return token;
    });

    return { text: out, substituted, warnings };
  }

  /** True when a known placeholder is a prefix of this token, or vice versa. */
  #looksMangled(token: string): boolean {
    for (const known of this.#byPlaceholder.keys()) {
      if (token.startsWith(known) || known.startsWith(token)) return true;
    }
    return false;
  }

  /** Does this text contain any placeholder we issued? */
  hasPlaceholders(text: string): boolean {
    PLACEHOLDER_SCAN.lastIndex = 0;
    return PLACEHOLDER_SCAN.test(text);
  }

  wipe(): void {
    this.#bySecret.clear();
    this.#byPlaceholder.clear();
    this.#sessionKey.fill(0);
    this.#wiped = true;
  }

  get wiped(): boolean {
    return this.#wiped;
  }

  // The two ways a secret would otherwise end up in a log line, a crash dump or
  // an error message: someone JSON.stringify's the vault, or console.log's it.
  toJSON(): string {
    return `[secretgate vault: ${this.size} entries, contents withheld]`;
  }

  toString(): string {
    return this.toJSON();
  }

  [inspect.custom](): string {
    return this.toJSON();
  }
}

/**
 * One vault per process, optionally backed by a store so it survives the gap
 * between one hook invocation and the next.
 */
let processVault: Vault | undefined;

export function getVault(storePath?: string): Vault {
  if (!processVault) {
    processVault = new Vault();
    if (storePath) processVault.attachStore(storePath);
    const wipe = () => processVault?.wipe();
    process.once("exit", wipe);
    process.once("SIGINT", () => {
      wipe();
      process.exit(130);
    });
    process.once("SIGTERM", () => {
      wipe();
      process.exit(143);
    });
  }
  return processVault;
}

/** Tests need a clean slate; production never calls this. */
export function resetVaultForTesting(): void {
  processVault?.wipe();
  processVault = undefined;
}

export { PLACEHOLDER_PREFIX };
