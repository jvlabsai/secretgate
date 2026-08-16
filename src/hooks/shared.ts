import { scan, blocking } from "../core/scan.js";
import { getVault } from "../core/redact.js";
import { VAULT_PATH } from "../core/vault-store.js";
import type { Config, Finding } from "../core/types.js";

/**
 * Redaction only works if the mapping outlives the process that made it —
 * hooks run one process per event — so the store is used whenever redact mode
 * is in play. `vault.persist: false` turns it off, at the cost of rehydration.
 */
function vaultFor(config: Pick<Config, "vault">) {
  return getVault(config.vault.persist ? VAULT_PATH : undefined);
}

export interface GuardOutcome {
  action: "allow" | "modify" | "deny";
  text: string;
  findings: Finding[];
  message?: string;
}

function describe(findings: Finding[]): string {
  const byProvider = new Map<string, number>();
  for (const f of findings) byProvider.set(f.provider, (byProvider.get(f.provider) ?? 0) + 1);
  return [...byProvider.entries()].map(([p, n]) => (n > 1 ? `${n}x ${p}` : p)).join(", ");
}

/**
 * The one decision every adapter needs, so no adapter re-implements policy.
 * Adapters translate the result into whatever shape their agent expects.
 */
export function guardOutbound(text: string, config: Config): GuardOutcome {
  const { findings } = scan(text, config);
  const serious = blocking(findings, config);

  if (serious.length === 0) return { action: "allow", text, findings };

  if (config.mode === "warn") {
    return {
      action: "allow",
      text,
      findings: serious,
      message: `secretgate: ${serious.length} credential(s) detected (${describe(serious)}). Mode is "warn", so nothing was changed.`,
    };
  }

  if (config.mode === "block") {
    return {
      action: "deny",
      text,
      findings: serious,
      message:
        `secretgate blocked this: ${serious.length} credential(s) detected (${describe(serious)}).\n` +
        `Remove them, add "# secretgate:allow" on the line if it is a false positive, ` +
        `or run "secretgate baseline" to accept existing findings.`,
    };
  }

  const vault = vaultFor(config);
  const { text: redacted, replacements } = vault.redact(text, serious);
  return {
    action: "modify",
    text: redacted,
    findings: serious,
    message:
      `secretgate redacted ${replacements.length} credential(s) (${describe(serious)}). ` +
      `The agent sees placeholders; real values are restored locally on write.`,
  };
}

/**
 * Inbound: swap placeholders back before bytes reach disk. Warnings are the
 * important half — a placeholder the agent mangled means the edit is suspect.
 */
export function guardInbound(
  text: string,
  config: Pick<Config, "vault"> = { vault: { persist: true } },
): { text: string; warnings: string[]; substituted: number } {
  const vault = vaultFor(config);
  if (!vault.hasPlaceholders(text)) return { text, warnings: [], substituted: 0 };

  const { text: restored, substituted, warnings } = vault.rehydrate(text);
  return { text: restored, substituted, warnings: warnings.map((w) => `secretgate: ${w.message}`) };
}

export async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

/** Everything an agent might stuff a credential into. */
export function extractToolText(toolName: string, input: Record<string, unknown>): string {
  const parts: string[] = [];
  const interesting = ["command", "content", "new_string", "old_string", "prompt", "query", "body", "text", "file_text"];
  for (const key of interesting) {
    const value = input[key];
    if (typeof value === "string") parts.push(value);
  }
  // Anything else stringifiable, so a novel tool schema still gets scanned.
  if (parts.length === 0) {
    for (const value of Object.values(input)) {
      if (typeof value === "string" && value.length > 8) parts.push(value);
    }
  }
  void toolName;
  return parts.join("\n");
}

/**
 * Reading these is how a well-behaved agent still walks off with your keys.
 *
 * The lookahead matters: `.env.example` and friends are templates, and the
 * denial message we print actively tells the agent to read one instead. Denying
 * both would leave it with nowhere to go.
 */
const SENSITIVE_READ =
  /(?:^|[\\/])(?:\.env(?!\.(?:example|sample|template|dist|schema|defaults))(?:\.[\w-]+)*|\.npmrc|\.pypirc|\.netrc|credentials|id_rsa|id_ed25519|id_ecdsa|[\w.-]*\.(?:pem|p12|pfx|key)|secrets?\.(?:ya?ml|json|toml))$/i;

const SENSITIVE_COMMAND =
  /\b(?:cat|bat|less|more|head|tail|strings|xxd|type)\b[^\n|;&]*(?:\.env|\.npmrc|\.netrc|credentials|id_rsa|id_ed25519)|(?:^|[\s;|&])(?:env|printenv|set)\s*$|\baws\s+configure\s+list|\bgcloud\s+auth\s+print-[\w-]*token|\bsecurity\s+find-generic-password|\bdocker\s+login\b/im;

export function isSensitivePath(path: string): boolean {
  return SENSITIVE_READ.test(path.replace(/\\/g, "/"));
}

export function isSensitiveCommand(command: string): boolean {
  return SENSITIVE_COMMAND.test(command);
}
