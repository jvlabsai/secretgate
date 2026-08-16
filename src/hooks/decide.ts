import { guardOutbound, guardInbound, extractToolText, isSensitivePath, isSensitiveCommand } from "./shared.js";
import type { Config } from "../core/types.js";

/**
 * What an adapter's host agent can actually do about a finding.
 *
 *   redact   the agent will accept modified tool input, so a secret can be
 *            swapped for a placeholder and restored afterwards
 *   block    the agent can only be told yes or no. Redaction is impossible,
 *            so a redactable finding has to become a refusal instead
 *   partial  block-only, and the hook does not even see every tool. Coverage
 *            has real gaps and the user has to be told which
 *
 * This exists so the distinction is enforced in one place rather than trusted
 * to five adapters. Someone on Windsurf must never be left believing their
 * values are being restored when the host has no mechanism to do it.
 */
export type Capability = "redact" | "block" | "partial";

export type Decision =
  | { kind: "allow" }
  | { kind: "deny"; reason: string }
  | { kind: "ask"; reason: string }
  | { kind: "modify"; reason: string; text: string };

/**
 * A host that cannot rewrite tool input cannot redact. Downgrading here, once,
 * is what stops an adapter quietly promising more than its agent supports.
 */
function applyCapability(decision: Decision, capability: Capability): Decision {
  if (decision.kind !== "modify") return decision;
  if (capability === "redact") return decision;
  return {
    kind: "deny",
    reason:
      `${decision.reason}\n\n` +
      `This agent cannot accept rewritten tool input, so the operation was blocked ` +
      `rather than redacted. Remove the credential, or run "secretgate lock" first ` +
      `so the file holds placeholders while you work.`,
  };
}

export function decidePrompt(prompt: string, config: Config, capability: Capability): Decision {
  if (!prompt) return { kind: "allow" };

  const outcome = guardOutbound(prompt, config);
  if (outcome.action === "deny") return { kind: "deny", reason: outcome.message ?? "credential detected" };
  if (outcome.action === "modify") {
    return applyCapability({ kind: "modify", reason: outcome.message ?? "credential redacted", text: outcome.text }, capability);
  }
  if (outcome.message) return { kind: "ask", reason: outcome.message };
  return { kind: "allow" };
}

/**
 * Path and command checks come first and are absolute. Reading a credentials
 * file leaks it whether or not its contents match any pattern, and that holds
 * for every host regardless of capability.
 */
export function decideToolUse(
  toolName: string,
  input: Record<string, unknown>,
  config: Config,
  capability: Capability,
): Decision {
  const filePath =
    (typeof input.file_path === "string" && input.file_path) ||
    (typeof input.path === "string" && input.path) ||
    (typeof input.filePath === "string" && input.filePath) ||
    (typeof input.absolute_path === "string" && input.absolute_path) ||
    "";

  if (filePath && isSensitivePath(filePath)) {
    return {
      kind: "deny",
      reason: `secretgate: ${filePath} holds credentials. Read the key names from a .env.example instead, or add an allowlist entry if this file is genuinely safe.`,
    };
  }

  const command =
    (typeof input.command === "string" && input.command) ||
    (typeof input.cmd === "string" && input.cmd) ||
    (typeof input.script === "string" && input.script) ||
    "";

  if (command && isSensitiveCommand(command)) {
    return {
      kind: "deny",
      reason: `secretgate: this command would print credentials to the transcript.\n  ${command.slice(0, 200)}`,
    };
  }

  const text = extractToolText(toolName, input);
  if (!text) return { kind: "allow" };

  const outcome = guardOutbound(text, config);
  if (outcome.action === "deny") return { kind: "deny", reason: outcome.message ?? "credential detected" };
  if (outcome.action === "modify") {
    return applyCapability({ kind: "modify", reason: outcome.message ?? "credential redacted", text: outcome.text }, capability);
  }
  if (outcome.message) return { kind: "ask", reason: outcome.message };
  return { kind: "allow" };
}

export interface ResultVerdict {
  context: string | undefined;
  substituted: number;
  warnings: string[];
}

/** Inbound: restore placeholders before anything reaches disk. */
export function decideToolResult(result: unknown, config: Config): ResultVerdict {
  const text = stringifyResult(result);
  if (!text) return { context: undefined, substituted: 0, warnings: [] };

  const { warnings, substituted } = guardInbound(text, config);
  if (warnings.length > 0) return { context: warnings.join("\n"), substituted, warnings };
  if (substituted > 0) {
    return { context: `secretgate restored ${substituted} real value(s) locally.`, substituted, warnings: [] };
  }
  return { context: undefined, substituted: 0, warnings: [] };
}

export function stringifyResult(result: unknown): string {
  if (typeof result === "string") return result;
  if (Array.isArray(result)) return result.map(stringifyResult).filter(Boolean).join("\n");
  if (result && typeof result === "object") {
    const parts: string[] = [];
    for (const value of Object.values(result as Record<string, unknown>)) {
      if (typeof value === "string") parts.push(value);
      else if (value && typeof value === "object") parts.push(stringifyResult(value));
    }
    return parts.join("\n");
  }
  return "";
}
