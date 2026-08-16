/**
 * Codex hook adapter.
 *
 * CAPABILITY: BLOCK ONLY, PARTIAL COVERAGE.
 *
 * Two limits, both of which the user has to be told about rather than left to
 * discover:
 *
 *   1. Hooks are behind a feature flag. Without `[features] codex_hooks = true`
 *      in config.toml nothing fires at all, and the failure is silent.
 *   2. PreToolUse only sees Bash. File reads never reach this adapter, so
 *      Codex opening .env directly is not something secretgate can intercept.
 *      `updatedInput` is rejected by the host, so nothing can be redacted
 *      either.
 *
 * That combination is why `init` prints a warning for Codex and `doctor` shows
 * "partial" beside it. Anyone wanting real coverage here should use
 * `secretgate lock`, which does not depend on the host cooperating at all.
 */
import { loadConfig } from "../config/index.js";
import { recordBeat } from "../core/heartbeat.js";
import { readStdin } from "./shared.js";
import { decideToolUse } from "./decide.js";

interface CodexPayload {
  hook_event_name?: string;
  event?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  command?: string | string[];
  cwd?: string;
}

function emit(response: object): void {
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

export async function runCodexHook(): Promise<number> {
  const raw = await readStdin();

  let payload: CodexPayload;
  try {
    payload = JSON.parse(raw) as CodexPayload;
  } catch {
    emit({});
    return 0;
  }

  const event = payload.hook_event_name ?? payload.event ?? "";
  const config = loadConfig(payload.cwd ?? process.cwd());

  recordBeat("codex", event || "unknown");

  if (event !== "PreToolUse") {
    emit({});
    return 0;
  }

  // Bash is the only tool this event covers. Codex passes the command either
  // as a string or as argv, depending on how it was invoked.
  const raw_command = payload.command ?? payload.tool_input?.command;
  const command = Array.isArray(raw_command) ? raw_command.join(" ") : typeof raw_command === "string" ? raw_command : "";

  if (!command) {
    emit({});
    return 0;
  }

  // "block" capability: a redactable finding is downgraded to a refusal,
  // because updatedInput would be rejected by the host anyway.
  const decision = decideToolUse("Bash", { command }, config, "block");

  if (decision.kind === "deny") {
    emit({ decision: "block", reason: decision.reason });
    return 2;
  }

  emit({});
  return 0;
}
