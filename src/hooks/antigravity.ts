/**
 * Antigravity hook adapter.
 *
 *   PreToolUse   tool arguments, before the tool runs
 *   PostToolUse  tool results, before anything lands on disk
 *
 * Matchers are regular expressions rather than the glob-ish strings Claude Code
 * uses, and a workspace hooks.json overrides the global one rather than merging
 * with it — both facts matter to the installer, not to this file.
 *
 * Capability is "redact": PostToolUse can restore values on the way back in.
 * There is no argument-override channel, so a redactable tool call becomes an
 * ask, exactly as on Claude Code.
 */
import { loadConfig } from "../config/index.js";
import { recordBeat } from "../core/heartbeat.js";
import { readStdin } from "./shared.js";
import { decideToolUse, decideToolResult } from "./decide.js";

interface AntigravityPayload {
  hook_event_name?: string;
  event?: string;
  tool_name?: string;
  tool?: string;
  tool_input?: Record<string, unknown>;
  input?: Record<string, unknown>;
  tool_output?: unknown;
  output?: unknown;
  cwd?: string;
  workspace_root?: string;
}

function emit(response: object): void {
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

export async function runAntigravityHook(): Promise<number> {
  const raw = await readStdin();

  let payload: AntigravityPayload;
  try {
    payload = JSON.parse(raw) as AntigravityPayload;
  } catch {
    emit({ permission: "allow" });
    return 0;
  }

  const event = payload.hook_event_name ?? payload.event ?? "";
  const cwd = payload.cwd ?? payload.workspace_root ?? process.cwd();
  const config = loadConfig(cwd);

  recordBeat("antigravity", event || "unknown");

  if (event === "PreToolUse") {
    const toolName = payload.tool_name ?? payload.tool ?? "";
    const input = payload.tool_input ?? payload.input ?? {};
    const decision = decideToolUse(toolName, input, config, "redact");

    if (decision.kind === "deny") {
      emit({ permission: "deny", reason: decision.reason, message: decision.reason });
      return 2;
    }
    if (decision.kind === "modify" || decision.kind === "ask") {
      emit({ permission: "ask", reason: decision.reason, message: decision.reason });
      return 0;
    }
    emit({ permission: "allow" });
    return 0;
  }

  if (event === "PostToolUse") {
    const { context } = decideToolResult(payload.tool_output ?? payload.output, config);
    emit(context ? { permission: "allow", message: context } : { permission: "allow" });
    return 0;
  }

  emit({ permission: "allow" });
  return 0;
}
