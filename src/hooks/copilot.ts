/**
 * GitHub Copilot hook adapter.
 *
 *   preToolUse   the only event available
 *
 * There is no post-tool event, so nothing can be restored on the way back in.
 * Capability is still "redact" because preToolUse can both deny and hand back
 * modified input — a tool call carrying a credential can proceed with a
 * placeholder rather than being refused outright.
 *
 * What that costs, and it is worth being clear about it: a placeholder written
 * by Copilot stays a placeholder on disk. Run `secretgate filter --rehydrate`
 * over the file afterwards, or use `secretgate lock` for the session instead.
 *
 * Hooks are declared in .github/hooks/*.json per repository, with
 * ~/.copilot/config.json as the global fallback.
 */
import { loadConfig } from "../config/index.js";
import { recordBeat } from "../core/heartbeat.js";
import { readStdin } from "./shared.js";
import { decideToolUse } from "./decide.js";

interface CopilotPayload {
  event?: string;
  hook_event_name?: string;
  tool?: string;
  tool_name?: string;
  toolName?: string;
  input?: Record<string, unknown>;
  tool_input?: Record<string, unknown>;
  arguments?: Record<string, unknown>;
  cwd?: string;
  repo_root?: string;
}

function emit(response: object): void {
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

export async function runCopilotHook(): Promise<number> {
  const raw = await readStdin();

  let payload: CopilotPayload;
  try {
    payload = JSON.parse(raw) as CopilotPayload;
  } catch {
    emit({ decision: "allow" });
    return 0;
  }

  const event = payload.event ?? payload.hook_event_name ?? "preToolUse";
  const config = loadConfig(payload.cwd ?? payload.repo_root ?? process.cwd());

  recordBeat("copilot", event || "unknown");

  if (event !== "preToolUse") {
    emit({ decision: "allow" });
    return 0;
  }

  const toolName = payload.tool ?? payload.tool_name ?? payload.toolName ?? "";
  const input = payload.input ?? payload.tool_input ?? payload.arguments ?? {};
  const decision = decideToolUse(toolName, input, config, "redact");

  if (decision.kind === "deny") {
    emit({ decision: "deny", reason: decision.reason });
    return 2;
  }

  if (decision.kind === "modify") {
    emit({
      decision: "modify",
      reason: decision.reason,
      input: withRedacted(input, decision.text),
    });
    return 0;
  }

  if (decision.kind === "ask") {
    // No ask channel here, and allowing silently would hide a real finding.
    emit({ decision: "deny", reason: decision.reason });
    return 2;
  }

  emit({ decision: "allow" });
  return 0;
}

function withRedacted(input: Record<string, unknown>, redacted: string): Record<string, unknown> {
  const out = { ...input };
  for (const key of ["command", "content", "new_string", "prompt", "text", "body"]) {
    if (typeof out[key] === "string") {
      out[key] = redacted;
      return out;
    }
  }
  return out;
}
