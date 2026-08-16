/**
 * The Claude Code hook contract, and every agent that copied it.
 *
 * Gemini CLI adopted the same shape — JSON on stdin, exit 2 blocks,
 * BeforeTool may override tool_input — so it runs through this same code with
 * different event names rather than a forked adapter. Two copies of this logic
 * would drift, and the second copy is always the one that stops being
 * maintained.
 *
 * Every field is read defensively and an unrecognised payload is allowed
 * through. These APIs are young and move; a guardrail that bricks the agent on
 * a schema change is a guardrail people uninstall. The heartbeat is what makes
 * failing open survivable — `doctor` will say the hook stopped firing.
 */
import { loadConfig } from "../config/index.js";
import { recordBeat } from "../core/heartbeat.js";
import { readStdin } from "./shared.js";
import { decidePrompt, decideToolUse, decideToolResult, type Capability } from "./decide.js";

export interface ClaudeCompatEvents {
  /** Absent when the host has no prompt-submit event. */
  prompt?: string;
  preTool: string;
  postTool: string;
}

export interface ClaudeCompatOptions {
  agentId: string;
  events: ClaudeCompatEvents;
  capability: Capability;
  /**
   * Hosts that accept a rewritten tool_input from the pre-tool hook. Only
   * Gemini's BeforeTool does; Claude Code has no such channel and has to ask
   * the developer instead.
   */
  supportsInputOverride?: boolean;
}

interface HookPayload {
  hook_event_name?: string;
  hookEventName?: string;
  prompt?: string;
  tool_name?: string;
  toolName?: string;
  tool_input?: Record<string, unknown>;
  toolInput?: Record<string, unknown>;
  tool_response?: unknown;
  toolResponse?: unknown;
  cwd?: string;
}

function emit(response: object): void {
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

export async function runClaudeCompatibleHook(opts: ClaudeCompatOptions): Promise<number> {
  const raw = await readStdin();

  let payload: HookPayload;
  try {
    payload = JSON.parse(raw) as HookPayload;
  } catch {
    emit({});
    return 0;
  }

  const event = payload.hook_event_name ?? payload.hookEventName ?? "";
  const config = loadConfig(payload.cwd ?? process.cwd());

  // Stamped before any decision, so `doctor` can tell "configured" from
  // "actually being called".
  recordBeat(opts.agentId, event || "unknown");

  if (opts.events.prompt && event === opts.events.prompt) {
    const decision = decidePrompt(payload.prompt ?? "", config, opts.capability);

    if (decision.kind === "deny") {
      emit({
        decision: "block",
        reason: decision.reason,
        hookSpecificOutput: { hookEventName: event, additionalContext: decision.reason },
      });
      return 0;
    }
    if (decision.kind === "modify") {
      // No prompt-rewrite channel exists on either host, so the redacted text
      // is handed back and the original is stopped. Blunt, but it is the
      // difference between the model seeing a live key and not.
      emit({
        decision: "block",
        reason: `${decision.reason}\n\nRedacted prompt follows; work from this version:\n\n${decision.text}`,
        hookSpecificOutput: { hookEventName: event, additionalContext: decision.text },
      });
      return 0;
    }
    if (decision.kind === "ask") {
      emit({ hookSpecificOutput: { hookEventName: event, additionalContext: decision.reason } });
      return 0;
    }
    emit({});
    return 0;
  }

  if (event === opts.events.preTool) {
    const toolName = payload.tool_name ?? payload.toolName ?? "";
    const input = payload.tool_input ?? payload.toolInput ?? {};
    const decision = decideToolUse(toolName, input, config, opts.capability);

    if (decision.kind === "deny") {
      emit({
        hookSpecificOutput: {
          hookEventName: event,
          permissionDecision: "deny",
          permissionDecisionReason: decision.reason,
        },
      });
      return 2; // exit 2 blocks on both hosts
    }

    if (decision.kind === "modify") {
      if (opts.supportsInputOverride) {
        // The good case: hand back rewritten arguments and let the tool run
        // with placeholders in place of the credential.
        emit({
          hookSpecificOutput: {
            hookEventName: event,
            permissionDecision: "allow",
            permissionDecisionReason: decision.reason,
            updatedInput: redactInput(input, decision.text),
          },
        });
        return 0;
      }
      emit({
        hookSpecificOutput: {
          hookEventName: event,
          permissionDecision: "ask",
          permissionDecisionReason: decision.reason,
        },
      });
      return 0;
    }

    if (decision.kind === "ask") {
      emit({
        hookSpecificOutput: { hookEventName: event, permissionDecision: "ask", permissionDecisionReason: decision.reason },
      });
      return 0;
    }

    emit({});
    return 0;
  }

  if (event === opts.events.postTool) {
    const { context } = decideToolResult(payload.tool_response ?? payload.toolResponse, config);
    emit(context ? { hookSpecificOutput: { hookEventName: event, additionalContext: context } } : {});
    return 0;
  }

  emit({});
  return 0;
}

/**
 * Puts the redacted text back into whichever field it came from. Only the
 * long free-text fields are candidates — rewriting a file path or a boolean
 * would corrupt the call.
 */
function redactInput(input: Record<string, unknown>, redacted: string): Record<string, unknown> {
  const out = { ...input };
  for (const key of ["command", "content", "new_string", "prompt", "text", "file_text", "body"]) {
    if (typeof out[key] === "string") {
      out[key] = redacted;
      return out;
    }
  }
  return out;
}
