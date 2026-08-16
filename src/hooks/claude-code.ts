/**
 * Claude Code hook adapter.
 *
 * Reads a hook payload on stdin, writes a hook response on stdout. Three events:
 *
 *   UserPromptSubmit  the developer's prompt, before the model sees it
 *   PreToolUse        tool arguments, before the tool runs
 *   PostToolUse       tool results, before anything lands on disk
 *
 * Hook payload shapes drift between Claude Code releases, so every field is
 * read defensively and an unrecognised payload is allowed through rather than
 * failing closed. A guardrail that bricks the agent on an unexpected schema is
 * a guardrail people remove.
 */
import { loadConfig } from "../config/index.js";
import { guardOutbound, guardInbound, extractToolText, isSensitivePath, isSensitiveCommand, readStdin } from "./shared.js";

interface HookPayload {
  hook_event_name?: string;
  prompt?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_response?: unknown;
  cwd?: string;
}

function emit(response: object): void {
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

function allow(): void {
  emit({});
}

function stringifyResponse(response: unknown): string {
  if (typeof response === "string") return response;
  if (response && typeof response === "object") {
    const parts: string[] = [];
    for (const value of Object.values(response as Record<string, unknown>)) {
      if (typeof value === "string") parts.push(value);
    }
    return parts.join("\n");
  }
  return "";
}

export async function runClaudeCodeHook(): Promise<number> {
  const raw = await readStdin();
  let payload: HookPayload;
  try {
    payload = JSON.parse(raw) as HookPayload;
  } catch {
    // Not a payload we understand. Say nothing and let the agent proceed.
    allow();
    return 0;
  }

  const config = loadConfig(payload.cwd ?? process.cwd());
  const event = payload.hook_event_name ?? "";

  if (event === "UserPromptSubmit") {
    const prompt = payload.prompt ?? "";
    if (!prompt) return allow(), 0;

    const outcome = guardOutbound(prompt, config);
    if (outcome.action === "deny") {
      emit({
        decision: "block",
        reason: outcome.message,
        hookSpecificOutput: { hookEventName: "UserPromptSubmit", additionalContext: outcome.message },
      });
      return 0;
    }
    if (outcome.action === "modify") {
      // Claude Code has no prompt-rewrite channel, so the redaction is
      // delivered as context and the original prompt is blocked. Blunt, but it
      // is the difference between the model seeing a live key and not.
      emit({
        decision: "block",
        reason:
          `${outcome.message}\n\nRedacted prompt follows; work from this version:\n\n${outcome.text}`,
        hookSpecificOutput: { hookEventName: "UserPromptSubmit", additionalContext: outcome.text },
      });
      return 0;
    }
    if (outcome.message) {
      emit({ hookSpecificOutput: { hookEventName: "UserPromptSubmit", additionalContext: outcome.message } });
      return 0;
    }
    allow();
    return 0;
  }

  if (event === "PreToolUse") {
    const toolName = payload.tool_name ?? "";
    const input = payload.tool_input ?? {};

    // Reading a credentials file is a leak even when the file's contents would
    // pass every regex we have.
    const filePath = typeof input.file_path === "string" ? input.file_path : "";
    if (filePath && isSensitivePath(filePath)) {
      emit({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: `secretgate: ${filePath} holds credentials. Read the key names from a .env.example instead, or add an allowlist entry if this file is genuinely safe.`,
        },
      });
      return 0;
    }

    const command = typeof input.command === "string" ? input.command : "";
    if (command && isSensitiveCommand(command)) {
      emit({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: `secretgate: this command would print credentials to the transcript.\n  ${command.slice(0, 200)}`,
        },
      });
      return 0;
    }

    const text = extractToolText(toolName, input);
    if (!text) return allow(), 0;

    const outcome = guardOutbound(text, config);
    if (outcome.action === "deny") {
      emit({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "deny",
          permissionDecisionReason: outcome.message,
        },
      });
      return 0;
    }
    if (outcome.action === "modify" || outcome.message) {
      // No argument-rewrite channel here either, so surface it and let the
      // developer decide. Denying every redactable tool call would make the
      // agent unusable on any repo that has a .env.
      emit({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "ask",
          permissionDecisionReason: outcome.message,
        },
      });
      return 0;
    }
    allow();
    return 0;
  }

  if (event === "PostToolUse") {
    const text = stringifyResponse(payload.tool_response);
    if (!text) return allow(), 0;

    const { warnings, substituted } = guardInbound(text, config);
    if (warnings.length > 0) {
      emit({
        hookSpecificOutput: {
          hookEventName: "PostToolUse",
          additionalContext: warnings.join("\n"),
        },
      });
      return 0;
    }
    if (substituted > 0) {
      emit({
        hookSpecificOutput: {
          hookEventName: "PostToolUse",
          additionalContext: `secretgate restored ${substituted} real value(s) locally.`,
        },
      });
      return 0;
    }
    allow();
    return 0;
  }

  allow();
  return 0;
}
