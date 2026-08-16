/**
 * Claude Code hook adapter.
 *
 *   UserPromptSubmit  the developer's prompt, before the model sees it
 *   PreToolUse        tool arguments, before the tool runs
 *   PostToolUse       tool results, before anything lands on disk
 *
 * The contract itself lives in claude-compat.ts, because Gemini CLI adopted the
 * same one and two copies would drift apart.
 *
 * Capability is "redact" even though Claude Code has no tool-input override:
 * the prompt path can still hand back redacted text, and PostToolUse restores
 * real values on the way back in. The pre-tool path asks the developer instead
 * of rewriting, which is why supportsInputOverride is false.
 */
import { runClaudeCompatibleHook } from "./claude-compat.js";

export function runClaudeCodeHook(): Promise<number> {
  return runClaudeCompatibleHook({
    agentId: "claude-code",
    capability: "redact",
    supportsInputOverride: false,
    events: {
      prompt: "UserPromptSubmit",
      preTool: "PreToolUse",
      postTool: "PostToolUse",
    },
  });
}
