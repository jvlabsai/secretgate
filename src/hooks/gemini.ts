/**
 * Gemini CLI hook adapter.
 *
 * Gemini adopted the Claude Code hook contract — JSON on stdin, exit 2 blocks,
 * and BeforeTool may hand back an overridden tool_input — so this is a thin
 * variant rather than a second implementation. All of the payload handling is
 * shared with claude-code.ts through claude-compat.ts.
 *
 *   BeforeTool  tool arguments, before the tool runs
 *   AfterTool   tool results, before anything lands on disk
 *
 * Capability is "redact", and unlike Claude Code this host genuinely accepts
 * rewritten arguments, so a tool call carrying a credential can proceed with a
 * placeholder instead of being refused.
 *
 * Config lives at ~/.gemini/settings.json globally and .gemini/settings.json
 * per workspace, with the workspace file taking precedence.
 */
import { runClaudeCompatibleHook } from "./claude-compat.js";

export function runGeminiHook(): Promise<number> {
  return runClaudeCompatibleHook({
    agentId: "gemini",
    capability: "redact",
    supportsInputOverride: true,
    events: {
      preTool: "BeforeTool",
      postTool: "AfterTool",
    },
  });
}
