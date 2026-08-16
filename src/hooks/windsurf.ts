/**
 * Windsurf hook adapter.
 *
 *   pre_read_code      before a file is read into context
 *   pre_run_command    before a shell command runs
 *
 * CAPABILITY: BLOCK ONLY.
 *
 * Windsurf's hooks answer a yes/no question. There is no channel to hand back
 * modified input and no post-tool event, so nothing here can redact anything
 * and nothing can be restored afterwards. A finding that would be redacted on
 * Claude Code becomes a refusal here — `decide.ts` enforces that downgrade so
 * this adapter cannot accidentally imply otherwise.
 *
 * This matters more than it sounds. A user who believes values are being
 * swapped and restored will paste a .env into a prompt expecting it to be
 * handled. On Windsurf it will not be. `doctor` prints the capability next to
 * the firing status for exactly this reason, and `secretgate lock` is the right
 * answer for anyone who wants redaction here.
 */
import { loadConfig } from "../config/index.js";
import { recordBeat } from "../core/heartbeat.js";
import { readStdin } from "./shared.js";
import { decideToolUse } from "./decide.js";

interface WindsurfPayload {
  hook_event_name?: string;
  event?: string;
  file_path?: string;
  path?: string;
  command?: string;
  cwd?: string;
  workspace?: string;
}

function emit(response: object): void {
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

const ALLOW = { permission: "allow" } as const;

export async function runWindsurfHook(): Promise<number> {
  const raw = await readStdin();

  let payload: WindsurfPayload;
  try {
    payload = JSON.parse(raw) as WindsurfPayload;
  } catch {
    emit(ALLOW);
    return 0;
  }

  const event = payload.hook_event_name ?? payload.event ?? "";
  const config = loadConfig(payload.cwd ?? payload.workspace ?? process.cwd());

  recordBeat("windsurf", event || "unknown");

  if (event === "pre_read_code") {
    const filePath = payload.file_path ?? payload.path ?? "";
    // "block" capability: any redactable finding is downgraded to a refusal.
    const decision = decideToolUse("Read", { file_path: filePath }, config, "block");
    if (decision.kind === "deny") {
      emit({ permission: "deny", reason: decision.reason });
      return 2;
    }
    emit(ALLOW);
    return 0;
  }

  if (event === "pre_run_command") {
    const command = payload.command ?? "";
    const decision = decideToolUse("Bash", { command }, config, "block");
    if (decision.kind === "deny") {
      emit({ permission: "deny", reason: decision.reason });
      return 2;
    }
    emit(ALLOW);
    return 0;
  }

  emit(ALLOW);
  return 0;
}
