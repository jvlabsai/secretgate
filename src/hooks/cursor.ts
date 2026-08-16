/**
 * Cursor hook adapter.
 *
 * Cursor's hook surface has moved more than once, so everything here is read
 * defensively and anything unrecognised is allowed through. The heartbeat is
 * what makes that acceptable: if Cursor renames an event and this adapter stops
 * being called, `secretgate doctor` reports "has never fired" instead of
 * quietly implying you are covered.
 *
 * Events used:
 *   beforeSubmitPrompt      the prompt, before the model sees it
 *   beforeShellExecution    a command, before it runs
 *   beforeReadFile          a file, before its contents are read into context
 *   afterFileEdit           an edit, after the model produced it
 *
 * Responses follow Cursor's permission shape: { permission: allow | deny | ask }.
 */
import { loadConfig } from "../config/index.js";
import { recordBeat } from "../core/heartbeat.js";
import { guardOutbound, guardInbound, isSensitivePath, isSensitiveCommand, readStdin } from "./shared.js";

interface CursorPayload {
  hook_event_name?: string;
  hookEventName?: string;
  prompt?: string;
  command?: string;
  file_path?: string;
  filePath?: string;
  content?: string;
  edits?: unknown;
  workspace_roots?: string[];
  cwd?: string;
}

function emit(response: object): void {
  process.stdout.write(`${JSON.stringify(response)}\n`);
}

function allow(): void {
  emit({ permission: "allow" });
}

export async function runCursorHook(): Promise<number> {
  const raw = await readStdin();

  let payload: CursorPayload;
  try {
    payload = JSON.parse(raw) as CursorPayload;
  } catch {
    allow();
    return 0;
  }

  const event = payload.hook_event_name ?? payload.hookEventName ?? "";
  recordBeat("cursor", event || "unknown");

  const cwd = payload.cwd ?? payload.workspace_roots?.[0] ?? process.cwd();
  const config = loadConfig(cwd);
  const filePath = payload.file_path ?? payload.filePath ?? "";

  switch (event) {
    case "beforeSubmitPrompt": {
      const prompt = payload.prompt ?? "";
      if (!prompt) break;

      const outcome = guardOutbound(prompt, config);
      if (outcome.action === "deny") {
        emit({ permission: "deny", userMessage: outcome.message, agentMessage: outcome.message });
        return 0;
      }
      if (outcome.action === "modify") {
        // Cursor has no prompt-rewrite channel either, so the redacted text is
        // handed back in the message and the original is stopped.
        emit({
          permission: "deny",
          userMessage: `${outcome.message}\n\nRedacted prompt — send this instead:\n\n${outcome.text}`,
          agentMessage: outcome.text,
        });
        return 0;
      }
      break;
    }

    case "beforeShellExecution": {
      const command = payload.command ?? "";
      if (command && isSensitiveCommand(command)) {
        emit({
          permission: "deny",
          userMessage: `secretgate: this command would print credentials into the transcript.\n  ${command.slice(0, 200)}`,
        });
        return 0;
      }
      if (command) {
        const outcome = guardOutbound(command, config);
        if (outcome.action === "deny") {
          emit({ permission: "deny", userMessage: outcome.message });
          return 0;
        }
        if (outcome.action === "modify") {
          emit({ permission: "ask", userMessage: outcome.message });
          return 0;
        }
      }
      break;
    }

    case "beforeReadFile": {
      if (filePath && isSensitivePath(filePath)) {
        emit({
          permission: "deny",
          userMessage: `secretgate: ${filePath} holds credentials. Read the key names from a .env.example instead.`,
        });
        return 0;
      }
      break;
    }

    case "afterFileEdit": {
      // Inbound: restore real values before the edit is written out.
      const text = typeof payload.content === "string" ? payload.content : "";
      if (text) {
        const { warnings } = guardInbound(text, config);
        if (warnings.length > 0) {
          emit({ permission: "ask", userMessage: warnings.join("\n") });
          return 0;
        }
      }
      break;
    }

    default:
      break;
  }

  allow();
  return 0;
}
