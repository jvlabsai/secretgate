import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { decideToolUse, decidePrompt } from "../src/hooks/decide.js";
import { defaultConfig } from "../src/config/index.js";
import { resetVaultForTesting } from "../src/core/redact.js";
import { readHeartbeat } from "../src/core/heartbeat.js";
import { detectAgents } from "../src/cli/install.js";
import { FAKE } from "./fixtures.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli", "index.ts");
const config = defaultConfig();

interface Run {
  stdout: string;
  code: number;
  home: string;
}

function hook(agent: string, payload: object): Run {
  const home = mkdtempSync(join(tmpdir(), "secretgate-adapter-"));
  const env = { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: "1" };
  try {
    const stdout = execFileSync(process.execPath, ["--import", "tsx", CLI, "hook", agent], {
      input: JSON.stringify(payload),
      encoding: "utf8",
      env,
    });
    return { stdout, code: 0, home };
  } catch (err) {
    const e = err as { stdout?: string; status?: number };
    return { stdout: e.stdout ?? "", code: e.status ?? 1, home };
  }
}

function cleanup(run: Run): void {
  rmSync(run.home, { recursive: true, force: true });
}

const AGENTS = ["claude-code", "cursor", "gemini", "antigravity", "copilot", "windsurf", "codex"];

// --- shared contract ------------------------------------------------------

test("every adapter fails open on a malformed payload", () => {
  // These hook APIs are young and move. An adapter that dies on an unexpected
  // schema takes the agent down with it, and gets uninstalled that same day.
  for (const agent of AGENTS) {
    const home = mkdtempSync(join(tmpdir(), "secretgate-open-"));
    try {
      const out = execFileSync(process.execPath, ["--import", "tsx", CLI, "hook", agent], {
        input: "this is not json",
        encoding: "utf8",
        env: { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: "1" },
      });
      assert.doesNotThrow(() => JSON.parse(out), `${agent} must emit valid JSON`);
      assert.ok(!/deny|block/i.test(out), `${agent} must not block on an unparseable payload`);
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }
});

test("every adapter records a heartbeat when it runs", () => {
  // The heartbeat is what makes failing open survivable: doctor can say the
  // hook stopped firing instead of the user assuming it still is.
  const events: Record<string, object> = {
    "claude-code": { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } },
    cursor: { hook_event_name: "beforeShellExecution", command: "ls" },
    gemini: { hook_event_name: "BeforeTool", tool_name: "Bash", tool_input: { command: "ls" } },
    antigravity: { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "ls" } },
    copilot: { event: "preToolUse", tool: "Bash", input: { command: "ls" } },
    windsurf: { hook_event_name: "pre_run_command", command: "ls" },
    codex: { hook_event_name: "PreToolUse", command: "ls" },
  };

  for (const [agent, payload] of Object.entries(events)) {
    const run = hook(agent, payload);
    try {
      const beat = readHeartbeat(join(run.home, ".secretgate", "last-seen.json"));
      assert.ok(beat.agents[agent], `${agent} did not record a heartbeat`);
    } finally {
      cleanup(run);
    }
  }
});

test("every adapter denies a read of .env", () => {
  const cases: [string, object][] = [
    ["claude-code", { hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: "/app/.env" } }],
    ["cursor", { hook_event_name: "beforeReadFile", file_path: "/app/.env" }],
    ["gemini", { hook_event_name: "BeforeTool", tool_name: "read_file", tool_input: { file_path: "/app/.env" } }],
    ["antigravity", { hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: "/app/.env" } }],
    ["copilot", { event: "preToolUse", tool: "read", input: { path: "/app/.env" } }],
    ["windsurf", { hook_event_name: "pre_read_code", file_path: "/app/.env" }],
  ];

  for (const [agent, payload] of cases) {
    const run = hook(agent, payload);
    try {
      assert.match(run.stdout, /deny|block/i, `${agent} allowed a read of .env:\n${run.stdout}`);
    } finally {
      cleanup(run);
    }
  }
});

test("every adapter denies a command that would dump credentials", () => {
  const cases: [string, object][] = [
    ["claude-code", { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "cat .env" } }],
    ["cursor", { hook_event_name: "beforeShellExecution", command: "cat .env" }],
    ["gemini", { hook_event_name: "BeforeTool", tool_name: "run_shell_command", tool_input: { command: "printenv" } }],
    ["antigravity", { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "cat .env" } }],
    ["copilot", { event: "preToolUse", tool: "shell", input: { command: "cat .env" } }],
    ["windsurf", { hook_event_name: "pre_run_command", command: "cat .env" }],
    ["codex", { hook_event_name: "PreToolUse", command: "cat .env" }],
  ];

  for (const [agent, payload] of cases) {
    const run = hook(agent, payload);
    try {
      assert.match(run.stdout, /deny|block/i, `${agent} allowed a credential dump:\n${run.stdout}`);
    } finally {
      cleanup(run);
    }
  }
});

test("every adapter allows ordinary work", () => {
  const cases: [string, object][] = [
    ["claude-code", { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "npm run build" } }],
    ["cursor", { hook_event_name: "beforeShellExecution", command: "npm run build" }],
    ["gemini", { hook_event_name: "BeforeTool", tool_name: "run_shell_command", tool_input: { command: "npm test" } }],
    ["antigravity", { hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "git status" } }],
    ["copilot", { event: "preToolUse", tool: "shell", input: { command: "ls -la" } }],
    ["windsurf", { hook_event_name: "pre_run_command", command: "npm test" }],
    ["codex", { hook_event_name: "PreToolUse", command: "npm test" }],
  ];

  for (const [agent, payload] of cases) {
    const run = hook(agent, payload);
    try {
      assert.ok(!/deny|"block"/i.test(run.stdout), `${agent} blocked ordinary work:\n${run.stdout}`);
      assert.equal(run.code, 0, `${agent} should exit 0 on allow`);
    } finally {
      cleanup(run);
    }
  }
});

// --- capability, the part that must not be got wrong -----------------------

/**
 * The distinction this whole capability field exists to protect.
 *
 * On a host that cannot accept rewritten tool input there is no mechanism to
 * redact anything. If such an adapter reported a redaction, a user would paste
 * a .env expecting it to be handled, and it would not be.
 */
test("a block-only host turns a redactable finding into a refusal", () => {
  resetVaultForTesting();
  const input = { command: `curl -H "Authorization: Bearer ${FAKE.githubToken}" https://api.example.com` };

  const redact = decideToolUse("Bash", input, config, "redact");
  assert.equal(redact.kind, "modify", "a redact-capable host should redact");

  for (const capability of ["block", "partial"] as const) {
    const decision = decideToolUse("Bash", input, config, capability);
    assert.equal(decision.kind, "deny", `${capability} must refuse rather than claim to redact`);
    assert.match(decision.reason, /cannot accept rewritten tool input/);
    assert.match(decision.reason, /secretgate lock/, "must point at the thing that does work");
  }
});

test("the same downgrade applies to prompts", () => {
  resetVaultForTesting();
  const prompt = `my key is ${FAKE.awsKey}`;
  assert.equal(decidePrompt(prompt, config, "redact").kind, "modify");
  assert.equal(decidePrompt(prompt, config, "block").kind, "deny");
});

test("gemini takes a rewritten tool_input; claude code asks instead", () => {
  resetVaultForTesting();
  const payload = {
    hook_event_name: "BeforeTool",
    tool_name: "run_shell_command",
    tool_input: { command: `echo ${FAKE.awsKey}` },
  };

  const gemini = hook("gemini", payload);
  try {
    // Gemini's BeforeTool can override arguments, so the call proceeds with a
    // placeholder rather than being refused.
    assert.match(gemini.stdout, /updatedInput/, `expected an input override:\n${gemini.stdout}`);
    assert.ok(!gemini.stdout.includes(FAKE.awsKey), "the real key must not survive into the response");
    assert.match(gemini.stdout, /SECRETGATE_AWS_KEY_/);
  } finally {
    cleanup(gemini);
  }

  const claude = hook("claude-code", {
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: `echo ${FAKE.awsKey}` },
  });
  try {
    assert.ok(!claude.stdout.includes("updatedInput"), "claude code has no override channel");
    assert.match(claude.stdout, /ask|deny/);
  } finally {
    cleanup(claude);
  }
});

test("windsurf never emits a redaction, only a refusal", () => {
  resetVaultForTesting();
  const run = hook("windsurf", { hook_event_name: "pre_run_command", command: `echo ${FAKE.awsKey}` });
  try {
    assert.ok(!run.stdout.includes("SECRETGATE_"), "block-only hosts must not imply a placeholder was substituted");
    assert.ok(!run.stdout.includes(FAKE.awsKey), "and must not echo the credential either");
    assert.match(run.stdout, /deny/);
  } finally {
    cleanup(run);
  }
});

test("codex only sees Bash, and says so through its capability", () => {
  const agents = detectAgents();
  const codex = agents.find((a) => a.id === "codex");
  assert.ok(codex);
  assert.equal(codex.capability, "partial", "coverage has real gaps and must be declared");
  assert.match(codex.note ?? "", /codex_hooks/, "the feature flag must be surfaced");
  assert.match(codex.note ?? "", /Bash/, "the Bash-only limit must be surfaced");

  // A file read never reaches this adapter, so it must not pretend to judge one.
  const run = hook("codex", { hook_event_name: "PreToolUse", tool_name: "Read", tool_input: { file_path: "/app/.env" } });
  try {
    assert.ok(!/deny|block/i.test(run.stdout), "codex has no file-read event to act on");
  } finally {
    cleanup(run);
  }
});

test("declared capabilities match what each adapter can actually do", () => {
  const byId = Object.fromEntries(detectAgents().map((a) => [a.id, a.capability]));
  assert.equal(byId["claude-code"], "redact");
  assert.equal(byId["cursor"], "redact");
  assert.equal(byId["gemini"], "redact");
  assert.equal(byId["antigravity"], "redact");
  assert.equal(byId["copilot"], "redact");
  assert.equal(byId["windsurf"], "block");
  assert.equal(byId["codex"], "partial");
  // Aider has no hook system at all, so it is lock-only and must not be
  // listed as something init can wire.
  assert.equal(byId["aider"], "none");
});

test("aider is never reported as installable", () => {
  const aider = detectAgents().find((a) => a.id === "aider");
  assert.ok(aider);
  assert.equal(aider.supported, false);
  assert.match(aider.note ?? "", /lock/, "must point the user at the thing that does work");
});
