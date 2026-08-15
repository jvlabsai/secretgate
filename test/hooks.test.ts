import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { guardOutbound, guardInbound, isSensitivePath, isSensitiveCommand, extractToolText } from "../src/hooks/shared.js";
import { defaultConfig } from "../src/config/index.js";
import { resetVaultForTesting } from "../src/core/redact.js";
import { FAKE } from "./fixtures.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli", "index.ts");
const AWS_KEY = FAKE.awsKey;

function runHook(payload: object): any {
  const out = execFileSync(process.execPath, ["--import", "tsx", CLI, "hook", "claude-code"], {
    input: JSON.stringify(payload),
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  });
  return JSON.parse(out || "{}");
}

test("a clean prompt passes straight through", () => {
  const response = runHook({ hook_event_name: "UserPromptSubmit", prompt: "how do I write a retry loop?" });
  assert.deepEqual(response, {});
});

test("a prompt carrying a credential is intercepted", () => {
  const response = runHook({
    hook_event_name: "UserPromptSubmit",
    prompt: `my key is ${AWS_KEY}, why does S3 return 403?`,
  });
  assert.equal(response.decision, "block");
  assert.ok(!JSON.stringify(response).includes(AWS_KEY), "the secret must not survive into the hook response");
  assert.match(JSON.stringify(response), /SECRETGATE_AWS_KEY_/);
});

test("reading a .env file is denied by path, not by content", () => {
  const response = runHook({
    hook_event_name: "PreToolUse",
    tool_name: "Read",
    tool_input: { file_path: "/home/dev/app/.env" },
  });
  assert.equal(response.hookSpecificOutput.permissionDecision, "deny");
});

test("a command that would print the environment is denied", () => {
  const response = runHook({
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "cat .env && npm start" },
  });
  assert.equal(response.hookSpecificOutput.permissionDecision, "deny");
});

test("an ordinary command is allowed", () => {
  const response = runHook({
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "npm run build" },
  });
  assert.deepEqual(response, {});
});

test("malformed payloads fail open rather than bricking the agent", () => {
  const out = execFileSync(process.execPath, ["--import", "tsx", CLI, "hook", "claude-code"], {
    input: "this is not json",
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  });
  assert.deepEqual(JSON.parse(out), {});
});

test("an unknown event is allowed through", () => {
  assert.deepEqual(runHook({ hook_event_name: "SomeFutureEvent", data: 1 }), {});
});

test("sensitive path detection covers the usual credential files", () => {
  for (const p of ["/app/.env", "/app/.env.production", "~/.npmrc", "~/.netrc", "/root/.ssh/id_rsa", "app/secrets.yaml", "/a/credentials"]) {
    assert.ok(isSensitivePath(p), p);
  }
  for (const p of ["/app/.env.example", "/app/src/index.ts", "/app/README.md"]) {
    assert.ok(!isSensitivePath(p), p);
  }
});

test("sensitive command detection covers the usual credential dumps", () => {
  for (const cmd of ["cat .env", "printenv", "env", "aws configure list", "gcloud auth print-access-token", "head -5 ~/.npmrc"]) {
    assert.ok(isSensitiveCommand(cmd), cmd);
  }
  for (const cmd of ["npm run build", "git status", "ls -la", "cat README.md"]) {
    assert.ok(!isSensitiveCommand(cmd), cmd);
  }
});

test("tool text extraction reaches every field an agent might use", () => {
  const text = extractToolText("Edit", { file_path: "a.ts", old_string: "before", new_string: `key=${AWS_KEY}` });
  assert.ok(text.includes(AWS_KEY));
});

test("block mode denies instead of redacting", () => {
  resetVaultForTesting();
  const config = { ...defaultConfig(), mode: "block" as const };
  const outcome = guardOutbound(`key=${AWS_KEY}`, config);
  assert.equal(outcome.action, "deny");
  assert.equal(outcome.text, `key=${AWS_KEY}`, "block mode leaves the text alone");
});

test("warn mode reports and changes nothing", () => {
  resetVaultForTesting();
  const config = { ...defaultConfig(), mode: "warn" as const };
  const outcome = guardOutbound(`key=${AWS_KEY}`, config);
  assert.equal(outcome.action, "allow");
  assert.equal(outcome.text, `key=${AWS_KEY}`);
  assert.match(outcome.message!, /warn/);
});

test("redact mode swaps the secret and can put it back", () => {
  resetVaultForTesting();
  const config = defaultConfig();
  const original = `key=${AWS_KEY}`;
  const outcome = guardOutbound(original, config);

  assert.equal(outcome.action, "modify");
  assert.ok(!outcome.text.includes(AWS_KEY));

  const back = guardInbound(outcome.text);
  assert.equal(back.text, original);
  assert.equal(back.substituted, 1);
  assert.deepEqual(back.warnings, []);
});

test("inbound text with no placeholders is untouched", () => {
  resetVaultForTesting();
  const text = "const x = 1;\n";
  assert.equal(guardInbound(text).text, text);
});
