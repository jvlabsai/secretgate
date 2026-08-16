import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { readHeartbeat, recordBeat, agentHealth, humanAge, clearHeartbeat } from "../src/core/heartbeat.js";
import { redactDeep } from "../src/hooks/mcp-proxy.js";
import { defaultConfig } from "../src/config/index.js";
import { resetVaultForTesting } from "../src/core/redact.js";
import { FAKE } from "./fixtures.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli", "index.ts");

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "secretgate-beat-"));
}

// --- heartbeat ------------------------------------------------------------

test("a beat records the agent, event, time and count", () => {
  const dir = tempDir();
  const path = join(dir, "last-seen.json");
  try {
    recordBeat("claude-code", "UserPromptSubmit", path);
    recordBeat("claude-code", "UserPromptSubmit", path);
    recordBeat("claude-code", "PreToolUse", path);

    const beat = readHeartbeat(path);
    assert.equal(beat.agents["claude-code"]!["UserPromptSubmit"]!.count, 2);
    assert.equal(beat.agents["claude-code"]!["PreToolUse"]!.count, 1);
    assert.ok(beat.agents["claude-code"]!["UserPromptSubmit"]!.at > 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the heartbeat records no content, only that something happened", () => {
  const dir = tempDir();
  const path = join(dir, "last-seen.json");
  try {
    recordBeat("claude-code", "UserPromptSubmit", path);
    const raw = readFileSync(path, "utf8");
    // Whatever else changes, this file must never become a place secrets land.
    assert.ok(!raw.includes(FAKE.awsKey));
    assert.deepEqual(Object.keys(JSON.parse(raw)).sort(), ["agents", "version"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("recording never throws, even on an unwritable path", () => {
  // A guardrail that crashes the agent because it could not write a timestamp
  // has its priorities backwards.
  assert.doesNotThrow(() => recordBeat("x", "y", join("/nonexistent-root-xyz", "a", "b.json")));
});

test("a missing or corrupt heartbeat reads as empty rather than throwing", () => {
  const dir = tempDir();
  try {
    assert.deepEqual(readHeartbeat(join(dir, "nope.json")).agents, {});
    const bad = join(dir, "bad.json");
    writeFileSync(bad, "{{{not json");
    assert.deepEqual(readHeartbeat(bad).agents, {});
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("agentHealth surfaces the most recent event first", () => {
  const beat = {
    version: 1 as const,
    agents: {
      "claude-code": {
        Old: { at: 1_000, count: 1 },
        New: { at: 9_000, count: 5 },
      },
    },
  };
  const [health] = agentHealth(beat);
  assert.ok(health);
  assert.equal(health.events[0]!.event, "New");
  assert.equal(health.lastSeen, 9_000);
});

test("ages read the way a human would say them", () => {
  const now = 1_000_000_000_000;
  assert.equal(humanAge(now - 5_000, now), "5s ago");
  assert.equal(humanAge(now - 4 * 60_000, now), "4m ago");
  assert.equal(humanAge(now - 3 * 3_600_000, now), "3h ago");
  assert.equal(humanAge(now - 5 * 86_400_000, now), "5d ago");
});

test("clearing removes the file", () => {
  const dir = tempDir();
  const path = join(dir, "last-seen.json");
  try {
    recordBeat("a", "b", path);
    assert.ok(existsSync(path));
    assert.equal(clearHeartbeat(path), true);
    assert.equal(clearHeartbeat(path), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a real hook invocation leaves a beat behind", () => {
  const home = tempDir();
  try {
    execFileSync(process.execPath, ["--import", "tsx", CLI, "hook", "claude-code"], {
      input: JSON.stringify({ hook_event_name: "UserPromptSubmit", prompt: "hello" }),
      encoding: "utf8",
      env: { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: "1" },
    });

    const beat = readHeartbeat(join(home, ".secretgate", "last-seen.json"));
    assert.ok(beat.agents["claude-code"]?.["UserPromptSubmit"], "the hook should have stamped the heartbeat");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

// --- mcp proxy ------------------------------------------------------------

test("redactDeep finds secrets at any depth in a JSON-RPC payload", () => {
  resetVaultForTesting();
  const config = { ...defaultConfig(), vault: { persist: false } };
  const counter = { n: 0 };

  const params = {
    name: "write_file",
    arguments: {
      path: "/app/.env",
      contents: `AWS_ACCESS_KEY_ID=${FAKE.awsKey}`,
      nested: { deeper: [{ token: FAKE.githubToken }] },
    },
  };

  const guarded = redactDeep(params, config, counter) as any;

  assert.equal(counter.n, 2, "both secrets, however deep, should be found");
  assert.ok(!JSON.stringify(guarded).includes(FAKE.awsKey));
  assert.ok(!JSON.stringify(guarded).includes(FAKE.githubToken));
  assert.match(guarded.arguments.contents, /SECRETGATE_AWS_KEY_/);
  assert.match(guarded.arguments.nested.deeper[0].token, /SECRETGATE_GITHUB_TOKEN_/);
  assert.equal(guarded.arguments.path, "/app/.env", "non-secret values pass through unchanged");
});

test("redactDeep leaves clean payloads byte-identical", () => {
  resetVaultForTesting();
  const config = { ...defaultConfig(), vault: { persist: false } };
  const counter = { n: 0 };
  const params = { name: "read_file", arguments: { path: "/app/README.md" } };

  assert.deepEqual(redactDeep(params, config, counter), params);
  assert.equal(counter.n, 0);
});

test("redactDeep does not recurse forever on a deeply nested payload", () => {
  resetVaultForTesting();
  const config = { ...defaultConfig(), vault: { persist: false } };
  let nested: any = FAKE.awsKey;
  for (let i = 0; i < 200; i++) nested = { down: nested };

  assert.doesNotThrow(() => redactDeep(nested, config, { n: 0 }));
});

test("the proxy relays a real JSON-RPC exchange and redacts on the way through", () => {
  // A minimal MCP-ish server: echoes back whatever params it is sent, which is
  // the shape that matters — a server returning file contents to the model.
  const echo = `
    const rl = require("node:readline").createInterface({ input: process.stdin });
    rl.on("line", (line) => {
      const msg = JSON.parse(line);
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { echoed: msg.params } }) + "\\n");
    });
  `;

  const home = tempDir();
  try {
    const request = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "write", arguments: { body: `key=${FAKE.awsKey}` } },
    });

    const result = spawnSync(
      process.execPath,
      ["--import", "tsx", CLI, "mcp-proxy", "--", process.execPath, "-e", echo],
      {
        input: `${request}\n`,
        encoding: "utf8",
        env: { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: "1" },
        timeout: 60_000,
      },
    );

    const stdout = result.stdout ?? "";
    assert.ok(stdout.includes("SECRETGATE_AWS_KEY_"), `expected a placeholder, got: ${stdout.slice(0, 300)}`);
    assert.ok(!stdout.includes(FAKE.awsKey), "the real key must never reach the server or come back");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
