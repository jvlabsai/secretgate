import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, existsSync, statSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir, platform } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Vault } from "../src/core/redact.js";
import { scan } from "../src/core/scan.js";
import { defaultConfig } from "../src/config/index.js";
import { loadStore, saveStore, emptyStore, clearStore, storeStatus } from "../src/core/vault-store.js";
import { FAKE } from "./fixtures.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli", "index.ts");
const config = defaultConfig();

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "secretgate-vault-"));
}

/**
 * The regression this whole file exists for.
 *
 * Every hook invocation is its own process — Claude Code runs the binary once
 * for UserPromptSubmit and again for PostToolUse. With an in-memory-only vault
 * the mapping was gone before the agent's edit came back, so redact mode could
 * remove a secret and never restore it. The unit tests missed it because they
 * called both halves inside one process.
 */
test("a secret redacted in one process is restored in another", () => {
  const dir = tempDir();
  const store = join(dir, "vault.json");
  try {
    const original = `AWS_ACCESS_KEY_ID=${FAKE.awsKey}\n`;

    const first = new Vault();
    first.attachStore(store);
    const { text: redacted } = first.redact(original, scan(original, config).findings);
    assert.ok(!redacted.includes(FAKE.awsKey));

    // A completely separate vault, as a new process would have.
    const second = new Vault();
    second.attachStore(store);
    const result = second.rehydrate(redacted);

    assert.equal(result.text, original, "the second process must restore the real value");
    assert.equal(result.substituted, 1);
    assert.deepEqual(result.warnings, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the same secret keeps the same placeholder across processes", () => {
  const dir = tempDir();
  const store = join(dir, "vault.json");
  try {
    const text = `key=${FAKE.awsKey}`;

    const first = new Vault();
    first.attachStore(store);
    const a = first.redact(text, scan(text, config).findings).replacements[0]!.placeholder;

    const second = new Vault();
    second.attachStore(store);
    const b = second.redact(text, scan(text, config).findings).replacements[0]!.placeholder;

    assert.equal(a, b, "a new placeholder each turn would confuse the model it is shown to");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("without a store, rehydration in a second process refuses rather than guessing", () => {
  const original = `key=${FAKE.awsKey}`;
  const first = new Vault();
  const { text: redacted } = first.redact(original, scan(original, config).findings);

  const second = new Vault(); // no store attached
  const result = second.rehydrate(redacted);

  assert.equal(result.substituted, 0);
  assert.ok(!result.text.includes(FAKE.awsKey));
  assert.equal(result.warnings[0]!.kind, "unknown");
});

test("the store file is not world readable", { skip: platform() === "win32" ? "POSIX modes only" : false }, () => {
  const dir = tempDir();
  const store = join(dir, "vault.json");
  try {
    saveStore(emptyStore("00".repeat(32)), store);
    const mode = statSync(store).mode & 0o777;
    assert.equal(mode, 0o600, `expected 0600, got ${mode.toString(8)}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("expired entries are dropped on load", () => {
  const dir = tempDir();
  const store = join(dir, "vault.json");
  try {
    const stale = emptyStore("00".repeat(32));
    stale.entries["SECRETGATE_AWS_KEY_ABCD"] = { secret: FAKE.awsKey, at: Date.now() - 48 * 60 * 60 * 1000 };
    stale.entries["SECRETGATE_AWS_KEY_BEEF"] = { secret: FAKE.awsKeyAlt, at: Date.now() };
    saveStore(stale, store);

    const loaded = loadStore(store);
    assert.ok(loaded);
    assert.equal(Object.keys(loaded.entries).length, 1, "the 48h-old entry should have expired");
    assert.ok(loaded.entries["SECRETGATE_AWS_KEY_BEEF"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a corrupt store starts fresh instead of throwing", () => {
  const dir = tempDir();
  const store = join(dir, "vault.json");
  try {
    writeFileSync(store, "{ not json at all");
    assert.equal(loadStore(store), null);

    const vault = new Vault();
    vault.attachStore(store); // must not throw
    assert.equal(vault.size, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("clearing removes the file", () => {
  const dir = tempDir();
  const store = join(dir, "vault.json");
  try {
    saveStore(emptyStore("00".repeat(32)), store);
    assert.ok(existsSync(store));
    assert.equal(clearStore(store), true);
    assert.ok(!existsSync(store));
    assert.equal(clearStore(store), false, "clearing twice is not an error");
    assert.equal(storeStatus(store).entries, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the store never contains a placeholder without its value, or vice versa", () => {
  const dir = tempDir();
  const store = join(dir, "vault.json");
  try {
    const text = `a=${FAKE.awsKey}\nb=${FAKE.githubToken}`;
    const vault = new Vault();
    vault.attachStore(store);
    vault.redact(text, scan(text, config).findings);

    const raw = JSON.parse(readFileSync(store, "utf8"));
    const entries = Object.entries(raw.entries as Record<string, { secret: string }>);
    assert.equal(entries.length, 2);
    for (const [placeholder, entry] of entries) {
      assert.match(placeholder, /^SECRETGATE_[A-Z0-9_]+$/);
      assert.ok(entry.secret.length > 0);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/** The real thing: two separate CLI invocations, as a user would run them. */
test("secretgate filter round-trips across two real processes", () => {
  const home = tempDir();
  const env = { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: "1" };
  try {
    const original = `AWS_ACCESS_KEY_ID=${FAKE.awsKey}\n`;

    const redacted = execFileSync(process.execPath, ["--import", "tsx", CLI, "filter"], {
      input: original,
      encoding: "utf8",
      env,
      stdio: ["pipe", "pipe", "ignore"],
    });
    assert.ok(!redacted.includes(FAKE.awsKey), "the agent must not see the secret");
    assert.match(redacted, /SECRETGATE_AWS_KEY_/);

    const restored = execFileSync(process.execPath, ["--import", "tsx", CLI, "filter", "--rehydrate"], {
      input: redacted,
      encoding: "utf8",
      env,
      stdio: ["pipe", "pipe", "ignore"],
    });
    assert.equal(restored, original, "a separate process must restore the real value");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
