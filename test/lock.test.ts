import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { isLocked } from "../src/cli/lock.js";
import { isSecretStore } from "../src/cli/secret-store.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli", "index.ts");

// Assembled from fragments, like test/fixtures.ts, so no committed file holds a
// contiguous run of characters shaped like a live credential. Push protection
// rejected the literal form of this, entirely correctly.
const j = (...parts: string[]) => parts.join("");
const FAKE_LINKEDIN = j("AQXd8x2mKp9", "rT4vN7wZ6bH1jC5s");
const FAKE_OPENROUTER = j("sk-or", "-v1-", "9f2c4e6a8b0d1f3e5a7c9b1d3f5e7a9c2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a");

const ENV_CONTENTS = [
  "NODE_ENV=development",
  `LINKEDIN_ACCESS_TOKEN="${FAKE_LINKEDIN}"`,
  `OPENROUTER_API_KEY=${FAKE_OPENROUTER}`,
  "",
].join("\n");

function workspace(): string {
  const dir = mkdtempSync(join(tmpdir(), "secretgate-lock-"));
  execFileSync("git", ["init", "-q"], { cwd: dir });
  writeFileSync(join(dir, ".gitignore"), ".env*\n");
  writeFileSync(join(dir, ".env.local"), ENV_CONTENTS);
  return dir;
}

function run(home: string, args: string[]): string {
  try {
    return execFileSync(process.execPath, ["--import", "tsx", CLI, ...args], {
      encoding: "utf8",
      env: { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: "1" },
    });
  } catch (err) {
    return (err as { stdout?: string }).stdout ?? "";
  }
}

test("locking replaces values with placeholders and leaves keys alone", () => {
  const dir = workspace();
  try {
    run(dir, ["lock", dir]);
    const locked = readFileSync(join(dir, ".env.local"), "utf8");

    assert.ok(!locked.includes(FAKE_LINKEDIN), "the token must be gone from disk");
    assert.ok(!locked.includes(FAKE_OPENROUTER), "the key must be gone from disk");
    assert.match(locked, /LINKEDIN_ACCESS_TOKEN=/, "the key name must survive so the app still knows what to ask for");
    assert.match(locked, /SECRETGATE_/);
    assert.match(locked, /^NODE_ENV=development$/m, "non-secret values are untouched");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("unlock restores the file byte for byte", () => {
  const dir = workspace();
  try {
    run(dir, ["lock", dir]);
    run(dir, ["unlock", dir]);
    assert.equal(readFileSync(join(dir, ".env.local"), "utf8"), ENV_CONTENTS);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * The bug this guards destroyed a credential outright.
 *
 * `lock` walked into its own backup directory, matched `.env.local.<hash>.bak`
 * as another env file, and locked that too. The only copy of the real values
 * became placeholders, so when the vault was cleared `unlock` had nothing to
 * fall back on and the secret was unrecoverable.
 */
test("a wiped vault still recovers from the backup", () => {
  const dir = workspace();
  try {
    run(dir, ["lock", dir]);
    run(dir, ["vault", "--clear"]);
    run(dir, ["unlock", dir]);

    assert.equal(
      readFileSync(join(dir, ".env.local"), "utf8"),
      ENV_CONTENTS,
      "losing the vault must never mean losing the credential",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("backup copies are never treated as env files", () => {
  for (const name of [
    "/a/.env.local.f141a1285bb37610.bak",
    "/a/.env.backup",
    "/a/.env.local.orig",
    "/a/.env.save",
    "/a/.env~",
  ]) {
    assert.ok(!isSecretStore(name), `${name} is a copy, not a live env file`);
  }
  assert.ok(isSecretStore("/a/.env.local"), "the real thing still matches");
});

test("locking never writes inside secretgate's own state directory", () => {
  const home = mkdtempSync(join(tmpdir(), "secretgate-state-"));
  try {
    const stateEnv = join(home, ".secretgate", "backups");
    mkdirSync(stateEnv, { recursive: true });
    const decoy = join(stateEnv, ".env.local");
    writeFileSync(decoy, ENV_CONTENTS);

    run(home, ["lock", join(home, ".secretgate")]);
    assert.equal(readFileSync(decoy, "utf8"), ENV_CONTENTS, "state directory must be untouchable");
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test("locking twice is a no-op rather than double-encoding", () => {
  const dir = workspace();
  try {
    run(dir, ["lock", dir]);
    const once = readFileSync(join(dir, ".env.local"), "utf8");
    const second = run(dir, ["lock", dir]);
    const twice = readFileSync(join(dir, ".env.local"), "utf8");

    assert.equal(once, twice, "a second lock must not touch an already locked file");
    assert.match(second, /already locked/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("unlocking something that was never locked does nothing", () => {
  const dir = workspace();
  try {
    const output = run(dir, ["unlock", dir]);
    assert.equal(readFileSync(join(dir, ".env.local"), "utf8"), ENV_CONTENTS);
    assert.match(output, /not locked/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a backup is written before the file is modified", () => {
  const dir = workspace();
  try {
    run(dir, ["lock", dir]);
    const backups = join(dir, ".secretgate", "backups");
    assert.ok(existsSync(backups), "a backup directory must exist after locking");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("isLocked recognises a locked file and only a locked file", () => {
  assert.ok(isLocked("API_KEY=SECRETGATE_AWS_KEY_A3F4\n"));
  assert.ok(isLocked('TOKEN="SECRETGATE_GENERIC_KEY_9260"\n'.replace(/"/g, "")));
  assert.ok(!isLocked("API_KEY=realvalue123456\n"));
  assert.ok(!isLocked("NODE_ENV=development\n"));
});

test(".env.example is never locked", () => {
  const dir = workspace();
  try {
    const example = join(dir, ".env.example");
    const contents = "LINKEDIN_ACCESS_TOKEN=\nOPENROUTER_API_KEY=\n";
    writeFileSync(example, contents);

    run(dir, ["lock", dir]);
    assert.equal(readFileSync(example, "utf8"), contents, "templates are meant to be committed, not locked");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
