import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { isSecretStore, gitIgnoreStatus, assessStore } from "../src/cli/secret-store.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "cli", "index.ts");

function repo(): string {
  const dir = mkdtempSync(join(tmpdir(), "secretgate-store-"));
  execFileSync("git", ["init", "-q"], { cwd: dir });
  return dir;
}

test("secret stores are recognised, templates are not", () => {
  for (const p of ["/a/.env", "/a/.env.local", "/a/.env.production", "/a/.npmrc", "/a/.netrc", "/a/.pypirc"]) {
    assert.ok(isSecretStore(p), p);
  }
  // These are templates. They hold key names, not values, and treating them as
  // secret stores would tell people to gitignore a file meant to be committed.
  for (const p of ["/a/.env.example", "/a/.env.sample", "/a/.env.template", "/a/src/index.ts", "/a/config.json"]) {
    assert.ok(!isSecretStore(p), p);
  }
});

test("git decides what is ignored, not us", () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, ".gitignore"), ".env*\n!.env.example\n");
    writeFileSync(join(dir, ".env"), "A=1\n");
    writeFileSync(join(dir, ".env.example"), "A=\n");

    assert.equal(gitIgnoreStatus(join(dir, ".env")), "ignored");
    // The negation is exactly the kind of rule a hand-rolled parser gets wrong,
    // which is why this asks git.
    assert.equal(gitIgnoreStatus(join(dir, ".env.example")), "not-ignored");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a file outside any repository is reported as such, not as exposed", () => {
  const dir = mkdtempSync(join(tmpdir(), "secretgate-norepo-"));
  try {
    writeFileSync(join(dir, ".env"), "A=1\n");
    const verdict = assessStore(join(dir, ".env"), 1);
    assert.equal(verdict.status, "no-repo");
    assert.equal(verdict.exposed, false, "no repo means nothing is about to be committed");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

/**
 * The behaviour this file exists for. Telling someone their .env contains
 * credentials is true and useless — that is the file's job. Before this, an
 * ignored .env and one about to be committed produced identical output, so the
 * one case that actually matters was invisible.
 */
function scan(dir: string, target: string): { stdout: string; code: number } {
  try {
    // Absolute target, and cwd left alone: running from the temp dir would
    // break tsx's own module resolution.
    const stdout = execFileSync(process.execPath, ["--import", "tsx", CLI, "scan", join(dir, target)], {
      encoding: "utf8",
      env: { ...process.env, NO_COLOR: "1" },
    });
    return { stdout, code: 0 };
  } catch (err) {
    const e = err as { stdout?: string; status?: number };
    return { stdout: e.stdout ?? "", code: e.status ?? 1 };
  }
}

test("an ignored .env is reported as fine and exits zero", () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, ".gitignore"), ".env*\n");
    writeFileSync(join(dir, ".env.local"), "API_KEY=Xk9mQ2pL7vN4wR8tY3zB6cF1dG5hJ0sA\n");

    const { stdout, code } = scan(dir, ".env.local");
    assert.match(stdout, /ignored by git/);
    assert.match(stdout, /Nothing to do/);
    assert.equal(code, 0, "a correctly ignored secrets file is not a problem");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an unignored .env is called out loudly and exits non-zero", () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, ".gitignore"), "node_modules\n");
    writeFileSync(join(dir, ".env.local"), "API_KEY=Xk9mQ2pL7vN4wR8tY3zB6cF1dG5hJ0sA\n");

    const { stdout, code } = scan(dir, ".env.local");
    assert.match(stdout, /EXPOSED/);
    assert.match(stdout, /NOT ignored by git/);
    assert.match(stdout, /gitignore/, "must say what to actually do");
    assert.match(stdout, /rotated/, "must warn that removal does not undo a commit");
    assert.equal(code, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a .env is never suggested for fix, pragma or baseline", () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, ".gitignore"), ".env*\n");
    writeFileSync(join(dir, ".env"), "API_KEY=Xk9mQ2pL7vN4wR8tY3zB6cF1dG5hJ0sA\n");

    const { stdout } = scan(dir, ".env");
    // All three were the old advice, and all three are wrong for a secrets file.
    assert.ok(!stdout.includes("secretgate fix"), "moving a .env into a .env is nonsense");
    assert.ok(!stdout.includes("secretgate:allow"), "suppressing your own secrets file is nonsense");
    assert.ok(!stdout.includes("secretgate baseline"), "baselining a secrets file is nonsense");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("hardcoded secrets in source are still reported normally", () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, ".gitignore"), ".env*\n");
    writeFileSync(join(dir, "config.ts"), 'const k = "AKIA4KTNQ7VZL2WXMP3D";\n');

    const { stdout, code } = scan(dir, "config.ts");
    assert.match(stdout, /aws-access-key-id/);
    assert.match(stdout, /secretgate fix/, "source files should still get the fix suggestion");
    assert.equal(code, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
