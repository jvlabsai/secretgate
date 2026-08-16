import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { planFix, applyEnvFiles, deriveEnvName } from "../src/cli/fix.js";
import { defaultConfig } from "../src/config/index.js";
import { scan, blocking } from "../src/core/scan.js";
import { FAKE } from "./fixtures.js";

const config = defaultConfig();

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "secretgate-fix-"));
}

test("a hardcoded key becomes a process.env lookup", () => {
  const source = `const client = new S3({\n  accessKeyId: "${FAKE.awsKey}",\n});\n`;
  const plan = planFix("/app/src/s3.ts", source, config);

  assert.equal(plan.language, "js");
  assert.equal(plan.edits.length, 1);
  assert.equal(plan.edits[0]!.name, "ACCESS_KEY_ID");
  assert.equal(plan.edits[0]!.value, FAKE.awsKey);
  assert.match(plan.updated, /accessKeyId: process\.env\.ACCESS_KEY_ID,/);
  assert.ok(!plan.updated.includes(FAKE.awsKey), "the literal must be gone from the source");
});

test("the quotes go with the value, not around the lookup", () => {
  const source = `const k = "${FAKE.awsKey}";\n`;
  const plan = planFix("/app/a.js", source, config);
  assert.match(plan.updated, /const k = process\.env\.[A-Z_]+;/);
  assert.ok(!plan.updated.includes('"process.env'), "must not leave a quoted lookup");
});

test("each language gets its own idiom", () => {
  const cases: [string, RegExp][] = [
    ["/a/x.py", /os\.environ\["[A-Z_]+"\]/],
    ["/a/x.rb", /ENV\["[A-Z_]+"\]/],
    ["/a/x.go", /os\.Getenv\("[A-Z_]+"\)/],
    ["/a/x.php", /getenv\("[A-Z_]+"\)/],
  ];
  for (const [path, expected] of cases) {
    const plan = planFix(path, `key = "${FAKE.awsKey}"\n`, config);
    assert.match(plan.updated, expected, path);
  }
});

test("an unsupported file type is left completely alone", () => {
  const source = `key = ${FAKE.awsKey}\n`;
  const plan = planFix("/a/notes.txt", source, config);
  assert.equal(plan.edits.length, 0);
  assert.equal(plan.updated, source);
  assert.equal(plan.skipped, "unsupported file type");
});

test("a file with no secrets is untouched", () => {
  const source = "const x = 1;\nconst y = 2;\n";
  const plan = planFix("/a/x.ts", source, config);
  assert.equal(plan.edits.length, 0);
  assert.equal(plan.updated, source);
});

test("multiple secrets in one file all move, and offsets stay correct", () => {
  const source =
    `const aws = "${FAKE.awsKey}";\n` +
    `const gh  = "${FAKE.githubToken}";\n` +
    `const databaseUrl = "postgres://svc:h4Kd9wQz2Lp8Nx7@db.internal:5432/orders";\n`;

  const plan = planFix("/a/config.ts", source, config);
  assert.equal(plan.edits.length, 3);
  assert.ok(!plan.updated.includes(FAKE.awsKey));
  assert.ok(!plan.updated.includes(FAKE.githubToken));
  assert.ok(!plan.updated.includes("h4Kd9wQz2Lp8Nx7"));
});

/**
 * The bug this guards is the nastiest one available to this command: swapping
 * only the matched span inside a connection string yields
 * `"postgres://svc:process.env.X@host/db"`, which still compiles, still looks
 * plausible in a diff, and silently never resolves the variable.
 */
test("a secret inside a larger literal moves the whole literal", () => {
  const source = `const databaseUrl = "postgres://svc:h4Kd9wQz2Lp8Nx7@db.internal:5432/orders";\n`;
  const plan = planFix("/a/db.ts", source, config);

  assert.equal(plan.edits.length, 1);
  assert.equal(plan.edits[0]!.name, "DATABASE_URL", "the name comes from the assignment, not the URI userinfo");
  assert.equal(
    plan.edits[0]!.value,
    "postgres://svc:h4Kd9wQz2Lp8Nx7@db.internal:5432/orders",
    "the whole URI goes into .env, not just the password",
  );
  assert.equal(plan.updated, "const databaseUrl = process.env.DATABASE_URL;\n");
  assert.ok(!/process\.env\.\w+@/.test(plan.updated), "must never leave a lookup embedded in a string");
});

test("a template literal with interpolation is left alone rather than broken", () => {
  const source = "const url = `postgres://svc:h4Kd9wQz2Lp8Nx7@${host}:5432/orders`;\n";
  const plan = planFix("/a/db.ts", source, config);

  assert.equal(plan.edits.length, 0);
  assert.equal(plan.updated, source, "moving this would silently drop ${host}");
  assert.match(plan.manual[0]!.reason, /interpolation/);
});

test("a secret that is not in a string literal is reported, not guessed at", () => {
  const source = `key = ${FAKE.awsKey}\n`;
  const plan = planFix("/a/x.py", source, config);
  assert.equal(plan.edits.length, 0);
  assert.equal(plan.updated, source);
  assert.match(plan.manual[0]!.reason, /not inside a string literal/);
});

test("names are derived from the identifier the developer already used", () => {
  const taken = new Set<string>();
  const source = `const stripeSecretKey = "${FAKE.awsKey}"`;
  const [finding] = blocking(scan(source, config).findings, config);
  assert.ok(finding);
  assert.equal(deriveEnvName(source, finding, taken), "STRIPE_SECRET_KEY");
});

test("duplicate names get suffixed rather than colliding", () => {
  const taken = new Set<string>();
  const source = `const key = "${FAKE.awsKey}"`;
  const [finding] = blocking(scan(source, config).findings, config);
  assert.ok(finding);
  assert.equal(deriveEnvName(source, finding, taken), "KEY");
  assert.equal(deriveEnvName(source, finding, taken), "KEY_2");
  assert.equal(deriveEnvName(source, finding, taken), "KEY_3");
});

test("a dry run changes nothing on disk", () => {
  const dir = tempDir();
  try {
    const file = join(dir, "app.ts");
    const source = `const k = "${FAKE.awsKey}";\n`;
    writeFileSync(file, source);

    const plan = planFix(file, source, config);
    applyEnvFiles(file, plan.edits, false);

    assert.equal(readFileSync(file, "utf8"), source, "source must be untouched");
    assert.ok(!existsSync(join(dir, ".env")), ".env must not be created on a dry run");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test(".env goes to the project root, not beside the source file", () => {
  const dir = tempDir();
  try {
    // A src/.env is useless to the runtime and just a new hiding place.
    mkdirSync(join(dir, "src", "deep"), { recursive: true });
    writeFileSync(join(dir, "package.json"), "{}");
    writeFileSync(join(dir, ".gitignore"), ".env\n");

    const file = join(dir, "src", "deep", "config.ts");
    const source = `const apiKey = "${FAKE.awsKey}";\n`;
    writeFileSync(file, source);

    const plan = planFix(file, source, config);
    applyEnvFiles(file, plan.edits, true);

    assert.ok(existsSync(join(dir, ".env")), ".env belongs at the root");
    assert.ok(!existsSync(join(dir, "src", "deep", ".env")), "and nowhere else");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("writing appends to .env and .env.example", () => {
  const dir = tempDir();
  try {
    const file = join(dir, "app.ts");
    const source = `const apiKey = "${FAKE.awsKey}";\n`;
    writeFileSync(file, source);
    writeFileSync(join(dir, ".gitignore"), ".env\n");

    const plan = planFix(file, source, config);
    const result = applyEnvFiles(file, plan.edits, true);

    const env = readFileSync(join(dir, ".env"), "utf8");
    assert.match(env, new RegExp(`^API_KEY=${FAKE.awsKey}$`, "m"));

    const example = readFileSync(join(dir, ".env.example"), "utf8");
    assert.match(example, /^API_KEY=$/m);
    assert.ok(!example.includes(FAKE.awsKey), ".env.example must never hold the value");

    assert.equal(result.gitignoreWarning, undefined);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an unignored .env is called out", () => {
  const dir = tempDir();
  try {
    const file = join(dir, "app.ts");
    const source = `const apiKey = "${FAKE.awsKey}";\n`;
    writeFileSync(file, source);
    writeFileSync(join(dir, ".gitignore"), "node_modules\n");

    const plan = planFix(file, source, config);
    const result = applyEnvFiles(file, plan.edits, true);

    // Moving a secret from source into a committed .env is not an improvement.
    assert.match(result.gitignoreWarning ?? "", /does not ignore \.env/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an existing key in .env is not appended twice", () => {
  const dir = tempDir();
  try {
    const file = join(dir, "app.ts");
    const source = `const apiKey = "${FAKE.awsKey}";\n`;
    writeFileSync(file, source);
    writeFileSync(join(dir, ".env"), "API_KEY=already-here\n");
    writeFileSync(join(dir, ".gitignore"), ".env\n");

    const plan = planFix(file, source, config);
    const result = applyEnvFiles(file, plan.edits, true);

    assert.deepEqual(result.added, []);
    const env = readFileSync(join(dir, ".env"), "utf8");
    assert.equal(env.match(/^API_KEY=/gm)?.length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the fixed source no longer trips the scanner", () => {
  const source = `const apiKey = "${FAKE.awsKey}";\nconst t = "${FAKE.githubToken}";\n`;
  const plan = planFix("/a/x.ts", source, config);
  const after = blocking(scan(plan.updated, config).findings, config);
  assert.equal(after.length, 0, "fixing should actually resolve the findings");
});
