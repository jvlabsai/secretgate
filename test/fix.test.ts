import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { planFix, applyEnvFiles, deriveEnvName, createRegistry } from "../src/cli/fix.js";
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

/**
 * Emitting a reference to something not in scope is the same class of mistake
 * as putting a lookup inside a string literal: the diff reads correctly and the
 * program is broken. Python raised NameError at runtime; Go would not compile.
 */
test("python gets its os import added", () => {
  const plan = planFix("/a/app.py", `API_KEY = "${FAKE.awsKey}"\n`, config);
  assert.match(plan.updated, /^import os$/m);
  assert.match(plan.updated, /os\.environ\["API_KEY"\]/);
});

test("python does not get a second os import", () => {
  const source = `import os\nimport sys\n\nAPI_KEY = "${FAKE.awsKey}"\n`;
  const plan = planFix("/a/app.py", source, config);
  assert.equal(plan.updated.match(/^import os$/gm)?.length, 1);
});

test("`from os import environ` does NOT count as importing os", () => {
  // It binds `environ`, not `os`, so os.environ would still be undefined.
  const source = `from os import environ\n\nAPI_KEY = "${FAKE.awsKey}"\n`;
  const plan = planFix("/a/app.py", source, config);
  assert.match(plan.updated, /^import os$/m, "os.environ needs os itself to be bound");
});

test("`import os.path` already binds os", () => {
  const source = `import os.path\n\nAPI_KEY = "${FAKE.awsKey}"\n`;
  const plan = planFix("/a/app.py", source, config);
  assert.equal(plan.updated.match(/^import os$/gm), null, "os is already bound; do not add a duplicate");
});

test("the python import lands after a shebang and docstring", () => {
  const source = `#!/usr/bin/env python\n"""Module docstring."""\n\nAPI_KEY = "${FAKE.awsKey}"\n`;
  const plan = planFix("/a/app.py", source, config);
  const lines = plan.updated.split("\n");
  assert.equal(lines[0], "#!/usr/bin/env python", "shebang must stay on line one");
  assert.ok(lines.indexOf("import os") > 1, "import must come after the docstring");
});

test("go gets os added to an existing import block, in gofmt order", () => {
  // gofmt sorts imports; inserting out of order means it rewrites our line the
  // first time anyone saves the file.
  const source = `package main\n\nimport (\n\t"fmt"\n)\n\nfunc main() {\n\tk := "${FAKE.awsKey}"\n\tfmt.Println(k)\n}\n`;
  const plan = planFix("/a/main.go", source, config);
  assert.match(plan.updated, /import \(\n\t"fmt"\n\t"os"\n\)/, '"fmt" sorts before "os"');
  assert.equal(plan.updated.match(/"os"/g)?.length, 1);
});

test("go import insertion stays sorted against a later package", () => {
  const source = `package main\n\nimport (\n\t"strings"\n)\n\nfunc main() {\n\tk := "${FAKE.awsKey}"\n\t_ = strings.TrimSpace(k)\n}\n`;
  const plan = planFix("/a/main.go", source, config);
  assert.match(plan.updated, /import \(\n\t"os"\n\t"strings"\n\)/, '"os" sorts before "strings"');
});

test("go with no imports at all gets one", () => {
  const source = `package main\n\nfunc main() {\n\tk := "${FAKE.awsKey}"\n\t_ = k\n}\n`;
  const plan = planFix("/a/main.go", source, config);
  assert.match(plan.updated, /^import "os"$/m);
  assert.match(plan.updated, /package main/);
});

test("go with a single import is promoted to a sorted block", () => {
  const source = `package main\n\nimport "fmt"\n\nfunc main() {\n\tk := "${FAKE.awsKey}"\n\tfmt.Println(k)\n}\n`;
  const plan = planFix("/a/main.go", source, config);
  assert.match(plan.updated, /import \(\n\t"fmt"\n\t"os"\n\)/, "existing import must survive, in order");
});

/**
 * These three had one assertion each, which is how the Python and Go import
 * bugs got through. Each now checks the exact output a developer would get.
 */
test("ruby uses ENV and needs no require", () => {
  const plan = planFix("/a/app.rb", `API_KEY = "${FAKE.awsKey}"\n`, config);
  assert.equal(plan.updated, 'API_KEY = ENV["API_KEY"]\n');
});

test("php uses getenv and needs no import", () => {
  const plan = planFix("/a/app.php", `<?php\n$apiKey = "${FAKE.awsKey}";\n`, config);
  assert.equal(plan.updated, '<?php\n$apiKey = getenv("API_KEY");\n');
});

test("shell reads the variable from the environment", () => {
  const plan = planFix("/a/app.sh", `#!/bin/bash\nAPI_KEY="${FAKE.awsKey}"\n`, config);
  assert.equal(plan.updated, '#!/bin/bash\nAPI_KEY="$API_KEY"\n');
});

test("typescript is unchanged apart from the lookup", () => {
  const plan = planFix("/a/app.ts", `const apiKey = "${FAKE.awsKey}";\n`, config);
  assert.equal(plan.updated, "const apiKey = process.env.API_KEY;\n");
});

test("languages with global env access need no import", () => {
  for (const [path, mustNotContain] of [
    ["/a/x.rb", "require"],
    ["/a/x.php", "import"],
  ] as const) {
    const plan = planFix(path, `key = "${FAKE.awsKey}"\n`, config);
    assert.ok(!plan.updated.includes(mustNotContain), `${path} should not gain an import`);
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

/**
 * The regression this guards is the nastiest bug this command has had.
 *
 * Two files both calling their constant `apiKey` each derived API_KEY. The
 * first won in .env, the second was skipped as a duplicate, and the second
 * file — already rewritten to process.env.API_KEY — silently read the first
 * file's credential while its own vanished entirely. Wrong value at runtime,
 * data loss, and nothing in the output to suggest it.
 */
test("two files with the same identifier but different secrets get different variables", () => {
  const dir = tempDir();
  try {
    writeFileSync(join(dir, "package.json"), "{}");
    writeFileSync(join(dir, ".gitignore"), ".env\n");

    const a = join(dir, "a.ts");
    const b = join(dir, "b.ts");
    const sourceA = `export const apiKey = "${FAKE.awsKey}";\n`;
    const sourceB = `export const apiKey = "${FAKE.awsKeyAlt}";\n`;
    writeFileSync(a, sourceA);
    writeFileSync(b, sourceB);

    const registry = createRegistry(join(dir, ".env"));

    const planA = planFix(a, sourceA, config, registry);
    applyEnvFiles(a, planA.edits, true);
    writeFileSync(a, planA.updated);

    const planB = planFix(b, sourceB, config, registry);
    applyEnvFiles(b, planB.edits, true);
    writeFileSync(b, planB.updated);

    assert.notEqual(planA.edits[0]!.name, planB.edits[0]!.name, "different secrets must not share a variable");

    const env = readFileSync(join(dir, ".env"), "utf8");
    assert.ok(env.includes(FAKE.awsKey), "the first secret must be in .env");
    assert.ok(env.includes(FAKE.awsKeyAlt), "the second secret must be in .env too, not silently dropped");

    // And each file must reference its own value.
    const nameA = planA.edits[0]!.name;
    const nameB = planB.edits[0]!.name;
    assert.match(readFileSync(a, "utf8"), new RegExp(`process\\.env\\.${nameA}`));
    assert.match(readFileSync(b, "utf8"), new RegExp(`process\\.env\\.${nameB}`));
    assert.match(env, new RegExp(`^${nameA}=${FAKE.awsKey}$`, "m"));
    assert.match(env, new RegExp(`^${nameB}=${FAKE.awsKeyAlt}$`, "m"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the same secret in two files collapses to one variable", () => {
  const dir = tempDir();
  try {
    const registry = createRegistry(join(dir, ".env"));
    const source = `export const apiKey = "${FAKE.awsKey}";\n`;

    const planA = planFix(join(dir, "a.ts"), source, config, registry);
    const planB = planFix(join(dir, "b.ts"), source, config, registry);

    assert.equal(planA.edits[0]!.name, planB.edits[0]!.name, "one secret is one variable");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a name already used in .env for a different value is not reused", () => {
  const dir = tempDir();
  try {
    writeFileSync(join(dir, ".env"), `API_KEY=${FAKE.awsKeyAlt}\n`);
    const registry = createRegistry(join(dir, ".env"));

    const source = `export const apiKey = "${FAKE.awsKey}";\n`;
    const plan = planFix(join(dir, "a.ts"), source, config, registry);

    assert.notEqual(plan.edits[0]!.name, "API_KEY", "must not collide with the existing entry");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a value already in .env reuses its existing variable name", () => {
  const dir = tempDir();
  try {
    writeFileSync(join(dir, ".env"), `EXISTING_NAME=${FAKE.awsKey}\n`);
    const registry = createRegistry(join(dir, ".env"));

    const source = `export const apiKey = "${FAKE.awsKey}";\n`;
    const plan = planFix(join(dir, "a.ts"), source, config, registry);

    assert.equal(plan.edits[0]!.name, "EXISTING_NAME", "do not add a second variable for a value already there");
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
