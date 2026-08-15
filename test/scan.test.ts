import { test } from "node:test";
import assert from "node:assert/strict";
import { scan, blocking } from "../src/core/scan.js";
import { defaultConfig } from "../src/config/index.js";
import { isPlaceholderValue, globMatch, isTestPath, fingerprint } from "../src/core/suppress.js";
import { shannon } from "../src/core/entropy.js";
import { isRealJwt } from "../src/core/rules/keys.js";
import { allRules } from "../src/core/rules/index.js";
import { FAKE, fakeJwt, fakePem, fakePublicPem } from "./fixtures.js";

const config = defaultConfig();
const found = (text: string) => scan(text, config).findings.map((f) => f.ruleId);

test("every rule has a unique id and a global regex", () => {
  const ids = new Set<string>();
  for (const r of allRules) {
    assert.ok(!ids.has(r.id), `duplicate rule id ${r.id}`);
    ids.add(r.id);
    assert.ok(r.regex.global, `${r.id} needs the g flag`);
    assert.ok(r.description.length > 0, `${r.id} needs a description`);
  }
});

test("scanning the same text twice gives the same answer", () => {
  // Catches a stateful lastIndex leaking between calls, which is the classic
  // way a shared global regex goes wrong.
  const text = `aws = "${FAKE.awsKey}"\ngh = "${FAKE.githubToken}"`;
  const first = scan(text, config).findings;
  const second = scan(text, config).findings;
  assert.deepEqual(first, second);
});

test("empty and whitespace input is handled", () => {
  assert.deepEqual(scan("", config).findings, []);
  assert.deepEqual(scan("   \n\t\n", config).findings, []);
});

test("findings point at the credential, not the surrounding context", () => {
  const secret = FAKE.awsKey;
  const text = `aws_access_key_id = "${secret}"`;
  const [finding] = scan(text, config).findings;
  assert.ok(finding);
  assert.equal(text.slice(finding.start, finding.end), secret);
});

test("connection strings flag the password only, not the whole URI", () => {
  const text = "postgres://svc_api:h4Kd9wQz2Lp8Nx7@db.internal:5432/orders";
  const [finding] = scan(text, config).findings;
  assert.ok(finding);
  assert.equal(finding.match, "h4Kd9wQz2Lp8Nx7");
});

test("an inline pragma opts a line out", () => {
  const text = `key = "${FAKE.awsKey}"  # secretgate:allow`;
  const result = scan(text, config);
  assert.deepEqual(result.findings, []);
  assert.equal(result.suppressed[0]?.note, "secretgate:allow pragma");
});

test("the pragma works in every comment syntax we document", () => {
  const key = FAKE.awsKey;
  for (const line of [
    `key = "${key}"  # secretgate:allow`,
    `const k = "${key}"; // secretgate:allow`,
    `const k = "${key}"; /* secretgate:allow */`,
    `key: ${key}  -- secretgate:allow`,
    `key = "${key}"  ; secretgate:allow`,
    `<!-- secretgate:allow --> ${key}`,
  ]) {
    assert.deepEqual(scan(line, config).findings, [], `pragma not honoured in: ${line}`);
  }
});

test("a pragma on a different line does not opt this one out", () => {
  const text = `# secretgate:allow\nkey = "${FAKE.awsKey}"`;
  assert.ok(scan(text, config).findings.length > 0);
});

test("findings in a test path are downgraded, not dropped", () => {
  const text = `key = "${FAKE.awsKey}"`;
  const inTest = scan(text, { ...config, path: "src/__tests__/fixtures.ts" });
  assert.equal(inTest.findings.length, 1);
  assert.equal(inTest.findings[0]!.confidence, "low");
  assert.equal(blocking(inTest.findings, config).length, 0);
});

test("an allowlisted path suppresses entirely", () => {
  const text = `key = "${FAKE.awsKey}"`;
  const cfg = { ...config, path: "packages/app/fixtures/creds.ts", allowlist: { paths: ["**/fixtures/**"], patterns: [] } };
  assert.deepEqual(scan(text, cfg).findings, []);
});

test("a baseline fingerprint suppresses a known finding", () => {
  const secret = FAKE.awsKey;
  const salt = "test-salt";
  const cfg = { ...config, baselineSalt: salt, baseline: new Set([fingerprint(secret, salt)]) };
  const result = scan(`key = "${secret}"`, cfg);
  assert.deepEqual(result.findings, []);
  assert.equal(result.suppressed[0]?.note, "accepted in baseline");
});

test("disabling a rule works by id and by provider", () => {
  const text = FAKE.githubToken;
  assert.ok(found(text).includes("github-pat-classic"));
  assert.deepEqual(scan(text, { ...config, rules: { disable: ["github-pat-classic"] } }).findings, []);
  assert.deepEqual(scan(text, { ...config, rules: { disable: ["github"] } }).findings, []);
});

test("overlapping matches collapse to the most specific one", () => {
  const text = 'DATABASE_URL="postgres://svc:h4Kd9wQz2Lp8Nx7@db.internal:5432/app"';
  const findings = scan(text, config).findings;
  assert.equal(findings.length, 1, "the generic rule must not double-report the db rule's hit");
  assert.equal(findings[0]!.ruleId, "db-connection-string");
});

test("entropy findings never block by default", () => {
  const text = 'cache_bust = "Xk9mQ2pL7vN4wR8tY3zB6cF1dG5hJ0sA"';
  const findings = scan(text, config).findings;
  for (const f of findings) {
    if (f.ruleId === "high-entropy-string") assert.equal(f.confidence, "low");
  }
  assert.equal(blocking(findings.filter((f) => f.ruleId === "high-entropy-string"), config).length, 0);
});

test("a public key block is not a private key", () => {
  assert.deepEqual(found(fakePublicPem()), []);
});

test("a private key block is caught", () => {
  assert.ok(found(fakePem()).some((id) => id.startsWith("private-key")));
});

test("jwt validation requires a decodable payload", () => {
  assert.ok(isRealJwt(fakeJwt()));
  assert.ok(!isRealJwt("not.a.jwt"));
  assert.ok(!isRealJwt("eyJhbGciXXXX.eyJzdWIiYWJj.notarealsignature1234"));
  assert.ok(!isRealJwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"), "a lone header is not a token");
});

test("placeholder detection catches stand-ins but not real keys", () => {
  for (const fake of [
    "your-api-key-here",
    "<your_stripe_secret_key>",
    "${DB_PASSWORD}",
    "changeme",
    FAKE.awsKeyRedacted,
    FAKE.awsDocKey,
    "sk-test-abcd-1234",
    "my-secret-password",
    "password",
    "var.db_password",
    "process.env.API_KEY",
  ]) {
    assert.ok(isPlaceholderValue(fake), `should be treated as a placeholder: ${fake}`);
  }

  for (const real of [
    FAKE.awsKey,
    FAKE.githubToken,
    FAKE.mailgunKey,
    "h4Kd9wQz2Lp8Nx7",
    "Rt3sTk9mQ2pL7vN4wR8t",
  ]) {
    assert.ok(!isPlaceholderValue(real), `should NOT be treated as a placeholder: ${real}`);
  }
});

test("short placeholder words only match as whole tokens", () => {
  // The regression this guards: substring matching on "test" silently dropped
  // roughly one real key in a thousand.
  assert.ok(!isPlaceholderValue("Rt3sTkTestable9mQ2pL7vN4wR8tY3zB"), "no delimiter, so no token match");
  assert.ok(isPlaceholderValue("abc-test-def"), "delimited, so it is a token match");
});

test("glob matching handles the patterns we document", () => {
  assert.ok(globMatch("**/fixtures/**", "packages/app/fixtures/creds.ts"));
  assert.ok(globMatch("**/fixtures/**", "fixtures/creds.ts"));
  assert.ok(!globMatch("**/fixtures/**", "src/app/main.ts"));
  assert.ok(globMatch("*.test.ts", "vault.test.ts"));
  assert.ok(globMatch("src/**/*.ts", "src/core/scan.ts"));
  assert.ok(!globMatch("src/*.ts", "src/core/scan.ts"), "single star must not cross a separator");
});

test("test path detection covers the usual layouts", () => {
  for (const p of ["src/__tests__/a.ts", "a/test/b.go", "pkg/thing_test.go", "x/fixtures/y.json", "app/config.example"]) {
    assert.ok(isTestPath(p), p);
  }
  assert.ok(!isTestPath("src/core/scan.ts"));
  assert.ok(!isTestPath(undefined));
});

test("shannon entropy is in the right ballpark", () => {
  assert.equal(shannon(""), 0);
  assert.equal(shannon("aaaa"), 0);
  assert.ok(shannon("abcd") > 1.9 && shannon("abcd") < 2.1);
  assert.ok(shannon("Xk9mQ2pL7vN4wR8tY3zB6cF1dG5hJ0sA") > 4.0);
});

test("a very long input does not hang the scanner", () => {
  const big = `${"lorem ipsum dolor sit amet ".repeat(20000)}${FAKE.awsKey}`;
  const t0 = Date.now();
  const findings = scan(big, config).findings;
  assert.ok(Date.now() - t0 < 2000, "must stay well inside a sane time bound");
  assert.ok(findings.some((f) => f.ruleId === "aws-access-key-id"));
});
