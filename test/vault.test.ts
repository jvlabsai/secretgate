import { test } from "node:test";
import assert from "node:assert/strict";
import { inspect } from "node:util";
import { Vault } from "../src/core/redact.js";
import { scan } from "../src/core/scan.js";
import { defaultConfig } from "../src/config/index.js";
import { FAKE } from "./fixtures.js";

const AWS_KEY = FAKE.awsKey;
const GH_TOKEN = FAKE.githubToken;
const config = defaultConfig();

function findingsFor(text: string) {
  return scan(text, config).findings;
}

test("placeholder is stable for the same secret within a session", () => {
  const vault = new Vault();
  const a = vault.redact(`key=${AWS_KEY}`, findingsFor(`key=${AWS_KEY}`));
  const b = vault.redact(`other line ${AWS_KEY}`, findingsFor(`other line ${AWS_KEY}`));

  const pa = a.replacements[0]!.placeholder;
  const pb = b.replacements[0]!.placeholder;
  assert.equal(pa, pb, "the same secret must map to the same placeholder all session");
});

test("different secrets get different placeholders", () => {
  const vault = new Vault();
  const text = `aws=${AWS_KEY}\ngh=${GH_TOKEN}`;
  const { replacements } = vault.redact(text, findingsFor(text));
  const placeholders = new Set(replacements.map((r) => r.placeholder));
  assert.equal(placeholders.size, 2);
});

test("placeholder preserves provider and kind so the model keeps its bearings", () => {
  const vault = new Vault();
  const { text } = vault.redact(`key=${AWS_KEY}`, findingsFor(`key=${AWS_KEY}`));
  assert.match(text, /SECRETGATE_AWS_KEY_[0-9A-F]{4}/);
});

test("placeholder survives shell, JSON and YAML quoting untouched", () => {
  const vault = new Vault();
  const { replacements } = vault.redact(AWS_KEY, findingsFor(AWS_KEY));
  const p = replacements[0]!.placeholder;

  // No characters that any of these would escape, quote or reflow.
  assert.match(p, /^[A-Z][A-Z0-9_]*$/, "must be a bare identifier");

  assert.equal(JSON.parse(JSON.stringify({ k: p })).k, p);
  assert.ok(!/["'`\\$ \n\t{}[\]]/.test(p), "must contain nothing a shell would interpret");
});

test("round trip returns the original text exactly", () => {
  const vault = new Vault();
  const original = `AWS_ACCESS_KEY_ID=${AWS_KEY}\nGITHUB_TOKEN=${GH_TOKEN}\n`;
  const { text: redacted } = vault.redact(original, findingsFor(original));

  assert.ok(!redacted.includes(AWS_KEY), "secret must not survive redaction");
  assert.ok(!redacted.includes(GH_TOKEN), "secret must not survive redaction");

  const { text: restored, substituted, warnings } = vault.rehydrate(redacted);
  assert.equal(restored, original);
  assert.equal(substituted, 2);
  assert.deepEqual(warnings, []);
});

test("a truncated placeholder is refused, not guessed at", () => {
  const vault = new Vault();
  const { replacements } = vault.redact(AWS_KEY, findingsFor(AWS_KEY));
  const p = replacements[0]!.placeholder;
  const truncated = p.slice(0, -1);

  const result = vault.rehydrate(`const key = "${truncated}";`);
  assert.equal(result.substituted, 0, "must not substitute on a partial match");
  assert.ok(result.text.includes(truncated), "the mangled token is left exactly as it arrived");
  assert.ok(!result.text.includes(AWS_KEY), "the real secret must not leak into a partial match");
  assert.equal(result.warnings.length, 1);
  assert.equal(result.warnings[0]!.kind, "mangled");
});

test("a placeholder with extra characters appended is refused", () => {
  const vault = new Vault();
  const { replacements } = vault.redact(AWS_KEY, findingsFor(AWS_KEY));
  const p = replacements[0]!.placeholder;

  const result = vault.rehydrate(`${p}_BACKUP`);
  assert.equal(result.substituted, 0);
  assert.ok(!result.text.includes(AWS_KEY));
  assert.equal(result.warnings[0]!.kind, "mangled");
});

test("a placeholder the agent invented is refused", () => {
  const vault = new Vault();
  vault.redact(AWS_KEY, findingsFor(AWS_KEY));

  const result = vault.rehydrate('token = "SECRETGATE_STRIPE_KEY_dead"');
  assert.equal(result.substituted, 0);
  assert.equal(result.warnings.length, 1);
  assert.equal(result.warnings[0]!.kind, "unknown");
});

test("rehydration is a no-op on text with no placeholders", () => {
  const vault = new Vault();
  const text = "just some ordinary code\nconst x = 1;\n";
  const result = vault.rehydrate(text);
  assert.equal(result.text, text);
  assert.equal(result.substituted, 0);
  assert.deepEqual(result.warnings, []);
});

test("multiple occurrences of one secret all rehydrate", () => {
  const vault = new Vault();
  const original = `a=${AWS_KEY}\nb=${AWS_KEY}\nc=${AWS_KEY}`;
  const { text: redacted } = vault.redact(original, findingsFor(original));
  const result = vault.rehydrate(redacted);
  assert.equal(result.text, original);
  assert.equal(result.substituted, 3);
});

test("wiping clears every mapping", () => {
  const vault = new Vault();
  const { text: redacted } = vault.redact(AWS_KEY, findingsFor(AWS_KEY));
  vault.wipe();

  assert.equal(vault.size, 0);
  const result = vault.rehydrate(redacted);
  assert.equal(result.substituted, 0);
  assert.ok(!result.text.includes(AWS_KEY), "a wiped vault cannot resurrect a secret");
});

test("the vault never renders its contents, however it is printed", () => {
  const vault = new Vault();
  vault.redact(`key=${AWS_KEY}`, findingsFor(`key=${AWS_KEY}`));

  const renderings = [
    JSON.stringify(vault),
    JSON.stringify({ nested: { vault } }),
    String(vault),
    `${vault}`,
    inspect(vault),
    inspect({ deep: { vault } }, { depth: 10 }),
    util_format(vault),
  ];

  for (const rendering of renderings) {
    assert.ok(!rendering.includes(AWS_KEY), `secret leaked via: ${rendering.slice(0, 120)}`);
  }
});

function util_format(v: unknown): string {
  // console.log's own formatting path, which is the one that actually ends up
  // in a terminal scrollback or a CI log.
  return inspect(v, { depth: null, showHidden: true });
}

test("an uncaught error carrying the vault does not print the secret", () => {
  const vault = new Vault();
  vault.redact(`key=${AWS_KEY}`, findingsFor(`key=${AWS_KEY}`));

  const err = new Error(`vault state: ${inspect(vault)}`);
  assert.ok(!err.stack!.includes(AWS_KEY));
  assert.ok(!err.message.includes(AWS_KEY));
});

test("colliding stems still produce distinct placeholders", () => {
  const vault = new Vault();
  // Force many secrets through one provider/kind stem and confirm the mapping
  // stays injective as the 4-hex suffix space fills up.
  const seen = new Set<string>();
  for (let i = 0; i < 400; i++) {
    const secret = `AKIA${String(i).padStart(6, "0")}QWERTYZXCV`;
    const p = vault.placeholderFor({
      ruleId: "aws-access-key-id",
      provider: "aws",
      match: secret,
      start: 0,
      end: secret.length,
      confidence: "high",
      entropy: 4,
    });
    assert.ok(!seen.has(p), `placeholder collision at ${i}: ${p}`);
    seen.add(p);
  }
  assert.equal(seen.size, 400);
});

test("redaction leaves surrounding text byte-identical", () => {
  const vault = new Vault();
  const original = `line one\n  aws_key = "${AWS_KEY}"  # keep this comment\nline three\n`;
  const { text } = vault.redact(original, findingsFor(original));

  assert.ok(text.startsWith("line one\n  aws_key = \""));
  assert.ok(text.includes('"  # keep this comment'));
  assert.ok(text.endsWith("line three\n"));
});
