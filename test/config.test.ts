import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseSimpleYaml } from "../src/config/yaml.js";
import { loadConfig, defaultConfig, SAMPLE_CONFIG } from "../src/config/index.js";

test("the yaml subset parses the shapes the config uses", () => {
  const parsed = parseSimpleYaml(`
mode: redact

entropy:
  enabled: true
  threshold: 4.0
  action: warn

rules:
  disable: []

allowlist:
  paths:
    - "**/fixtures/**"
    - "**/testdata/**"
  patterns:
    - "EXAMPLE_.*"

vault:
  persist: false
`);

  assert.equal(parsed.mode, "redact");
  assert.deepEqual(parsed.entropy, { enabled: true, threshold: 4, action: "warn" });
  assert.deepEqual((parsed.allowlist as any).paths, ["**/fixtures/**", "**/testdata/**"]);
  assert.deepEqual((parsed.allowlist as any).patterns, ["EXAMPLE_.*"]);
  assert.deepEqual((parsed.vault as any).persist, false);
});

test("comments and blank lines are ignored, but a # inside quotes is content", () => {
  const parsed = parseSimpleYaml(`
# leading comment
mode: block   # trailing comment

allowlist:
  patterns:
    - "KEY_#_LITERAL"
`);
  assert.equal(parsed.mode, "block");
  assert.deepEqual((parsed.allowlist as any).patterns, ["KEY_#_LITERAL"]);
});

test("the sample config we ship actually parses", () => {
  const parsed = parseSimpleYaml(SAMPLE_CONFIG);
  assert.equal(parsed.mode, "redact");
  assert.equal((parsed.entropy as any).action, "warn");
  assert.deepEqual((parsed.allowlist as any).paths, ["**/fixtures/**", "**/testdata/**"]);
});

test("scalars coerce to the right types", () => {
  const parsed = parseSimpleYaml("a: true\nb: false\nc: 4.0\nd: 12\ne: hello\nf: \"quoted\"\ng:\n");
  assert.equal(parsed.a, true);
  assert.equal(parsed.b, false);
  assert.equal(parsed.c, 4);
  assert.equal(parsed.d, 12);
  assert.equal(parsed.e, "hello");
  assert.equal(parsed.f, "quoted");
  assert.equal(parsed.g, "");
});

test("loadConfig reads a real file from disk", () => {
  const dir = mkdtempSync(join(tmpdir(), "secretgate-"));
  try {
    writeFileSync(
      join(dir, "secretgate.yml"),
      "mode: block\nentropy:\n  enabled: false\n  threshold: 3.5\n  action: ignore\nrules:\n  disable:\n    - generic-api-key\n",
    );
    const config = loadConfig(dir);
    assert.equal(config.mode, "block");
    assert.equal(config.entropy.enabled, false);
    assert.equal(config.entropy.threshold, 3.5);
    assert.equal(config.entropy.action, "ignore");
    assert.deepEqual(config.rules.disable, ["generic-api-key"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a broken config falls back to defaults rather than crashing", () => {
  const dir = mkdtempSync(join(tmpdir(), "secretgate-"));
  try {
    writeFileSync(join(dir, "secretgate.yml"), ":::: not really yaml [[[\n\t\tmode\n");
    const config = loadConfig(dir);
    assert.equal(config.mode, defaultConfig().mode);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an unknown mode is ignored rather than accepted", () => {
  const dir = mkdtempSync(join(tmpdir(), "secretgate-"));
  try {
    writeFileSync(join(dir, "secretgate.yml"), "mode: yolo\n");
    assert.equal(loadConfig(dir).mode, "redact");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
