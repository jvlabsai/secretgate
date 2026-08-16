import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseSimpleYaml } from "../src/config/yaml.js";
import { buildCustomRules } from "../src/core/rules/custom.js";
import { loadConfig, defaultConfig } from "../src/config/index.js";
import { scan, blocking } from "../src/core/scan.js";

test("the yaml subset parses a list of maps", () => {
  const parsed = parseSimpleYaml(`
rules:
  custom:
    - id: acme-service-token
      provider: acme
      description: ACME internal service token
      regex: "ACME-SVC-[A-Z0-9]{32}"
      confidence: high
      prefilter:
        - "ACME-SVC-"
    - id: legacy-key
      regex: "LEGACY_[0-9a-f]{40}"
`);

  const custom = (parsed.rules as any).custom;
  assert.equal(custom.length, 2);
  assert.equal(custom[0].id, "acme-service-token");
  assert.equal(custom[0].provider, "acme");
  assert.equal(custom[0].regex, "ACME-SVC-[A-Z0-9]{32}");
  assert.deepEqual(custom[0].prefilter, ["ACME-SVC-"]);
  assert.equal(custom[1].id, "legacy-key");
});

test("lists of scalars still parse the way they did", () => {
  const parsed = parseSimpleYaml(`
allowlist:
  paths:
    - "**/fixtures/**"
    - "**/testdata/**"
`);
  assert.deepEqual((parsed.allowlist as any).paths, ["**/fixtures/**", "**/testdata/**"]);
});

test("a quoted scalar containing a colon is not mistaken for a map", () => {
  const parsed = parseSimpleYaml(`
allowlist:
  patterns:
    - "postgres://localhost:5432"
`);
  assert.deepEqual((parsed.allowlist as any).patterns, ["postgres://localhost:5432"]);
});

test("a custom rule detects a format no built-in knows about", () => {
  const { rules, problems } = buildCustomRules([
    { id: "acme-service-token", provider: "acme", regex: "ACME-SVC-[A-Z0-9]{32}", prefilter: ["ACME-SVC-"] },
  ]);
  assert.deepEqual(problems, []);
  assert.equal(rules.length, 1);

  const config = { ...defaultConfig(), rules: { disable: [], custom: rules } };
  const secret = `ACME-SVC-${"K7M2QP9XLR4TVN8WZB6CF1DG5HJ0SA3E".slice(0, 32)}`;
  const findings = blocking(scan(`token = "${secret}"`, config).findings, config);

  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.ruleId, "acme-service-token");
  assert.equal(findings[0]!.provider, "acme");
  assert.equal(findings[0]!.match, secret);
});

test("without the custom rule that same format is invisible", () => {
  const secret = "ACME-SVC-K7M2QP9XLR4TVN8WZB6CF1DG5HJ0SA3E";
  const findings = blocking(scan(`token = "${secret}"`, defaultConfig()).findings, defaultConfig());
  assert.equal(findings.filter((f) => f.provider === "acme").length, 0);
});

test("a rule that does not compile is reported, not swallowed", () => {
  const { rules, problems } = buildCustomRules([{ id: "broken", regex: "([unclosed" }]);
  assert.equal(rules.length, 0);
  assert.equal(problems.length, 1);
  assert.match(problems[0]!, /does not compile/);
});

test("a rule missing an id or regex is reported", () => {
  const noId = buildCustomRules([{ regex: "abc" }]);
  assert.match(noId.problems[0]!, /needs an id/);

  const noRegex = buildCustomRules([{ id: "x" }]);
  assert.match(noRegex.problems[0]!, /needs a regex/);
});

test("a catastrophically backtracking regex is rejected rather than run", () => {
  // Left in the ruleset this would hang the scanner on every prompt, and the
  // developer would blame the agent rather than their config.
  const { rules, problems } = buildCustomRules([{ id: "redos", regex: "^(a+)+$" }]);
  assert.equal(rules.length, 0, "must not be loaded");
  assert.match(problems[0]!, /too slow/);
});

test("custom rules always get the global flag", () => {
  const { rules } = buildCustomRules([{ id: "x", regex: "abc", flags: "i" }]);
  assert.ok(rules[0]!.regex.global);
  assert.ok(rules[0]!.regex.ignoreCase);
});

test("custom rules can be disabled like any other", () => {
  const { rules } = buildCustomRules([{ id: "acme", regex: "ACME-[A-Z0-9]{20}" }]);
  const config = { ...defaultConfig(), rules: { disable: ["acme"], custom: rules } };
  assert.deepEqual(scan("ACME-K7M2QP9XLR4TVN8WZB6C", config).findings, []);
});

test("loadConfig compiles custom rules from a real file", () => {
  const dir = mkdtempSync(join(tmpdir(), "secretgate-custom-"));
  try {
    writeFileSync(
      join(dir, "secretgate.yml"),
      [
        "rules:",
        "  custom:",
        "    - id: acme-service-token",
        "      provider: acme",
        '      regex: "ACME-SVC-[A-Z0-9]{32}"',
        "      confidence: high",
        "",
      ].join("\n"),
    );

    const config = loadConfig(dir);
    assert.equal(config.rules.custom.length, 1);
    assert.equal(config.rules.custom[0]!.id, "acme-service-token");

    const secret = "ACME-SVC-K7M2QP9XLR4TVN8WZB6CF1DG5HJ0SA3E";
    const findings = blocking(scan(`t = "${secret}"`, config).findings, config);
    assert.equal(findings.length, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
