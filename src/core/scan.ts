import type { Config, Confidence, Finding, Rule, ScanResult } from "./types.js";
import { rulesFor } from "./rules/index.js";
import { shannon, entropyThresholdFor } from "./entropy.js";
import { evaluateSuppression, isPlaceholderValue } from "./suppress.js";

const CONFIDENCE_RANK: Record<Confidence, number> = { high: 3, medium: 2, low: 1 };

/**
 * Cheap gate before the regex set runs. Rules that carry a distinctive literal
 * ("AKIA", "ghp_", "sk-ant-") are skipped outright when the text does not
 * contain it, which is the difference between running 40 regexes and running 3
 * on a typical prompt.
 *
 * ponytail: plain `includes` per literal, O(n·m). Aho-Corasick would be the
 * textbook answer; at ~90 literals over a 10KB prompt this already lands well
 * inside the 50ms budget, so it can wait until the ruleset is ten times bigger.
 */
function prefilterHit(text: string, rule: Rule): boolean {
  if (!rule.prefilter || rule.prefilter.length === 0) return true;
  for (const literal of rule.prefilter) {
    if (text.includes(literal)) return true;
  }
  return false;
}

function runRule(text: string, rule: Rule, out: Finding[]): void {
  if (!prefilterHit(text, rule)) return;

  rule.regex.lastIndex = 0;
  let m: RegExpExecArray | null;
  let guard = 0;

  while ((m = rule.regex.exec(text)) !== null) {
    // A zero-length match would spin forever; nudge past it.
    if (m[0].length === 0) {
      rule.regex.lastIndex += 1;
      continue;
    }
    if (++guard > 5000) break;

    const groupIndex = rule.group ?? 0;
    const secret = m[groupIndex];
    if (!secret) continue;

    if (rule.validate && !rule.validate(secret, m[0])) continue;

    const ent = shannon(secret);
    if (rule.entropyMin !== undefined && ent < rule.entropyMin) continue;

    // Where the secret itself sits, not where the surrounding context starts —
    // redaction must replace only the credential.
    const offsetInMatch = groupIndex === 0 ? 0 : m[0].indexOf(secret);
    const start = m.index + (offsetInMatch === -1 ? 0 : offsetInMatch);

    out.push({
      ruleId: rule.id,
      provider: rule.provider,
      match: secret,
      start,
      end: start + secret.length,
      confidence: rule.confidence ?? "medium",
      entropy: ent,
    });
  }
}

// Quoted strings and assignment right-hand sides — the only places a bare
// high-entropy blob is worth a second look.
const CANDIDATE = /(?:["'`]([A-Za-z0-9+/=_-]{16,120})["'`]|[:=]\s*([A-Za-z0-9+/=_-]{16,120})(?=[\s,;)\]}]|$))/g;

function runEntropyLayer(text: string, config: Config, covered: Finding[], out: Finding[]): void {
  if (!config.entropy.enabled) return;

  CANDIDATE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = CANDIDATE.exec(text)) !== null) {
    const value = m[1] ?? m[2];
    if (!value) continue;

    const start = m[0].indexOf(value) + m.index;
    // A structured rule already owns this span; do not double-report it.
    if (covered.some((f) => start < f.end && start + value.length > f.start)) continue;

    if (isPlaceholderValue(value)) continue;

    const ent = shannon(value);
    if (ent < entropyThresholdFor(value, config.entropy.threshold)) continue;

    out.push({
      ruleId: "high-entropy-string",
      provider: "unknown",
      match: value,
      start,
      end: start + value.length,
      // Never high. Entropy alone is a hint, and treating it as more than that
      // is how a scanner earns its way into a developer's ignore list.
      confidence: "low",
      entropy: ent,
    });
  }
}

/**
 * Overlapping matches are normal — a connection string inside a .env line hits
 * both the db rule and the generic one. Keep the strongest, and among equals
 * the longest, so the placeholder names the most specific provider we know.
 */
function dedupe(findings: Finding[]): Finding[] {
  const sorted = [...findings].sort((a, b) => {
    const rank = CONFIDENCE_RANK[b.confidence] - CONFIDENCE_RANK[a.confidence];
    if (rank !== 0) return rank;
    return b.end - b.start - (a.end - a.start);
  });

  const kept: Finding[] = [];
  for (const f of sorted) {
    if (kept.some((k) => f.start < k.end && f.end > k.start)) continue;
    kept.push(f);
  }
  return kept.sort((a, b) => a.start - b.start);
}

export function scan(text: string, config: Config): ScanResult {
  if (!text) return { findings: [], suppressed: [] };

  const raw: Finding[] = [];
  for (const rule of rulesFor(config.rules.disable, config.rules.custom)) {
    runRule(text, rule, raw);
  }

  const structured = dedupe(raw);
  const withEntropy = [...structured];
  runEntropyLayer(text, config, structured, withEntropy);

  const findings: Finding[] = [];
  const suppressed: Finding[] = [];

  for (const f of dedupe(withEntropy)) {
    const verdict = evaluateSuppression(f, text, config);
    if (verdict.suppressed) {
      suppressed.push({ ...f, note: verdict.note });
      continue;
    }
    if (verdict.downgraded) {
      findings.push({ ...f, confidence: "low", note: verdict.note });
      continue;
    }
    findings.push(f);
  }

  return { findings, suppressed };
}

/** Findings serious enough to act on in `block` mode. */
export function blocking(findings: Finding[], config: Config): Finding[] {
  return findings.filter((f) => {
    if (f.ruleId === "high-entropy-string") return config.entropy.action === "block";
    return f.confidence !== "low";
  });
}
