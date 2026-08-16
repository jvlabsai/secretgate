import type { Confidence, Rule } from "../types.js";

/**
 * User-defined rules from secretgate.yml.
 *
 * Every organisation of any size has credential formats nobody outside it has
 * heard of — internal service tokens, a bespoke JWT issuer, a legacy key
 * format that predates the current platform team. Without a way to express
 * those, secretgate is a personal tool that a company cannot actually roll out,
 * which is a strange place for something whose whole pitch is protecting
 * company credentials.
 */

export interface CustomRuleSpec {
  id?: unknown;
  provider?: unknown;
  description?: unknown;
  regex?: unknown;
  flags?: unknown;
  prefilter?: unknown;
  group?: unknown;
  entropyMin?: unknown;
  confidence?: unknown;
}

export interface CustomRuleResult {
  rules: Rule[];
  /** Problems worth telling the user about, rather than failing silently. */
  problems: string[];
}

const VALID_CONFIDENCE = new Set(["high", "medium", "low"]);

/**
 * A regex from a config file is attacker-adjacent input in the sense that
 * matters here: a careless nested quantifier will hang the scanner on every
 * prompt, and the developer will blame the agent. Compile-and-time it once at
 * load rather than discovering it in the hot path.
 */
function compilesQuickly(regex: RegExp): boolean {
  // A string engineered to make classic catastrophic backtracking show itself.
  const bait = `${"a".repeat(60)}!${"b".repeat(60)}`;
  const started = process.hrtime.bigint();
  try {
    regex.lastIndex = 0;
    regex.test(bait);
  } catch {
    return false;
  }
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
  return elapsedMs < 50;
}

export function buildCustomRules(specs: unknown): CustomRuleResult {
  const rules: Rule[] = [];
  const problems: string[] = [];

  if (specs === undefined || specs === null) return { rules, problems };
  if (!Array.isArray(specs)) {
    return { rules, problems: ["rules.custom must be a list"] };
  }

  specs.forEach((raw, index) => {
    const spec = (raw ?? {}) as CustomRuleSpec;
    const where = `rules.custom[${index}]`;

    if (typeof spec.id !== "string" || !spec.id.trim()) {
      problems.push(`${where}: needs an id`);
      return;
    }
    const id = spec.id.trim();

    if (typeof spec.regex !== "string" || !spec.regex.trim()) {
      problems.push(`${where} (${id}): needs a regex`);
      return;
    }

    // Always global — scan() relies on exec() advancing lastIndex.
    let flags = "g";
    if (typeof spec.flags === "string") {
      const extra = spec.flags.replace(/[^imsu]/g, "");
      flags = `g${extra}`;
    }

    let regex: RegExp;
    try {
      regex = new RegExp(spec.regex, flags);
    } catch (err) {
      problems.push(`${where} (${id}): regex does not compile — ${err instanceof Error ? err.message : String(err)}`);
      return;
    }

    if (!compilesQuickly(regex)) {
      problems.push(
        `${where} (${id}): regex is too slow to run safely and was skipped. ` +
          `Nested quantifiers like (a+)+ backtrack catastrophically; rewrite it to be linear.`,
      );
      return;
    }

    const confidence: Confidence = VALID_CONFIDENCE.has(String(spec.confidence))
      ? (spec.confidence as Confidence)
      : "high"; // A rule someone wrote by hand for their own format is not a guess.

    rules.push({
      id,
      provider: typeof spec.provider === "string" && spec.provider.trim() ? spec.provider.trim() : "custom",
      description: typeof spec.description === "string" && spec.description.trim() ? spec.description.trim() : id,
      regex,
      prefilter: Array.isArray(spec.prefilter) ? spec.prefilter.map(String).filter(Boolean) : undefined,
      group: typeof spec.group === "number" && Number.isInteger(spec.group) && spec.group >= 0 ? spec.group : undefined,
      entropyMin: typeof spec.entropyMin === "number" ? spec.entropyMin : undefined,
      confidence,
    });
  });

  return { rules, problems };
}
