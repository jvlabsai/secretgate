import type { Rule } from "../types.js";
import { cloudRules } from "./cloud.js";
import { vcsRules } from "./vcs.js";
import { aiRules } from "./ai.js";
import { saasRules } from "./saas.js";
import { keyRules } from "./keys.js";
import { dbRules } from "./db.js";
import { genericRules } from "./generic.js";

/**
 * Hand-maintained packs. `scripts/sync-rules.ts` can additionally emit
 * `generated.ts` from an upstream gitleaks.toml; that file is optional and
 * absent from a fresh clone, so it is loaded defensively at build time rather
 * than imported here.
 */
export const allRules: Rule[] = [
  ...cloudRules,
  ...vcsRules,
  ...aiRules,
  ...saasRules,
  ...keyRules,
  ...dbRules,
  ...genericRules,
];

const seen = new Set<string>();
for (const r of allRules) {
  if (seen.has(r.id)) throw new Error(`duplicate rule id: ${r.id}`);
  seen.add(r.id);
  if (!r.regex.global) throw new Error(`rule ${r.id} regex must have the g flag`);
}

/**
 * Custom rules run first so a user's own definition wins the dedupe against a
 * built-in that happens to overlap — they know their credential formats better
 * than we do, and the placeholder should name their provider, not ours.
 */
export function rulesFor(disabled: string[], custom: Rule[] = []): Rule[] {
  const combined = custom.length > 0 ? [...custom, ...allRules] : allRules;
  if (disabled.length === 0) return combined;
  const drop = new Set(disabled);
  return combined.filter((r) => !drop.has(r.id) && !drop.has(r.provider));
}

export { cloudRules, vcsRules, aiRules, saasRules, keyRules, dbRules, genericRules };
