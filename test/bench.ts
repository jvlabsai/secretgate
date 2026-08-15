/**
 * Precision / recall / F1 against test/corpus.
 *
 * Scoring is at the level of "would this have stopped or redacted something",
 * because that is the only thing a developer actually experiences. Low-
 * confidence entropy hints are excluded — they never block by default, so
 * counting them would flatter precision on a signal users do not feel.
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scan, blocking } from "../src/core/scan.js";
import { defaultConfig } from "../src/config/index.js";

const HERE = dirname(fileURLToPath(import.meta.url));
// The corpus itself is generated, not committed — see scripts/gen-corpus.ts.
// The scores are committed, so a regression shows up as a diff in review.
const CORPUS = join(HERE, "corpus");
const SCORES = join(HERE, "scores.json");

interface TruePositive { id: string; provider: string; secret: string; text: string }
interface Negative { id: string; why: string; text: string }
interface MixedSample { id: string; text: string; secrets: string[] }

const truePositives: TruePositive[] = JSON.parse(readFileSync(join(CORPUS, "true-positives.json"), "utf8"));
const negatives: Negative[] = JSON.parse(readFileSync(join(CORPUS, "hard-negatives.json"), "utf8"));
const mixed: MixedSample[] = JSON.parse(readFileSync(join(CORPUS, "mixed.json"), "utf8"));

const config = defaultConfig();

let tp = 0;
let fp = 0;
let fn = 0;
const missed: string[] = [];
const spurious: string[] = [];

function found(text: string): string[] {
  return blocking(scan(text, config).findings, config).map((f) => f.match);
}

/** A hit counts if the flagged span and the expected secret contain each other. */
function covers(hit: string, expected: string): boolean {
  return hit.includes(expected) || expected.includes(hit);
}

for (const sample of truePositives) {
  const hits = found(sample.text);
  if (hits.some((h) => covers(h, sample.secret))) {
    tp++;
    // Extra flags beyond the expected secret are still false positives.
    const extra = hits.filter((h) => !covers(h, sample.secret));
    if (extra.length > 0) {
      fp += extra.length;
      spurious.push(`${sample.id} (extra) -> ${extra.map((h) => h.slice(0, 40)).join(" | ")}`);
    }
  } else {
    fn++;
    missed.push(`${sample.id} (${sample.provider}): ${sample.secret.slice(0, 44)}`);
  }
}

for (const sample of negatives) {
  const hits = found(sample.text);
  if (hits.length > 0) {
    fp += hits.length;
    spurious.push(`${sample.id} [${sample.why}] -> ${hits.map((h) => h.slice(0, 40)).join(" | ")}`);
  }
}

for (const sample of mixed) {
  const hits = found(sample.text);
  const claimed = new Set<string>();
  for (const expected of sample.secrets) {
    const hit = hits.find((h) => covers(h, expected));
    if (hit) {
      tp++;
      claimed.add(hit);
    } else {
      fn++;
      missed.push(`${sample.id}: ${expected.slice(0, 44)}`);
    }
  }
  const extra = hits.filter((h) => !claimed.has(h));
  if (extra.length > 0) {
    fp += extra.length;
    spurious.push(`${sample.id} -> ${extra.map((h) => h.slice(0, 40)).join(" | ")}`);
  }
}

const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

// --- latency budget -------------------------------------------------------

const prompt = `${mixed.map((m) => m.text).join("\n")}\n`.slice(0, 10_240);
for (let i = 0; i < 50; i++) scan(prompt, config); // warm up the JIT
const samples: number[] = [];
for (let i = 0; i < 300; i++) {
  const t0 = process.hrtime.bigint();
  scan(prompt, config);
  samples.push(Number(process.hrtime.bigint() - t0) / 1e6);
}
samples.sort((a, b) => a - b);
const p50 = samples[Math.floor(samples.length * 0.5)]!;
const p99 = samples[Math.floor(samples.length * 0.99)]!;

// --- report ---------------------------------------------------------------

const pct = (n: number) => (n * 100).toFixed(2).padStart(6);

console.log("");
console.log(`corpus     ${truePositives.length} true positives  ${negatives.length} hard negatives  ${mixed.length} mixed`);
console.log(`counts     tp=${tp}  fp=${fp}  fn=${fn}`);
console.log("");
console.log(`precision  ${pct(precision)}%`);
console.log(`recall     ${pct(recall)}%`);
console.log(`f1         ${pct(f1)}%`);
console.log("");
console.log(`latency    p50 ${p50.toFixed(2)}ms   p99 ${p99.toFixed(2)}ms   (10KB prompt, budget 50ms)`);

if (missed.length) {
  console.log(`\nmissed (${missed.length}):`);
  for (const m of missed.slice(0, 25)) console.log(`  - ${m}`);
  if (missed.length > 25) console.log(`  ... ${missed.length - 25} more`);
}
if (spurious.length) {
  console.log(`\nfalse positives (${spurious.length}):`);
  for (const s of spurious.slice(0, 25)) console.log(`  - ${s}`);
  if (spurious.length > 25) console.log(`  ... ${spurious.length - 25} more`);
}

// --- diff versus last committed scores ------------------------------------

const current = {
  precision: Number(precision.toFixed(4)),
  recall: Number(recall.toFixed(4)),
  f1: Number(f1.toFixed(4)),
  tp,
  fp,
  fn,
};

if (existsSync(SCORES)) {
  const previous = JSON.parse(readFileSync(SCORES, "utf8"));
  const delta = (key: "precision" | "recall" | "f1") => {
    const d = current[key] - previous[key];
    if (Math.abs(d) < 0.0001) return "  =";
    return `${d > 0 ? "+" : ""}${(d * 100).toFixed(2)}pp`;
  };
  console.log("\nvs committed scores:");
  console.log(`  precision ${delta("precision")}   recall ${delta("recall")}   f1 ${delta("f1")}`);
}

if (process.argv.includes("--update")) {
  writeFileSync(SCORES, `${JSON.stringify(current, null, 2)}\n`);
  console.log(`\nwrote ${SCORES}`);
}

// --- gates ----------------------------------------------------------------

const PRECISION_FLOOR = 0.98;
const RECALL_FLOOR = 0.9;
const P99_BUDGET_MS = 50;

let failed = false;
if (precision < PRECISION_FLOOR) {
  console.error(`\nFAIL precision ${(precision * 100).toFixed(2)}% is below the ${PRECISION_FLOOR * 100}% floor`);
  failed = true;
}
if (recall < RECALL_FLOOR) {
  console.error(`FAIL recall ${(recall * 100).toFixed(2)}% is below the ${RECALL_FLOOR * 100}% floor`);
  failed = true;
}
if (p99 > P99_BUDGET_MS) {
  console.error(`FAIL p99 ${p99.toFixed(2)}ms exceeds the ${P99_BUDGET_MS}ms budget`);
  failed = true;
}

console.log("");
process.exit(failed ? 1 : 0);
