import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { STATE_DIR } from "./vault-store.js";

/**
 * Proof that a hook is actually being invoked.
 *
 * `doctor` could previously only tell you that a hook was *configured* — that
 * the right line existed in the right JSON file. That is a different claim from
 * "the agent is calling it", and the gap between them is the worst failure this
 * project has. Agent hook APIs move; an event gets renamed, the hook silently
 * stops firing, and you carry on pasting .env files into prompts believing you
 * are covered. A guardrail that quietly stopped working is worse than none,
 * because you stopped watching for the thing it was supposed to catch.
 *
 * So every hook invocation stamps a file, and `doctor` reports how long ago
 * each event was last seen. Nothing about the content is recorded — event name,
 * timestamp, count. That is enough to answer "is this thing on?" and nothing
 * more, which is the only question being asked.
 */

export const HEARTBEAT_PATH = join(STATE_DIR, "last-seen.json");

export interface EventBeat {
  /** Epoch millis of the most recent invocation. */
  at: number;
  count: number;
}

export interface Heartbeat {
  version: 1;
  /** agent id -> event name -> beat */
  agents: Record<string, Record<string, EventBeat>>;
}

function empty(): Heartbeat {
  return { version: 1, agents: {} };
}

export function readHeartbeat(path: string = HEARTBEAT_PATH): Heartbeat {
  if (!existsSync(path)) return empty();
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as Heartbeat;
    if (parsed?.version !== 1 || typeof parsed.agents !== "object" || parsed.agents === null) return empty();
    return parsed;
  } catch {
    return empty();
  }
}

/**
 * Called on every hook invocation, so it has to be cheap and must never throw —
 * a guardrail that crashes the agent because it could not write a timestamp
 * has its priorities backwards.
 */
export function recordBeat(agent: string, event: string, path: string = HEARTBEAT_PATH): void {
  try {
    const beat = readHeartbeat(path);
    const events = (beat.agents[agent] ??= {});
    const existing = events[event];
    events[event] = { at: Date.now(), count: (existing?.count ?? 0) + 1 };

    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify(beat), { mode: 0o600 });
  } catch {
    /* best effort, never fatal */
  }
}

export function clearHeartbeat(path: string = HEARTBEAT_PATH): boolean {
  if (!existsSync(path)) return false;
  rmSync(path, { force: true });
  return true;
}

/** "4 minutes ago", for doctor output. */
export function humanAge(at: number, now: number = Date.now()): string {
  const seconds = Math.max(0, Math.round((now - at) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export interface AgentHealth {
  agent: string;
  events: { event: string; at: number; count: number }[];
  lastSeen: number | undefined;
}

export function agentHealth(beat: Heartbeat): AgentHealth[] {
  return Object.entries(beat.agents).map(([agent, events]) => {
    const list = Object.entries(events).map(([event, b]) => ({ event, at: b.at, count: b.count }));
    list.sort((a, b) => b.at - a.at);
    return { agent, events: list, lastSeen: list[0]?.at };
  });
}
