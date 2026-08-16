/**
 * MCP proxy.
 *
 * An MCP server sits at the end of a pipe the agent hooks never see. Tool
 * arguments go straight from the model to the server, and results come straight
 * back — so a filesystem server reading `.env`, or a database server handed a
 * connection string, leaks past every other guard in this project. Nothing else
 * in this category covers it.
 *
 * The proxy speaks stdio, spawning the real server as a child and relaying
 * newline-delimited JSON-RPC in both directions:
 *
 *   secretgate mcp-proxy -- npx -y @modelcontextprotocol/server-filesystem /srv
 *
 * stdio rather than HTTP quite deliberately. A URL-based proxy would put a
 * network client inside the one part of the codebase that promises never to
 * make a network call, and the promise is worth more than the transport.
 *
 * Outbound (agent -> server) arguments are redacted. Inbound (server -> agent)
 * results are scanned too, because a server that reads a file for you will
 * happily read a credentials file, and that response is headed for the model.
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { loadConfig } from "../config/index.js";
import { scan, blocking } from "../core/scan.js";
import { getVault } from "../core/redact.js";
import { VAULT_PATH } from "../core/vault-store.js";
import { recordBeat } from "../core/heartbeat.js";
import type { Config } from "../core/types.js";

interface JsonRpc {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
  result?: unknown;
  error?: unknown;
}

/**
 * Walks a JSON-RPC value and redacts every string in it, in place.
 *
 * Recursive rather than targeted at `params.arguments` because MCP servers put
 * arguments wherever their schema likes, and a guard that only checks the
 * documented location misses the interesting cases.
 */
function redactDeep(value: unknown, config: Config, counter: { n: number }, depth = 0): unknown {
  if (depth > 24) return value;

  if (typeof value === "string") {
    const findings = blocking(scan(value, config).findings, config);
    if (findings.length === 0) return value;
    const vault = getVault(config.vault.persist ? VAULT_PATH : undefined);
    counter.n += findings.length;
    return vault.redact(value, findings).text;
  }

  if (Array.isArray(value)) {
    return value.map((v) => redactDeep(v, config, counter, depth + 1));
  }

  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactDeep(v, config, counter, depth + 1);
    }
    return out;
  }

  return value;
}

export async function runMcpProxy(argv: string[]): Promise<number> {
  if (argv.length === 0) {
    process.stderr.write(
      "secretgate: mcp-proxy needs a server to run\n\n" +
        "  secretgate mcp-proxy -- npx -y @modelcontextprotocol/server-filesystem /srv\n",
    );
    return 2;
  }

  const config = loadConfig();
  recordBeat("mcp-proxy", "start");

  const [command, ...args] = argv;
  // spawn with an argument array, never a shell string: these values come from
  // a config file the agent can influence.
  const child = spawn(command!, args, { stdio: ["pipe", "pipe", "inherit"] });

  child.on("error", (err) => {
    process.stderr.write(`secretgate: could not start "${command}": ${err.message}\n`);
    process.exit(2);
  });

  /**
   * A proxy that crashes takes the agent's MCP server down with it, so every
   * write has to survive the far end going away. The server exiting while the
   * agent is still sending is entirely normal — it is how a server signals it
   * is done — and an unhandled EPIPE turns that into a stack trace.
   */
  let childAlive = true;
  child.stdin.on("error", () => {
    childAlive = false;
  });
  process.stdout.on("error", () => {
    /* the agent hung up; nothing useful left to do */
  });

  function toChild(line: string): void {
    if (!childAlive || child.stdin.destroyed || !child.stdin.writable) return;
    try {
      child.stdin.write(`${line}\n`);
    } catch {
      childAlive = false;
    }
  }

  function toAgent(line: string): void {
    try {
      process.stdout.write(`${line}\n`);
    } catch {
      /* agent closed the pipe */
    }
  }

  // agent -> server
  const fromAgent = createInterface({ input: process.stdin, crlfDelay: Infinity });
  fromAgent.on("line", (line) => {
    if (!line.trim()) return;
    let message: JsonRpc;
    try {
      message = JSON.parse(line) as JsonRpc;
    } catch {
      // Not JSON-RPC we understand. Pass it through untouched rather than
      // breaking a protocol we only partly model.
      toChild(line);
      return;
    }

    const counter = { n: 0 };
    const guarded = message.params ? { ...message, params: redactDeep(message.params, config, counter) as Record<string, unknown> } : message;
    if (counter.n > 0) {
      recordBeat("mcp-proxy", "redacted-request");
      process.stderr.write(`secretgate: redacted ${counter.n} credential(s) from ${message.method ?? "a request"}\n`);
    }
    toChild(JSON.stringify(guarded));
  });

  fromAgent.on("close", () => {
    if (childAlive && !child.stdin.destroyed) {
      try {
        child.stdin.end();
      } catch {
        /* already gone */
      }
    }
  });

  child.on("close", () => {
    childAlive = false;
    fromAgent.close();
  });

  // server -> agent
  const fromServer = createInterface({ input: child.stdout, crlfDelay: Infinity });
  fromServer.on("line", (line) => {
    if (!line.trim()) return;
    let message: JsonRpc;
    try {
      message = JSON.parse(line) as JsonRpc;
    } catch {
      toAgent(line);
      return;
    }

    const counter = { n: 0 };
    const guarded = message.result !== undefined ? { ...message, result: redactDeep(message.result, config, counter) } : message;
    if (counter.n > 0) {
      recordBeat("mcp-proxy", "redacted-response");
      process.stderr.write(`secretgate: redacted ${counter.n} credential(s) from a server response\n`);
    }
    toAgent(JSON.stringify(guarded));
  });

  return new Promise<number>((resolve) => {
    child.on("close", (code) => resolve(code ?? 0));
  });
}

export { redactDeep };
