# secretgate

[![ci](https://github.com/jvlabsai/secretgate/actions/workflows/ci.yml/badge.svg)](https://github.com/jvlabsai/secretgate/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/secretgate)](https://www.npmjs.com/package/secretgate)
[![licence](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)
[![dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](package.json)
[![precision](https://img.shields.io/badge/corpus%20precision-100%25-brightgreen)](#current-corpus-results)

**Keep credentials out of your AI coding agent — without breaking your flow.**

You paste a stack trace into Claude Code. It has your database URL in it. That
URL is now in someone else's logs, and rotating it is your afternoon.

secretgate sits between you and the agent. It finds the credential, swaps it for
a stable placeholder, lets the agent do its work, and puts the real value back
locally before anything touches disk. The model never sees the secret. You never
lose your train of thought.

![secretgate redacting a .env, the agent editing it, and the real values being restored](docs/demo.gif)

Note what survived that round trip: the agent's edit (`db.internal` became
`db.prod.internal`) is kept, and all three credentials come back. The agent
could still reason about the file — it knew that was an AWS key and a Postgres
password — it just could not read either one.

---

## First — which agent are you using?

This decides how you use secretgate, so answer it before installing anything.

| Your agent | What protects you |
|---|---|
| **Claude Code** | Hooks — `secretgate init` |
| **Cursor** | Hooks, beta and unverified — `secretgate init` |
| **Gemini / Antigravity, Copilot, Codex, Windsurf, Aider, everything else** | **`secretgate lock`** — hooks cannot work |

A hook is code your agent calls before it reads a file. **Only Claude Code and
Cursor expose one.** For every other agent there is nothing for secretgate to
attach to, so it cannot intercept a read — and running `init` will not protect
you, however successful it looks.

That is a limit of how those tools work, not something being worked around
quietly. For any unsupported agent, use `lock`, which needs no cooperation from
the agent at all:

```bash
secretgate lock .     # .env values become placeholders; real ones move out of the project
# ... let the agent do its work ...
secretgate unlock .   # values come back, byte for byte
```

**`secretgate doctor` tells you which situation you are in.** If it says
`NOT PROTECTED`, hooks are not firing and `lock` is your answer.

New here? [**docs/GETTING-STARTED.md**](docs/GETTING-STARTED.md) is a worked
example you can paste into a terminal.

---

## Quickstart

Three commands. About a minute.

### 1. Install and wire it up

```bash
npm install -g secretgate
secretgate init
```

`init` finds the agents you already have, adds the hooks, and prints what it
changed. It backs up every file it touches, and `secretgate uninstall` puts them
all back exactly as they were.

```
secretgate init

  + Claude Code    wired (backup: ~/.claude/settings.json.secretgate-backup-…)
  + git pre-commit hook created
  + secretgate.yml created

  done — 2 hook(s) wired
```

### 2. Check it is actually running

Use your agent normally for a minute, then:

```bash
secretgate doctor
```

```
agents
  Claude Code    firing, last seen 12s ago
    UserPromptSubmit   12s ago   4x
    PreToolUse         12s ago   9x
```

**`firing` is the word that matters.** If it says `wired, but has never fired`,
the hook is configured but your agent is not calling it — so you are not
protected. Nothing else in the output means anything until that says `firing`.

### 3. That's it

There is no step 3. From here on it works on its own:

- Your agent is refused when it tries to read `.env`, `~/.aws/credentials`,
  `id_rsa`, or run `cat .env` / `printenv`.
- Any credential that reaches a prompt anyway is swapped for a placeholder like
  `SECRETGATE_AWS_KEY_6B8A`, and the real value is put back locally when the
  agent writes a file.
- `git commit` is blocked if you are about to commit a credential.

### Where do I put my `.env`?

Leave it exactly where it is, in the project root. Moving it achieves nothing —
the protection is not that the file is hidden, it is that the *read* is
intercepted. `.env` and `.env.example` can sit side by side in the same folder:
the agent is refused the first and allowed the second.

### Try it without installing anything

If you would rather see it work before wiring it into your editor:

```bash
printf 'AWS_ACCESS_KEY_ID=AKIA4KTNQ7VZL2WXMP3D\n' > /tmp/demo.env
npx secretgate filter < /tmp/demo.env
```

```
AWS_ACCESS_KEY_ID=SECRETGATE_AWS_KEY_6B8A
```

### Two useful extras

```bash
secretgate scan .          # find credentials already in your code
secretgate fix .           # move them into .env (dry run; add --write to apply)
```

### If your agent is not supported

Hooks only exist for **Claude Code** and **Cursor** today. For anything else
there is nothing to intercept the read, so use the pipe form
(`secretgate filter`) or rely on the git pre-commit hook. See
[what is not built yet](#what-is-not-built-yet).

---

## Why this and not the alternatives

| | secretgate | GitGuardian ggshield | Cycode AI Guardrails | agent-guard |
|---|---|---|---|---|
| Account required | no | yes | yes | no |
| Works offline | yes, enforced in CI | no | no | yes |
| Telemetry | none | yes | yes | none |
| Redact and restore | **yes** | block only | block only | block only |
| Agents covered | Claude Code, + any tool via stdin filter | several | several | 2 |
| Live-credential verification | no | **yes** | **yes** | no |
| Org policy / dashboards / incident workflow | no | **yes** | **yes** | no |
| Rule count | 55 hand-written (+ gitleaks import) | thousands | thousands | ~20 |
| Runtime dependencies | **zero** | many | many | none (shell) |
| Licence | Apache-2.0 | commercial | commercial | MIT |

**Be honest about the trade:** if you need to know whether a leaked key is
*still live*, need an audit trail for a compliance team, or need to push policy
to 500 engineers, buy GitGuardian or Cycode. Those are real capabilities we do
not have and are not building. secretgate is for the individual developer or
small team who wants a guardrail that works on a plane, requires no signup, and
does not turn every secret into a hard stop.

## Precision over recall, deliberately

A scanner that cries wolf gets uninstalled, and an uninstalled scanner has zero
recall. So every design decision here favours precision:

- Entropy findings **never block by default** — they warn. Entropy alone is the
  single largest source of false positives in this whole category of tool.
- Placeholder words are matched as delimiter-separated tokens, never substrings.
  Substring-matching `test` swallows roughly one real key in a thousand.
- Findings in `test/`, `fixtures/` and `*.test.*` are downgraded, not dropped —
  fixtures do occasionally hold a live key.
- `secretgate baseline` hashes everything currently flagged so an existing
  codebase does not greet you with 400 findings on day one.

### Current corpus results

```
corpus     138 true positives  118 hard negatives  60 mixed prompts
precision  100.00%
recall     100.00%
latency    p99 1.2ms on a 10KB prompt (budget: 50ms)
```

**A tool scoring 100% on its own corpus is not evidence of anything** — every
scanner does. The corpus is the artifact worth reviewing, not the score.

The 118 hard negatives are hand-written and live in
[`scripts/gen-corpus.ts`](scripts/gen-corpus.ts), each one labelled with why it
is not a secret. Go read them and decide whether they look like your codebase.
CI fails below 98% precision, and `test/scores.json` is committed so any change
in detection quality shows up as a diff in review.

The corpus JSON itself is generated rather than committed (`npm run corpus`),
because it contains ~200 realistically shaped fake credentials and every push
protection scanner on earth correctly objects to them. That the fixtures trip
real scanners is a reasonable sign they are realistic.

If secretgate misses something in your codebase, or flags something that is not
a secret, open an issue with a sample — that is the most useful contribution
anyone can make here.

## Install

```bash
npm install -g secretgate    # or use npx, no install needed
secretgate init
```

Requires Node 20+. Prebuilt binaries are on the releases page for machines
without Node.

**Zero runtime dependencies.** `npm install secretgate` pulls nothing else in —
the whole tool is one 66 KB file. For something that handles credentials, an
empty dependency tree is a feature: there is no supply chain to audit and
nothing that can change under you. The YAML config is read by a ~90-line parser
covering exactly the documented schema rather than a general-purpose library.

## Commands

```
secretgate init              detect installed agents and wire every hook
secretgate scan [path]       scan a file or directory
secretgate fix [path]        move hardcoded secrets into .env (--write to apply)
secretgate filter            stdin -> stdout, redacted (--rehydrate to reverse)
secretgate baseline          accept every current finding
secretgate doctor            check what is wired up and whether it is firing
secretgate uninstall         restore every config file we touched
secretgate rules             list detection rules
secretgate vault             inspect the placeholder store (--clear to wipe)
secretgate mcp-proxy -- <cmd>  guard an MCP server's stdio in both directions
```

### `fix` — because finding it is only half the job

Every other tool in this space stops at "there is a secret on line 12" and
leaves you to do the actual work. That is the moment people reach for a pragma
instead, and a suppressed finding is a secret that is still in the repo.

```bash
secretgate fix .            # dry run, shows the diff
secretgate fix . --write    # apply it
```

```diff
- databaseUrl: "postgres://svc:h4Kd9wQz2Lp8Nx7@db.internal:5432/orders",
+ databaseUrl: process.env.DATABASE_URL,
```

The value goes into `.env` at the project root, the key goes into
`.env.example` with an empty value, and you get a warning if `.env` is not
gitignored — moving a secret into a committed file is not an improvement.

Note it moves the *whole* string literal. Replacing only the matched password
would produce `"postgres://svc:process.env.X@host/db"`, which still compiles and
silently never resolves. Template literals with `${interpolation}` and values
that are not inside a string are reported and left alone rather than guessed at.

JS/TS, Python, Ruby, Go, PHP and shell.

### `doctor` — configured is not the same as working

```
agents
  Claude Code    wired, last fired 4m ago
    UserPromptSubmit   4m ago    31x
    PreToolUse         4m ago    112x
  Cursor         wired, but has never fired — start a session and check again
```

Hook APIs move. An event gets renamed, your hook stops being called, and you
keep pasting `.env` files into prompts believing you are covered. Every hook
invocation stamps a local file with the event name and timestamp — no content —
so `doctor` can tell you the difference between "the config looks right" and
"this is actually running".

## Custom rules

Every company has credential formats nobody outside it has heard of. Without
these, secretgate is a tool an individual can use and a team cannot.

```yaml
rules:
  custom:
    - id: acme-service-token
      provider: acme
      description: ACME internal service token
      regex: "ACME-SVC-[A-Z0-9]{32}"
      prefilter:
        - "ACME-SVC-"
      confidence: high
```

Rules that fail to compile are reported rather than silently dropped, and one
that backtracks catastrophically is rejected outright — left in, it would hang
the scanner on every prompt and you would blame the agent.

## MCP servers

An MCP server sits at the end of a pipe the agent hooks never see. Tool
arguments go straight from the model to the server and results come straight
back, so a filesystem server reading `.env` leaks past everything else here.

```bash
secretgate mcp-proxy -- npx -y @modelcontextprotocol/server-filesystem /srv
```

Relays stdio JSON-RPC in both directions, redacting arguments on the way out and
results on the way back. stdio rather than HTTP deliberately: a network client
would have to live in the one part of this codebase that promises never to make
a network call.

## pre-commit

```yaml
repos:
  - repo: https://github.com/jvlabsai/secretgate
    rev: v0.1.0
    hooks:
      - id: secretgate
```

The filter is the universal escape hatch — it makes secretgate work with tools
nobody has written an adapter for:

```bash
cat prompt.txt | secretgate filter | your-agent
```

Exit code 0 clean or redacted, 2 blocked.

## Configuration

`secretgate.yml`, found by walking up from the working directory:

```yaml
mode: redact        # redact | block | warn

entropy:
  enabled: true
  threshold: 4.0
  action: warn      # blocking on entropy alone is how a scanner gets uninstalled

rules:
  disable: []       # rule ids or whole providers

allowlist:
  paths: ["**/fixtures/**"]
  patterns: ["EXAMPLE_.*"]

vault:
  persist: false    # in-memory only, so a crash cannot leave secrets on disk
```

Per-line opt-out, in any comment syntax:

```python
API_KEY = "AKIA4KTNQ7VZL2W…"  # secretgate:allow
```

## How the vault works

Outbound, each finding becomes `SECRETGATE_<PROVIDER>_<KIND>_<HMAC4>`:

- **Stable within a session** — the same secret always maps to the same
  placeholder, so a multi-turn conversation stays coherent for the model.
- **Uppercase and underscore only** — no shell, JSON, YAML or language parser
  will quote, escape or reflow it.
- **Suffix is an HMAC** under a per-session random key, so nothing about the
  secret leaks through the placeholder.

Inbound, placeholders are swapped back before bytes reach disk. Anything that
looks like ours but is not an exact match is **reported and left alone**. If the
agent truncated or reformatted a placeholder, or invented one, secretgate warns
rather than substituting — writing a real credential into a location nobody
chose is worse than an edit that fails.

The vault refuses to render its contents through `JSON.stringify`,
`console.log`, `util.inspect` or a stack trace, and there is a test that greps
every rendering path for a known secret.

**Redact mode stores the mapping on disk**, at `~/.secretgate/vault.json`, mode
`0600`, entries expiring after 12 hours. It has to: agent hooks run one process
per event, so a purely in-memory vault has exited before the agent's edit comes
back to be restored. Inspect it with `secretgate vault`, wipe it with
`secretgate vault --clear`.

That is a real trade and [SECURITY.md](SECURITY.md) argues it honestly rather
than glossing it. If you would rather no secret ever touched disk, use
`mode: block`.

## What is not built yet

Being straight about it rather than letting you find out:

- **Codex, Copilot, Windsurf, Aider** — detected by `init`, which tells you
  plainly that there is no adapter yet. Use `secretgate filter` meanwhile.
- **The Cursor adapter is written but unverified against a live Cursor.** Its
  hook surface has moved more than once, so the adapter reads defensively and
  fails open. `doctor` will tell you whether it is actually firing — that is
  precisely the case the heartbeat was built for.
- **Encryption at rest for the vault** — the store is `0600` and short-lived but
  not encrypted, because a key stored beside the ciphertext is theatre. Doing it
  properly means an OS-keychain dependency, which conflicts with the zero-runtime-
  dependency guarantee. Open question, honestly flagged.
- **The gitleaks rule import** — `scripts/sync-rules.ts` works and emits a
  committed `generated.ts`, but the shipped ruleset is the 55 hand-written rules.

## Threat model

Read [SECURITY.md](SECURITY.md) before relying on this for anything serious. The
short version: **pattern-based detection is defence in depth, not an adversarial
boundary.** secretgate raises the cost of an accident. It will not stop an agent
that is actively trying to evade it, and it is not a vault, a rotation tool, or
a substitute for scoping your credentials properly.

## Contributing

The most valuable contribution is a false positive. If secretgate flags
something in your codebase that is not a secret, open an issue with a sample —
that sample goes straight into `test/corpus/hard-negatives.json` and CI keeps it
from ever regressing.

```bash
npm ci
npm test              # unit tests
npm run bench         # corpus precision/recall
npm run ci            # everything CI runs
```

## Licence

Apache-2.0. Detection rules derive in part from
[Gitleaks](https://github.com/gitleaks/gitleaks) (MIT) — see [NOTICE](NOTICE).
