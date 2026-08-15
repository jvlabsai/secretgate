# secretgate

**Keep credentials out of your AI coding agent — without breaking your flow.**

You paste a stack trace into Claude Code. It has your database URL in it. That
URL is now in someone else's logs, and rotating it is your afternoon.

secretgate sits between you and the agent. It finds the credential, swaps it for
a stable placeholder, lets the agent do its work, and puts the real value back
locally before anything touches disk. The model never sees the secret. You never
lose your train of thought.

```
you type                                                the agent sees
─────────────────────────────────────────  ───────────────────────────────────────────
DATABASE_URL=postgres://svc:hunter2@db/app  DATABASE_URL=postgres://svc:SECRETGATE_DATABASE_PASSWORD_4837@db/app
AWS_ACCESS_KEY_ID=AKIA4KTNQ7VZL2W…          AWS_ACCESS_KEY_ID=SECRETGATE_AWS_KEY_6B8A
GITHUB_TOKEN=ghp_9fK2mQ7xLp4RtY8v…          GITHUB_TOKEN=SECRETGATE_GITHUB_TOKEN_E36B
```

The agent can still reason about the code — it knows that's an AWS key and a
Postgres password. It just cannot read them. When it writes a file back, the
real values return.

```bash
npx secretgate init
```

That detects which agents you have installed, wires every hook, and prints what
it did. Roughly fifteen seconds. `secretgate uninstall` puts everything back.

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
secretgate filter            stdin -> stdout, redacted (--rehydrate to reverse)
secretgate baseline          accept every current finding
secretgate doctor            check what is wired up and what is not
secretgate uninstall         restore every config file we touched
secretgate rules             list detection rules
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

The vault lives in memory, is wiped on exit, and refuses to render its contents
through `JSON.stringify`, `console.log`, `util.inspect` or a stack trace. There
is a test that greps every rendering path for a known secret.

## What is not built yet

Being straight about it rather than letting you find out:

- **Cursor, Codex, Copilot, Windsurf, Aider** — detected by `init`, which tells
  you plainly that there is no adapter yet. Use `secretgate filter`. Their hook
  APIs move quickly and shipping an adapter I cannot test against the current
  version would be worse than shipping none.
- **MCP proxy mode** — designed, not written. A real leak path, and next up.
- **Encrypted vault persistence** — the config flag exists and is honoured as
  "off". Cross-session placeholder stability is not implemented.
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
