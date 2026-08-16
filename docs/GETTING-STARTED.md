# Getting started

A worked example, start to finish. Copy and paste it — it runs on a throwaway
project, so nothing you care about is touched.

---

## First: does secretgate work with your agent?

This decides everything else, so answer it before installing.

| Your agent | What protects you | How |
|---|---|---|
| **Claude Code** | Hooks | `secretgate init` |
| **Cursor** | Hooks (beta, unverified) | `secretgate init` |
| **Gemini / Antigravity, Copilot, Codex, Windsurf, Aider, anything else** | **`lock` / `unlock`** | see [Path B](#path-b--any-other-agent) |

**Hooks only exist for Claude Code and Cursor.** A hook is code the agent itself
calls before it reads a file. If your agent has no hook API, there is nothing for
secretgate to attach to, and it cannot stop a read. That is not a bug we are
hiding — it is a limit of how these tools work.

If you are on any other agent, skip to [Path B](#path-b--any-other-agent). It
works everywhere, because it does not need the agent's cooperation at all.

---

## Set up the example project

```bash
mkdir /tmp/sg-demo && cd /tmp/sg-demo
git init -q
npm init -y >/dev/null

printf 'node_modules\n.env*\n' > .gitignore

cat > .env.local <<'EOF'
NODE_ENV=development
LINKEDIN_ACCESS_TOKEN="AQXd8x2mKp9…"
OPENROUTER_API_KEY=sk-or-v1-9f2c4e6a8b0d…
EOF
```

Install:

```bash
npm install -g secretgate
```

---

## Path A — Claude Code or Cursor

### Step 1: wire the hooks

```bash
secretgate init
```

It edits your agent's settings file, backs it up first, and prints what it
changed. `secretgate uninstall` puts everything back exactly.

### Step 2: prove it is actually running

This step is not optional. Configured and working are different states.

Use your agent for a minute — ask it anything — then:

```bash
secretgate doctor
```

```
  PROTECTED  a hook has fired, so secretgate is in the path

  agents
    Claude Code    firing, last seen 12s ago
      UserPromptSubmit   12s ago   4x
```

If it says **`NOT PROTECTED`**, the hook is not being called and you are not
covered. Use Path B instead.

### Step 3: try to make the agent read your secrets

Ask it, in the agent:

> can you read .env.local and show me the token?

It will be refused. The denial happens on the *path*, before the file is opened,
so it does not matter what is inside.

```
secretgate: /tmp/sg-demo/.env.local holds credentials. Read the key names
from a .env.example instead.
```

`.env.example` is still allowed, because that is what the agent actually needs —
the key names, not the values.

---

## Path B — any other agent

Your agent has no hook. So instead of stopping the read, we make the read
worthless: `.env` is rewritten to hold placeholders while you work.

### Step 1: lock

```bash
secretgate lock .
```

```
  + .env.local    2 value(s) replaced with placeholders

locked  the agent now reads placeholders, not credentials
  real values are in ~/.secretgate/vault.json, outside this project
```

Look at the file now:

```bash
cat .env.local
```

```
NODE_ENV=development
LINKEDIN_ACCESS_TOKEN="SECRETGATE_GENERIC_KEY_9260"
OPENROUTER_API_KEY=SECRETGATE_OPENAI_KEY_D11C
```

**This is the answer to "the file is in the same folder, how can it not read
it?"** The agent can read it. There is simply nothing in it. The real values
moved to `~/.secretgate/`, which is outside the project folder your agent has
access to.

Key names survive on purpose, so the agent can still understand the shape of
your config.

### Step 2: let the agent work

Do whatever you were going to do. Ask it to read `.env.local` if you like — it
gets placeholders.

### Step 3: unlock when you are done

```bash
secretgate unlock .
```

```
  + .env.local    2 value(s) restored
```

The file is byte-for-byte what it was before.

### The trade-off, stated plainly

**Your app will not run while locked.** The environment holds placeholders, so
anything that actually calls LinkedIn or OpenRouter will fail. Lock while an
agent is working; unlock to run your app.

If you forget and lose the vault, a backup is written to `~/.secretgate/backups/`
*before* anything is modified, and `unlock` falls back to it automatically.

---

## Checking a project for hardcoded secrets

Separate from the agent question: are there credentials sitting in your source?

```bash
secretgate scan .
```

Two kinds of result, and they mean different things.

**Secrets in source code** — a real problem:

```
  ! src/config.ts:12  aws-access-key-id (aws)

1 credential(s) hardcoded in 24 scanned file(s)
  secretgate fix .            move them into .env
```

**Secrets in `.env`** — expected, and only worth knowing about if git can see it:

```
  secrets files
    ok      .env.local    2 credential(s), ignored by git
    Credentials belong here. Nothing to do.
```

If instead it says `EXPOSED`, that is real and urgent:

```
    EXPOSED .env.local    2 credential(s) and NOT ignored by git
    echo '.env.local' >> .gitignore
```

### Moving hardcoded secrets out of source

```bash
secretgate fix .            # dry run, shows what it would change
secretgate fix . --write    # apply
```

```diff
- const apiKey = "AKIA4KTNQ7VZL2WXMP3D";
+ const apiKey = process.env.API_KEY;
```

The value goes to `.env`, the key name to `.env.example`, and required imports
are added for Python and Go.

---

## Stopping secrets reaching git

```bash
secretgate init
```

also installs a pre-commit hook. Try it:

```bash
echo 'const k = "AKIA4KTNQ7VZL2WXMP3D";' > leak.js
git add leak.js && git commit -m "test"
```

```
secretgate: 1 credential(s) in staged changes
  leak.js:1  aws-access-key-id (aws)
```

The commit is blocked. `git commit --no-verify` overrides it if you are sure.

---

## Clean up the example

```bash
cd / && rm -rf /tmp/sg-demo
secretgate vault --clear
```

---

## Cheat sheet

```bash
secretgate init             # wire hooks (Claude Code / Cursor only)
secretgate doctor           # PROTECTED or NOT PROTECTED — check this
secretgate lock .           # any agent: blank out .env while you work
secretgate unlock .         # put the values back
secretgate scan .           # find secrets in source, check .env is ignored
secretgate fix . --write    # move hardcoded secrets into .env
secretgate uninstall        # undo everything init did
```

## Still stuck?

Open an issue with the output of `secretgate doctor` — it says which agents were
detected, whether hooks are firing, and what config is in effect, which is
usually enough to see what is wrong.
