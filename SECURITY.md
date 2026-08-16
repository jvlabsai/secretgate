# Security

## Reporting a vulnerability

Email **connect@jvlabs.io**. Please do not open a public issue for anything that
would let someone extract secrets from another person's machine.

Include a reproduction if you can. We will confirm receipt, and we would rather
hear about a maybe than not hear about a definitely.

## Threat model

Read this before you rely on secretgate for anything that matters.

### What secretgate is

**Defence in depth against accidents.** The overwhelmingly common failure is a
developer pasting a `.env`, a stack trace, or a config file into an agent
without thinking about what is in it. secretgate catches that class of mistake
cheaply and without breaking the workflow.

### What secretgate is not

**It is not an adversarial boundary.** Everything below is out of scope, by
design, and no amount of rule-writing changes that:

- **An agent that is actively evading it.** Pattern matching loses to anyone who
  wants it to. An agent can base64 a credential, split it across two tool calls,
  encode it in variable names, or ask you to read it aloud. If your threat model
  includes a hostile model or a prompt-injected agent, secretgate is not the
  control you need.
- **Anything that does not pass through a hook.** You typing a key into a
  terminal, an MCP server we are not proxying, an agent shelling out through a
  path the hooks do not cover, a browser extension. Hooks only see what the
  agent tells them about.
- **Credentials with no recognisable shape.** A 12-character password that looks
  like a word will not be caught, and the entropy layer deliberately will not
  block on a guess.
- **Secrets already committed.** secretgate scans what you are about to send and
  what you are about to commit. It does not rewrite history or scan your remote.

### What secretgate never does

- **No network calls, ever.** Enforced mechanically: `npm run check:no-network`
  fails the build if anything in `src/core` or `src/hooks` imports a network
  module or calls `fetch`. It runs on every CI job. This is the one promise the
  commercial alternatives cannot make, so we check it rather than assert it.
- **No telemetry, no analytics, no crash reporting.** Nothing leaves the machine.
- **No account, no licence check, no phone-home on install.**

### Where secrets live at runtime

**Redact mode writes secrets to disk. Read this section before using it.**

Every hook invocation is its own process — Claude Code runs the binary once for
`UserPromptSubmit` and again for `PostToolUse`. An in-memory-only vault has
already exited by the time the agent's edit comes back, so redaction could
remove a secret and never restore it. Making the feature work at all requires
the mapping to outlive the process that created it.

So, concretely:

- The placeholder → value mapping is written to `~/.secretgate/vault.json`
  with file mode `0600`.
- Entries expire after 12 hours and are dropped on the next load.
- `secretgate vault` shows what is stored; `secretgate vault --clear` removes
  it; `secretgate uninstall` clears it too.
- In memory it lives in a single per-process `Vault`, wiped on `exit`, `SIGINT`
  and `SIGTERM`.
- The vault refuses to serialise itself through `JSON.stringify`, `toString`,
  template interpolation or `util.inspect`, so a stray `console.log` or an error
  message cannot spill it. There is a test asserting this against every
  rendering path we could think of.

**The file is not encrypted, and that is deliberate rather than an oversight.**
Any key we could ship would have to sit beside the ciphertext, on the same disk,
under the same permissions — which buys close to nothing while inviting a
security claim we could not defend. An OS-keychain-backed key would be
genuinely better and needs a native dependency; it is on the list, not
pretended.

The narrow argument for why this is acceptable: anything able to read
`~/.secretgate/vault.json` already has your user privileges, and could equally
read `~/.aws/credentials`, your `.env`, or your shell history. The store is
short-lived and holds only what you already pasted. It does not meaningfully
widen the attack surface.

It is still a real trade. **If you would rather no secret ever touched disk,
set `mode: block`** — you lose the redact-and-restore workflow and get a hard
stop instead. Setting `vault.persist: false` also stops the writes, but then
redaction cannot restore anything and you get placeholders you cannot undo,
which is the worst of both. Use `block`.

### The baseline file

`.secretgate-baseline.json` holds **salted SHA-256 fingerprints**, never the
secrets. The salt sits next to the hashes, which is the point: it defeats
precomputed rainbow tables, not an attacker who already has both the file and a
specific value to test. Committing the baseline is expected and safe.

Note that a baseline records that you *accepted* a finding. It does not make
that credential safe — if you baseline a live production key, it is still a live
production key sitting in your repository.

### Placeholder collisions

Placeholder suffixes are the first 4 hex characters of an HMAC, which collide
about once in 65,536 within a single provider/kind stem. On collision the suffix
lengthens until the mapping is injective again. There is a test that pushes 400
secrets through one stem and asserts no two share a placeholder. A collision
that slipped through would rehydrate one secret into another secret's position,
which is why it is tested rather than assumed.

### Refusing to rehydrate

If text coming back from an agent contains something that looks like one of our
placeholders but is not an exact match, secretgate **warns and substitutes
nothing**. This covers two cases:

- the agent truncated or reformatted the placeholder
- the agent invented a placeholder we never issued

Substituting on a fuzzy match would write a real credential into a location
chosen by a language model. Failing loudly is the correct outcome, and it is
tested in both directions.

### Editing other tools' configuration

`secretgate init` modifies files that belong to other programs. Before every
write it takes a timestamped backup and records the change in
`~/.secretgate/install.json`. `secretgate uninstall` restores from those
backups rather than guessing at the original content, and existing hooks are
appended to rather than replaced. A config file we cannot parse is left
untouched with an explanation, because rewriting it would mean discarding
settings we failed to read.

## Supported versions

Pre-1.0. Only the latest release gets fixes. Once 1.0 ships this section becomes
a real support matrix.
