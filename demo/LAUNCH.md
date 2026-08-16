# Launch notes

Internal. Not part of the published docs.

## Order of operations

Distribution before promotion. Every hour spent posting before these are done is
wasted, because the traffic arrives and bounces.

1. **`npm publish`** — the README's first command is `npx secretgate init`. Until
   the package exists that command 404s, and the first thing every visitor does
   is try it. This is the single highest-value action available.
2. **`vhs demo/demo.tape`** — produces `docs/demo.gif`. Put it directly under the
   headline in the README. A 20-second GIF of a secret going in and coming back
   out does more than every paragraph of copy on the page.
3. Only then, post.

## Show HN

Title (Show HN titles should be plain, no adjectives):

    Show HN: Secretgate – redact secrets from AI coding agents, then put them back

Body:

> I kept pasting stack traces into Claude Code and noticing afterwards that they
> had a database URL in them.
>
> The existing options block the prompt, which means you stop what you were
> doing and go clean it up by hand. Secretgate swaps the credential for a stable
> placeholder — SECRETGATE_AWS_KEY_6B8A — lets the agent work on that, and puts
> the real value back locally before anything hits disk. The model keeps enough
> context to reason about the code, it just never holds the key.
>
> It runs entirely offline. No account, no cloud, no telemetry, zero runtime
> dependencies. The no-network property is enforced by a CI check that fails the
> build if anything under src/core or src/hooks imports a network module, rather
> than being a line in the README.
>
> The part I would most like feedback on is precision. Detection is regex packs
> plus entropy plus a suppression layer, scored against a corpus of 316 samples
> where the 118 hard negatives are hand-written — git SHAs, lockfile hashes,
> UUIDs, base64 images, Kubernetes secretKeyRef blocks. CI fails below 98%
> precision. The reasoning is that a scanner which cries wolf gets uninstalled,
> and an uninstalled scanner has zero recall.
>
> Two things it does not do: verify whether a leaked key is still live, and stop
> an agent that is actively trying to evade it. The threat model in SECURITY.md
> says so directly.
>
> https://github.com/jvlabsai/secretgate

Post Tuesday–Thursday, roughly 9am ET. Then stay at the keyboard for three
hours and answer every comment. On Show HN the comment thread is the product
demo; a post the author abandons dies regardless of the idea.

Expect the top comment to be some version of "gitleaks already exists". The
honest answer, which you should give rather than deflect: gitleaks scans repos,
this sits in the agent's prompt path and restores values afterwards, and the
ruleset is genuinely indebted to theirs.

## Reddit

- **r/ExperiencedDevs** — no link in the post body, it reads as spam. Lead with
  the war story: the two-process bug where redaction removed secrets it could
  never restore, and how building the demo is what surfaced it. Link in a
  comment when someone asks.
- **r/devops**, **r/netsec** — netsec is hostile to anything that overclaims.
  Lead with the threat model and what the tool explicitly does not do. That
  audience rewards it.
- **r/ClaudeAI**, **r/cursor** — most directly relevant users. Short post, GIF,
  one link.

Not all in one day. One subreddit per day, and reply to everything.

## LinkedIn

Different audience — engineering managers rather than the people who will run
it. Lead with the incident shape, not the tool:

> A developer pastes a stack trace into an AI coding assistant. The stack trace
> contains a database connection string. That credential is now in a third
> party's logs, and someone's afternoon is gone rotating it.
>
> We built secretgate to make that specific mistake harmless...

Include the GIF. LinkedIn's algorithm heavily favours native video/images over
links, so put the link in the first comment.

## What not to do

- Do not buy stars, run star-exchange schemes, or ask groups to star it. GitHub
  detects it, it is trivially visible in the stargazer timeline, and it destroys
  the credibility this project's entire pitch rests on.
- Do not mass-DM. Do not post to fifteen subreddits in one day.
- Do not claim "zero false positives". 100% on our own corpus means our corpus,
  and the README already says so.

## Realistic expectations

A good Show HN for a developer tool in a crowded category lands somewhere in the
tens to low hundreds of stars. A great one, front page for a few hours, reaches
four figures. Most posts get neither, and the difference is usually the demo and
whether the author answered comments — not the code.

The strongest asset here is that the honesty is unusual: a security tool whose
README documents what it cannot do, with a threat model that says "this is not
an adversarial boundary". Lead with that. It is genuinely differentiating in a
space full of overclaiming.
