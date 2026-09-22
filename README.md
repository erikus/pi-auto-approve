# pi-auto-approve

LLM auto-approval of risky tool calls for the [pi coding agent](https://pi.dev), ported from
OpenAI Codex's "guardian" auto-review system
([`codex-rs/core/src/guardian/`](https://github.com/openai/codex/tree/main/codex-rs/core/src/guardian),
[`codex-rs/guardian-context/`](https://github.com/openai/codex/tree/main/codex-rs/guardian-context),
[`codex-rs/ext/guardian-reviewer/`](https://github.com/openai/codex/tree/main/codex-rs/ext/guardian-reviewer),
Apache-2.0). Instead of prompting you for every risky tool call - or running with no
gate at all (pi ships without a permission system) - a reviewer model judges each
risky action against a written policy and allows or denies it automatically.

`pi-auto-approve` is pre-1.0: the command, config file names, and policy paths may
still change between minor versions.

## Usage

```bash
pi install npm:pi-auto-approve
```

Or install straight from git (clones under `~/.pi/agent/git/` and registers the
extension in your settings):

```bash
pi install git:github.com/erikus/pi-auto-approve
```

Requires pi >= 0.84 (the reviewer runs through `ctx.modelRegistry.complete`, added in
0.84; on older pi the extension fails closed and blocks every gated action).

To try it once without installing: `pi -e git:github.com/erikus/pi-auto-approve`.
For local development, clone the repo and run `pi -e ./index.ts` from the checkout
(or symlink the checkout into `~/.pi/agent/extensions/`).

- `/auto-approve` - show state and stats (reviews / allowed / denied / overridden / failures)
- `/auto-approve off`, `/auto-approve on` - disable / re-enable (`on` also resets the circuit breaker)

Set `PI_AUTO_APPROVE_LOG=/path/to/file` to append one JSON line per review.

## How a tool call is decided

1. **Static gates** (no model call):
   - read-only tools (`read`, `grep`, `find`, `ls`) run freely;
   - `write`/`edit` inside the working directory run freely (stands in for Codex's
     workspace-write sandbox - pi has no sandbox);
   - `bash` commands made only of allowlisted read-only segments (`ls`, `cat`, `git status`,
     `grep`, …, no redirection/substitution) run freely.
2. **Auto-approve review** for everything else: the extension builds a compact transcript
   (every user message, plus recent assistant/tool evidence that is capped,
   truncation-tagged, and treated according to the policy's trust rules), renders the
   complete planned action, fits the request into the reviewer model's context window
   (optional evidence is evicted first, user messages are shortened only as a last
   resort, and an omission notice tells the reviewer not to infer authorization from
   missing evidence), and asks for a strict-JSON verdict
   `{risk_level, user_authorization, outcome, rationale}` per the policy prompt.
3. **Deny** blocks the tool call with instructions to the agent not to work around the
   denial (mirroring Codex). In the TUI you get an "Allow anyway?" override prompt - a manual approval is final, like Codex's post-denial user approval.
4. **Fail closed**: timeout (one 90s deadline shared by all attempts), unparseable
   verdict, oversized action, malformed reviewer config, or no authenticated model never
   silently allows - with a UI you're prompted; headless, the action is blocked. Parse
   errors and transient service/network failures retry up to three total attempts with
   backoff; permanent failures do not retry. The planned action is never shortened for
   model review and then run in full: if it cannot fit the reviewer's window beside the
   policy and the minimum evidence, the review fails.
5. **Circuit breaker**: 3 consecutive denials in a turn or 10 denials in the last 50
   reviews pauses auto-review; gated actions fall back to manual prompts
   (the same shape as Claude Code's auto-mode breaker).

## Model

By default the reviewer is the session's current model (`ctx.model`), always run at
low effort regardless of the session's effort setting. To review with a different
model, create the first of:

1. `<project>/.pi/auto-approve.json`
2. `~/.pi/agent/auto-approve.json`

containing exactly:

```json
{ "model": "<provider>/<model-id>" }
```

for example `{ "model": "anthropic/claude-opus-5" }`. The provider is everything before
the first `/`, so OpenRouter-style ids like `openrouter/anthropic/claude-opus-5` work. The model must exist in pi's
model registry and have configured auth. A malformed file, an unknown model, or a
model without auth is a configuration error: gated actions fail closed with a message
naming the file, rather than silently falling back to the session model. A missing
file simply means no override.

## Policy

The judging prompt is `policy/policy_template.md` with `{{ tenant_policy_config }}`
replaced by the first of:

1. `<project>/.pi/auto-approve-policy.md`
2. `~/.pi/agent/auto-approve-policy.md`
3. bundled `policy/policy.md` (Codex's default tenant policy)

The template's `{{ extra_policy }}` slot (Codex's `[auto_review] extra_policy`) is filled
from the first of `<project>/.pi/auto-approve-extra-policy.md` or
`~/.pi/agent/auto-approve-extra-policy.md`, and left empty when neither exists. Use it to
add rules on top of the default policy without replacing it.

Both prompt files are copied verbatim from openai/codex (Apache-2.0); see the license
note below. The extension appends a pi-specific environment override because pi has no
operating-system sandbox and the reviewer has no investigation tools. Notable defaults:
sensitive egress must be authorized for the specific payload and destination; critical
actions are denied; and high-risk actions need at least `medium` user authorization.

## Differences from Codex's guardian (prototype limitations)

- **No investigation tools.** Codex's guardian can run read-only commands (e.g. inspect
  an `rm -rf` target) before deciding; this extension judges from the transcript alone
  and the output contract tells it to lean conservative when facts are unverifiable.
- **Single-completion review**, no prewarmed review session.
- **Char-based caps** (~4 chars/token) instead of Codex's tokenizer-based transcript and
  request budgets; like Codex, message and tool evidence have separate budgets, all user
  messages are retained before recent non-user evidence, and the whole request is fitted
  to the reviewer model's context window. Codex additionally scales that window by a
  per-model percentage that pi does not expose.
- **Reviewer model.** Codex reviews with a dedicated `codex-auto-review` model and falls
  back to the session model when it is missing from the account's catalog; this
  extension reviews with the session model unless an override is configured (see
  Model above), and an unusable override fails closed instead of falling back.
- The static safe-command check is a much smaller allowlist than Codex's
  `is_safe_command` parser - anything it can't prove safe just goes to review, so
  being conservative here only costs latency, not safety.
- Verdicts are not persisted or cached (Claude Code caches e.g. network-host
  verdicts; a nice future addition).

## Testing

```bash
./node_modules/.bin/tsc -p tsconfig.json       # typecheck (node_modules symlinks to ../pi)
node --experimental-strip-types smoke-test.ts   # static-gate, parser, and budget tests
node --experimental-strip-types harness-test.ts # tool_call handler against a mocked registry
```

## License / attribution

The extension code is MIT licensed (see `LICENSE`).

`policy/policy_template.md` and `policy/policy.md` are copied from
[openai/codex](https://github.com/openai/codex) (`codex-rs/prompts/templates/guardian/`),
licensed under Apache-2.0 (see `policy/LICENSE`; `policy/NOTICE` reproduces the
upstream attribution notice as Apache-2.0 requires). The extension code is a re-implementation of that design
for pi's extension API; constants (timeout, retry count, breaker thresholds, transcript
caps) mirror `codex-rs/ext/guardian-reviewer/` and `codex-rs/guardian-context/`.
