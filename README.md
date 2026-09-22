# pi-guardian

An LLM auto-approval "guardian" for the [pi coding agent](https://pi.dev), ported from
OpenAI Codex's guardian auto-review system
([`codex-rs/core/src/guardian/`](https://github.com/openai/codex/tree/main/codex-rs/core/src/guardian),
Apache-2.0). Instead of prompting you for every risky tool call - or running with no
gate at all (pi ships without a permission system) - a reviewer model judges each
risky action against a written policy and allows or denies it automatically.

## Usage

```bash
pi install git:github.com/erikus/pi-guardian
```

Requires pi >= 0.84 (the guardian calls `ctx.modelRegistry.complete`, added in
0.84; on older pi it fails closed and blocks every gated action).

This clones the repo under `~/.pi/agent/git/` and registers it in your settings - no
manual clone needed. To try it once without installing: `pi -e git:github.com/erikus/pi-guardian`.

For local development, clone the repo and run `pi -e ./index.ts` from the checkout
(or symlink the checkout into `~/.pi/agent/extensions/`).

- `/guardian` - show state and stats (reviews / allowed / denied / overridden / failures)
- `/guardian off`, `/guardian on` - disable / re-enable (`on` also resets the circuit breaker)

## How a tool call is decided

1. **Static gates** (no model call):
   - read-only tools (`read`, `grep`, `find`, `ls`) run freely;
   - `write`/`edit` inside the working directory run freely (stands in for Codex's
     workspace-write sandbox - pi has no sandbox);
   - `bash` commands made only of allowlisted read-only segments (`ls`, `cat`, `git status`,
     `grep`, …, no redirection/substitution) run freely.
2. **Guardian review** for everything else: the extension builds a compact transcript
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
   verdict, oversized action, or no authenticated model never silently allows - with a
   UI you're prompted; headless, the action is blocked. Parse errors and transient
   service/network failures retry up to three total attempts with backoff; permanent
   failures do not retry. The planned action is never shortened for model review and
   then run in full: if it cannot fit the reviewer's window beside the policy and the
   minimum evidence, the review fails.
5. **Circuit breaker**: 3 consecutive denials in a turn or 10 denials in the last 50
   reviews pauses auto-review; gated actions fall back to manual prompts
   (the same shape as Claude Code's auto-mode breaker).

## Model

Preferred reviewer: `anthropic/claude-opus-5` at low effort (edit `GUARDIAN_PROVIDER` /
`GUARDIAN_MODEL_ID` in `index.ts`). If that model has no configured auth, the guardian
falls back to the session's main model - the same fallback Codex uses when
`codex-auto-review` isn't in the account's catalog.

## Policy

The judging prompt is `policy/policy_template.md` with `{{ tenant_policy_config }}`
replaced by the first of:

1. `<project>/.pi/guardian-policy.md`
2. `~/.pi/agent/guardian-policy.md`
3. bundled `policy/policy.md` (Codex's default tenant policy)

The template's `{{ extra_policy }}` slot (Codex's `[auto_review] extra_policy`) is filled
from the first of `<project>/.pi/guardian-extra-policy.md` or
`~/.pi/agent/guardian-extra-policy.md`, and left empty when neither exists. Use it to add
rules on top of the default policy without replacing it.

Both prompt files are copied verbatim from openai/codex (Apache-2.0); see the license
note below. The extension appends a pi-specific environment override because pi has no
operating-system sandbox and the reviewer has no investigation tools. Notable defaults:
sensitive egress must be authorized for the specific payload and destination; critical
actions are denied; and high-risk actions need at least `medium` user authorization.

## Differences from Codex's guardian (prototype limitations)

- **No investigation tools.** Codex's guardian can run read-only commands (e.g. inspect
  an `rm -rf` target) before deciding; this prototype judges from the transcript alone
  and the output contract tells it to lean conservative when facts are unverifiable.
- **Single-completion review**, no prewarmed review session.
- **Char-based caps** (~4 chars/token) instead of Codex's tokenizer-based transcript and
  request budgets; like Codex, message and tool evidence have separate budgets, all user
  messages are retained before recent non-user evidence, and the whole request is fitted
  to the reviewer model's context window. Codex additionally scales that window by a
  per-model percentage that pi does not expose.
- The static safe-command check is a much smaller allowlist than Codex's
  `is_safe_command` parser - anything it can't prove safe just goes to review, so
  being conservative here only costs latency, not safety.
- Guardian verdicts are not persisted or cached (Claude Code caches e.g. network-host
  verdicts; a nice future addition).

## Testing

```bash
./node_modules/.bin/tsc -p tsconfig.json     # typecheck (node_modules symlinks to ../pi)
node --experimental-strip-types smoke-test.ts # static-gate + parser tests
```

## License / attribution

The extension code is MIT licensed (see `LICENSE`).

`policy/policy_template.md` and `policy/policy.md` are copied from
[openai/codex](https://github.com/openai/codex) (`codex-rs/core/src/guardian/`),
licensed under Apache-2.0 (see `policy/LICENSE`; `policy/NOTICE` reproduces the
upstream attribution notice as Apache-2.0 requires). The extension code is a re-implementation of that design
for pi's extension API; constants (timeout, retry count, breaker thresholds, transcript
caps) mirror `codex-rs/core/src/guardian/mod.rs`.
