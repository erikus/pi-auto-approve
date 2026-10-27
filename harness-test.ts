/**
 * Harness test: drives the tool_call handler with a mocked model registry to
 * verify allow / deny / fail-closed / circuit-breaker behavior without any
 * live API. Run: node --experimental-strip-types harness-test.ts
 */
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Isolate the harness from the developer's own pi configuration. The extension
// resolves ~/.pi/agent/auto-approve.json and the user policy files from $HOME
// when it is imported, and <cwd>/.pi/ on every review, so a real reviewer-model
// override or custom policy would otherwise leak into these tests. HOME must be
// set before the extension module loads, hence the dynamic import.
const scratchHome = mkdtempSync(join(tmpdir(), "pi-auto-approve-harness-"));
process.env.HOME = scratchHome;
process.chdir(scratchHome);
const { default: autoApproveExtension, AutoApproveReviewTimeoutError } = await import("./index.ts");

type Handler = (event: unknown, ctx: unknown) => Promise<{ block: boolean; reason?: string } | undefined>;

type BranchEntry = { type: string; id?: string; message?: { role: string; content: unknown } };

function userEntry(id: string, text: string): BranchEntry {
	return { type: "message", id, message: { role: "user", content: [{ type: "text", text }] } };
}

function makeHarness(
	completeImpl: (signal?: AbortSignal) => Promise<string>,
	options: { contextWindow?: number; branch?: () => BranchEntry[]; signal?: AbortSignal } = {},
) {
	const handlers = new Map<string, Handler>();
	const fakePi = {
		on: (name: string, handler: Handler) => handlers.set(name, handler),
		registerCommand: () => {},
	};
	autoApproveExtension(fakePi as never);

	const model = { id: "mock-model", provider: "mock", contextWindow: options.contextWindow };
	const ctx = {
		hasUI: false,
		ui: undefined,
		model,
		modelRegistry: {
			find: () => undefined, // no override config in this checkout -> the session model reviews
			hasConfiguredAuth: () => true,
			complete: async (_model: unknown, _request: unknown, opts?: { signal?: AbortSignal }) => ({
				content: [{ type: "text", text: await completeImpl(opts?.signal) }],
			}),
		},
		sessionManager: {
			getBranch: options.branch ?? (() => [userEntry("u1", "please do the thing")]),
		},
		signal: options.signal,
	};

	const toolCall = handlers.get("tool_call");
	const beforeAgentStart = handlers.get("before_agent_start");
	assert.ok(toolCall, "tool_call handler registered");
	return {
		review: (input: Record<string, unknown> = { command: "sudo systemctl stop nginx" }) =>
			toolCall({ toolName: "bash", toolCallId: "t1", input }, ctx),
		newTurn: () => beforeAgentStart?.({}, ctx),
	};
}

// Static gate short-circuits without calling the model.
{
	let calls = 0;
	const h = makeHarness(async () => {
		calls++;
		return '{"outcome":"allow"}';
	});
	const result = await h.review({ command: "git status" });
	assert.equal(result, undefined);
	assert.equal(calls, 0, "safe command must not trigger a review");
}

// Allow verdict -> tool proceeds.
{
	const h = makeHarness(async () => '{"risk_level":"medium","user_authorization":"high","outcome":"allow","rationale":"ok"}');
	assert.equal(await h.review(), undefined);
}

// Deny verdict -> block with codex-style reason.
{
	const h = makeHarness(async () => '{"risk_level":"high","user_authorization":"low","outcome":"deny","rationale":"not authorized"}');
	const result = await h.review();
	assert.ok(result?.block, "deny must block");
	assert.match(result.reason ?? "", /denied bash \(risk: high, authorization: low\)/);
	assert.match(result.reason ?? "", /Do not attempt to work around/);
}

// Permanent model failure -> fail closed without retrying.
{
	let calls = 0;
	const h = makeHarness(async () => {
		calls++;
		throw new Error("invalid API key");
	});
	const result = await h.review();
	assert.ok(result?.block, "failure must block");
	assert.match(result.reason ?? "", /Automatic approval review failed: invalid API key/);
	assert.match(result.reason ?? "", /review failure, not a determination that the action is unsafe/);
	assert.doesNotMatch(result.reason ?? "", /risk:/, "a failed review must not report a risk finding");
	assert.equal(calls, 1, "permanent failures must not retry");
}

// 409 conflicts are not transient (Codex retries only 408/429/5xx by status).
{
	let calls = 0;
	const h = makeHarness(async () => {
		calls++;
		const error = new Error("conflict") as Error & { status: number };
		error.status = 409;
		throw error;
	});
	const result = await h.review();
	assert.ok(result?.block, "409 must fail closed");
	assert.equal(calls, 1, "409 must not retry");
}

/** Run `fn` with a project `.pi/auto-approve.json` of `body` in a scratch cwd. */
async function withProjectConfig(body: string, fn: () => Promise<void>): Promise<void> {
	const dir = mkdtempSync(join(tmpdir(), "pi-auto-approve-harness-"));
	mkdirSync(join(dir, ".pi"));
	writeFileSync(join(dir, ".pi", "auto-approve.json"), body);
	const previous = process.cwd();
	process.chdir(dir);
	try {
		await fn();
	} finally {
		process.chdir(previous);
	}
}

const neverResolves = (signal?: AbortSignal) =>
	new Promise<string>((_, reject) => signal?.addEventListener("abort", () => reject(signal.reason)));

// A configured timeoutMs replaces the 90s default as the whole review's budget.
await withProjectConfig('{"timeoutMs": 40}', async () => {
	const h = makeHarness(neverResolves);
	const started = Date.now();
	const result = await h.review();
	assert.ok(result?.block, "configured timeout must block");
	assert.match(result.reason ?? "", /timed out while evaluating/);
	assert.ok(Date.now() - started < 1_000, "the configured deadline applies, not the default");
});

// timeoutMs 0 disables the deadline; cancellation still ends the review.
await withProjectConfig('{"timeoutMs": 0}', async () => {
	const controller = new AbortController();
	const h = makeHarness(neverResolves, { signal: controller.signal });
	setTimeout(() => controller.abort(), 30);
	const result = await h.review();
	assert.ok(result?.block, "cancelled review must block");
	assert.match(result.reason ?? "", /cancelled before it completed/);
});

// Timeout -> distinct instructions that permit one agent retry.
{
	const h = makeHarness(async () => {
		throw new AutoApproveReviewTimeoutError(90_000);
	});
	const result = await h.review();
	assert.ok(result?.block, "timeout must block");
	assert.match(result.reason ?? "", /timed out while evaluating/);
	assert.match(result.reason ?? "", /You may retry once/);
}

// Unparseable verdict -> retry, then fail closed.
{
	let calls = 0;
	const h = makeHarness(async () => {
		calls++;
		return "sure, go ahead!";
	});
	const result = await h.review();
	assert.ok(result?.block, "unparseable verdict must block");
	assert.equal(calls, 3, "parse failures should use the three-attempt budget");
}

// An empty reviewer response is a terminal session failure, not a parse
// failure: no retry, and the reason names the missing payload.
{
	let calls = 0;
	const h = makeHarness(async () => {
		calls++;
		return "";
	});
	const result = await h.review();
	assert.ok(result?.block, "empty response must block");
	assert.match(result.reason ?? "", /review failed: reviewer completed without an assessment payload/);
	assert.match(result.reason ?? "", /review failure, not a determination that the action is unsafe/);
	assert.equal(calls, 1, "a missing assessment payload must not retry");
}

// A model-not-found provider error is terminal even without an HTTP status.
{
	let calls = 0;
	const h = makeHarness(async () => {
		calls++;
		throw new Error('{"error":{"code":"model_not_found","message":"Access to this deployment ended."}}');
	});
	const result = await h.review();
	assert.ok(result?.block, "unknown model must fail closed");
	assert.match(result.reason ?? "", /model_not_found/);
	assert.equal(calls, 1, "model_not_found must not retry");
}

// Flex capacity failures retry like other transient service failures.
{
	let calls = 0;
	const h = makeHarness(async () => {
		calls++;
		if (calls === 1) throw new Error("Flex capacity unavailable.");
		return '{"outcome":"allow"}';
	});
	assert.equal(await h.review(), undefined);
	assert.equal(calls, 2, "flex capacity failures should retry");
}

// Transient service failure -> retry with backoff.
{
	let calls = 0;
	const h = makeHarness(async () => {
		calls++;
		if (calls === 1) {
			const error = new Error("service unavailable") as Error & { status: number };
			error.status = 503;
			throw error;
		}
		return '{"outcome":"allow"}';
	});
	assert.equal(await h.review(), undefined);
	assert.equal(calls, 2, "transient failures should retry");
}

// A user message that lands mid-review invalidates an allow: the verdict is
// discarded and the review is redone against the new evidence without backoff.
{
	const branch = [userEntry("u1", "please do the thing")];
	let calls = 0;
	const h = makeHarness(
		async () => {
			calls++;
			if (calls === 1) branch.push(userEntry("u2", "wait, not that"));
			return '{"outcome":"allow"}';
		},
		{ branch: () => branch },
	);
	const started = Date.now();
	assert.equal(await h.review(), undefined);
	assert.equal(calls, 2, "a stale allow must be re-reviewed against the new user message");
	assert.ok(Date.now() - started < 150, "stale-authorization retries must skip the service backoff");
}

// Authorization that keeps changing exhausts the attempt budget and fails
// closed as a review failure, not a risk finding.
{
	const branch = [userEntry("u1", "please do the thing")];
	let calls = 0;
	const h = makeHarness(
		async () => {
			calls++;
			branch.push(userEntry(`u${calls + 1}`, "and also this"));
			return '{"outcome":"allow"}';
		},
		{ branch: () => branch },
	);
	const result = await h.review();
	assert.ok(result?.block, "an allow never applied against current authorization must block");
	assert.match(result.reason ?? "", /review failed: authorization changed before approval could be applied/);
	assert.match(result.reason ?? "", /review failure, not a determination that the action is unsafe/);
	assert.equal(calls, 3, "stale authorization consumes the shared attempt budget");
}

// A denial stands even if a user message arrives mid-review (only allows are re-checked).
{
	const branch = [userEntry("u1", "please do the thing")];
	let calls = 0;
	const h = makeHarness(
		async () => {
			calls++;
			branch.push(userEntry("u2", "go ahead, I approve"));
			return '{"risk_level":"high","user_authorization":"low","outcome":"deny","rationale":"not authorized"}';
		},
		{ branch: () => branch },
	);
	const result = await h.review();
	assert.ok(result?.block, "deny must block");
	assert.equal(calls, 1, "denials are not re-reviewed on authorization change");
}

// An action that cannot fit the reviewer's window is never shortened for review
// and then run in full: the review fails closed without reaching the model.
{
	let calls = 0;
	const h = makeHarness(
		async () => {
			calls++;
			return '{"outcome":"allow"}';
		},
		{ contextWindow: 8_000 },
	);
	const result = await h.review({ command: `${"x".repeat(64_001)}; rm -rf /` });
	assert.ok(result?.block, "oversized action must block");
	assert.match(result.reason ?? "", /exceed the reviewer input budget/);
	assert.equal(calls, 0, "oversized action must not reach the reviewer model");
}

// The same action fits a larger window and is reviewed complete.
{
	let calls = 0;
	const h = makeHarness(
		async () => {
			calls++;
			return '{"outcome":"allow"}';
		},
		{ contextWindow: 200_000 },
	);
	assert.equal(await h.review({ command: `${"x".repeat(64_001)}; echo ok` }), undefined);
	assert.equal(calls, 1);
}

// Circuit breaker: 3 consecutive denials trip it; later reviews skip the model.
{
	let calls = 0;
	const h = makeHarness(async () => {
		calls++;
		return '{"risk_level":"high","user_authorization":"unknown","outcome":"deny","rationale":"no"}';
	});
	for (let i = 0; i < 3; i++) {
		const result = await h.review();
		assert.ok(result?.block);
	}
	assert.equal(calls, 3);
	const afterTrip = await h.review();
	assert.ok(afterTrip?.block, "breaker active: headless blocks without review");
	assert.match(afterTrip.reason ?? "", /circuit breaker/);
	assert.equal(calls, 3, "breaker must skip the model");
}

// New turn resets the consecutive counter (but a tripped breaker stays tripped).
{
	let verdict = '{"outcome":"deny","risk_level":"high","user_authorization":"low","rationale":"no"}';
	const h = makeHarness(async () => verdict);
	await h.review();
	await h.review();
	await h.newTurn(); // consecutive resets to 0 before the third denial
	await h.review();
	verdict = '{"outcome":"allow"}';
	const result = await h.review();
	assert.equal(result, undefined, "breaker must not trip on 2+1 denials across turns");
}

console.log("all harness tests passed");
