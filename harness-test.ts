/**
 * Harness test: drives the tool_call handler with a mocked model registry to
 * verify allow / deny / fail-closed / circuit-breaker behavior without any
 * live API. Run: node --experimental-strip-types harness-test.ts
 */
import assert from "node:assert/strict";
import autoApproveExtension, { AutoApproveReviewTimeoutError } from "./index.ts";

type Handler = (event: unknown, ctx: unknown) => Promise<{ block: boolean; reason?: string } | undefined>;

function makeHarness(completeImpl: () => Promise<string>, options: { contextWindow?: number } = {}) {
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
			complete: async () => ({ content: [{ type: "text", text: await completeImpl() }] }),
		},
		sessionManager: {
			getBranch: () => [
				{
					type: "message",
					message: { role: "user", content: [{ type: "text", text: "please do the thing" }] },
				},
			],
		},
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
