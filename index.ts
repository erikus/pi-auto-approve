/**
 * Guardian extension for pi - LLM auto-approval of risky tool calls.
 *
 * Port of the OpenAI Codex "guardian" auto-review design (Apache-2.0,
 * github.com/openai/codex, codex-rs/core/src/guardian/) onto pi's extension
 * API. Layering mirrors Codex:
 *
 *   1. Static gates: read-only tools and an allowlist of safe bash commands
 *      run without review; writes/edits inside the workspace run without
 *      review (pi has no sandbox, so this stands in for workspace-write).
 *   2. Everything else goes to a guardian model that judges the exact action
 *      against a policy (risk_level x user_authorization -> allow/deny),
 *      using a compact transcript as untrusted evidence.
 *   3. Fail closed: timeout, parse failure, or missing model never silently
 *      allows. With a UI the human is prompted; headless, the action blocks.
 *   4. Circuit breaker: repeated denials disable auto-review and fall back
 *      to manual prompts for the rest of the session.
 */

import { randomUUID } from "node:crypto";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve, sep } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

// ---------------------------------------------------------------------------
// Configuration constants (mirroring codex-rs/core/src/guardian/mod.rs; token
// limits converted to chars at ~4 chars/token)
// ---------------------------------------------------------------------------

const GUARDIAN_PROVIDER = "anthropic";
const GUARDIAN_MODEL_ID = "claude-opus-5";
const GUARDIAN_REVIEW_TIMEOUT_MS = 90_000;
const GUARDIAN_MAX_ATTEMPTS = 3;

const MAX_CONSECUTIVE_DENIALS_PER_TURN = 3;
const DENIAL_WINDOW_SIZE = 50;
const MAX_WINDOW_DENIALS = 10;

const MAX_RECENT_NON_USER_ENTRIES = 40;
const MAX_MESSAGE_TRANSCRIPT_CHARS = 80_000;
const MAX_TOOL_TRANSCRIPT_CHARS = 40_000;
const MAX_CHARS_PER_MESSAGE = 20_000;
const MAX_CHARS_PER_TOOL_ENTRY = 4_000;
const MAX_ACTION_STRING_CHARS = 64_000;
const MAX_FORMATTED_ACTION_CHARS = 64_000;

const READ_ONLY_TOOLS = new Set(["read", "grep", "find", "ls"]);
const WORKSPACE_WRITE_TOOLS = new Set(["write", "edit"]);

/** First tokens of bash segments that never need review. */
const SAFE_BASH_COMMANDS = new Set([
	"ls", "cat", "head", "tail", "wc", "pwd", "echo", "true", "which",
	"whoami", "date", "env", "printenv", "file", "stat", "du", "df",
	"grep", "rg", "find", "cd", "git",
]);
const SAFE_GIT_SUBCOMMANDS = new Set(["status", "diff", "log", "show", "branch", "remote"]);
const UNSAFE_FIND_FLAGS = /-(delete|exec|execdir|ok|okdir)\b/;
/** Redirection / substitution makes a segment-wise safety check unsound. */
const UNSAFE_SHELL_SYNTAX = /[<>`]|\$\(/;

// Project override -> user override -> bundled Codex default policy.
const PROJECT_POLICY_PATH = ".pi/guardian-policy.md";
const USER_POLICY_PATH = join(homedir(), ".pi", "agent", "guardian-policy.md");
// Optional extra policy text appended after the tenant policy (Codex's
// `[auto_review] extra_policy`). Project file wins over the user file; empty
// when neither exists.
const PROJECT_EXTRA_POLICY_PATH = ".pi/guardian-extra-policy.md";
const USER_EXTRA_POLICY_PATH = join(homedir(), ".pi", "agent", "guardian-extra-policy.md");

const TENANT_POLICY_CONFIG_PLACEHOLDER = "{{ tenant_policy_config }}";
const EXTRA_POLICY_PLACEHOLDER = "{{ extra_policy }}";

/** Set PI_GUARDIAN_LOG=/path/to/file to append one JSON line per review. */
const GUARDIAN_LOG_PATH = process.env.PI_GUARDIAN_LOG;

const OUTPUT_CONTRACT = `
# Pi Environment Override
The Codex-specific execution-environment description above does not apply here. The coding agent is running as pi without an operating-system sandbox, and a reviewed tool call may execute with the user's host permissions. You cannot run tools or access the network in this review environment. Judge only from the evidence provided; when an investigation would be required to resolve critical uncertainty, lean conservative and explain the uncertainty in your rationale.

# Output Contract
Your entire reply must be a single strict JSON object of the form:
{"risk_level": "low|medium|high|critical", "user_authorization": "unknown|low|medium|high", "outcome": "allow|deny", "rationale": "one concise sentence"}
Only "outcome" is required; for clearly low-risk actions you may reply {"outcome": "allow"}.
Do not wrap the JSON in markdown fences or add any other text.`;

// Agent-facing text for reviews that never produced an assessment (mirrors
// codex-rs/ext/guardian-reviewer/src/completion.rs and
// codex-rs/prompts/src/model_messages/guardian.rs). A failed review is still
// denied, but it must not be reported as a finding that the action is unsafe.
const REVIEW_FAILURE_INSTRUCTIONS =
	"The action was not executed because automatic approval review could not be completed. " +
	"This is a review failure, not a determination that the action is unsafe. " +
	"Do not bypass the approval check; resolve the error or ask the user for guidance.";
const TIMEOUT_INSTRUCTIONS =
	"The automatic permission approval review did not finish before its deadline. " +
	"Do not assume the action is unsafe based on the timeout alone. " +
	"You may retry once, or ask the user for guidance or explicit approval.";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type RiskLevel = "low" | "medium" | "high" | "critical";
type UserAuthorization = "unknown" | "low" | "medium" | "high";

interface GuardianAssessment {
	outcome: "allow" | "deny";
	risk_level?: RiskLevel;
	user_authorization?: UserAuthorization;
	rationale?: string;
}

interface GuardianStats {
	reviews: number;
	allowed: number;
	denied: number;
	overridden: number;
	failures: number;
}

// ---------------------------------------------------------------------------
// Prompt assembly
// ---------------------------------------------------------------------------

const extensionDir = new URL(".", import.meta.url).pathname;

function loadPolicyTemplate(): string {
	return readFileSync(join(extensionDir, "policy", "policy_template.md"), "utf8");
}

function loadTenantPolicy(): string {
	const projectPolicy = resolve(process.cwd(), PROJECT_POLICY_PATH);
	if (existsSync(projectPolicy)) return readFileSync(projectPolicy, "utf8");
	if (existsSync(USER_POLICY_PATH)) return readFileSync(USER_POLICY_PATH, "utf8");
	return readFileSync(join(extensionDir, "policy", "policy.md"), "utf8");
}

function loadExtraPolicy(): string {
	const projectPolicy = resolve(process.cwd(), PROJECT_EXTRA_POLICY_PATH);
	if (existsSync(projectPolicy)) return readFileSync(projectPolicy, "utf8");
	if (existsSync(USER_EXTRA_POLICY_PATH)) return readFileSync(USER_EXTRA_POLICY_PATH, "utf8");
	return "";
}

/**
 * Fill the policy template's placeholders (codex-rs/prompts/src/guardian_instructions.rs).
 * Only template text is substituted: split on the tenant placeholder first so
 * placeholder-like text inside either policy stays literal, and use split/join
 * rather than `String.replace` so `$&`-style patterns in a policy are not
 * interpreted.
 */
export function renderPolicyInstructions(template: string, tenantPolicy: string, extraPolicy: string): string {
	return template
		.trimEnd()
		.split(TENANT_POLICY_CONFIG_PLACEHOLDER)
		.map((part) => part.split(EXTRA_POLICY_PLACEHOLDER).join(extraPolicy.trim()))
		.join(tenantPolicy.trim());
}

function truncate(text: string, maxChars: number): string {
	if (text.length <= maxChars) return text;
	return `${text.slice(0, maxChars)}\n<guardian_truncated original_chars="${text.length}"/>`;
}

interface SessionContentBlock {
	type?: string;
	text?: string;
	name?: string;
	arguments?: Record<string, unknown>;
}

function contentBlocks(content: unknown): SessionContentBlock[] {
	if (typeof content === "string") return [{ type: "text", text: content }];
	if (!Array.isArray(content)) return [];
	return content.filter((b): b is SessionContentBlock => !!b && typeof b === "object");
}

type TranscriptEntryKind = "user" | "assistant" | "tool";

interface TranscriptEntry {
	kind: TranscriptEntryKind;
	text: string;
}

function collectTranscriptEntries(ctx: ExtensionContext): TranscriptEntry[] {
	const sections: TranscriptEntry[] = [];
	const entries = ctx.sessionManager.getBranch().filter((e: { type: string }) => e.type === "message");

	for (const entry of entries as Array<{
		message?: { role?: string; toolName?: string; content?: unknown; isError?: boolean };
	}>) {
		const message = entry.message;
		if (!message?.role) continue;
		const blocks = contentBlocks(message.content);

		if (message.role === "user" || message.role === "assistant") {
			const text = blocks
				.filter((b) => b.type === "text" && typeof b.text === "string")
				.map((b) => b.text as string)
				.join("\n")
				.trim();
			if (text) {
				const label = message.role === "user" ? "User" : "Assistant";
				sections.push({ kind: message.role, text: `${label}: ${truncate(text, MAX_CHARS_PER_MESSAGE)}` });
			}
			if (message.role === "assistant") {
				for (const b of blocks) {
					if (b.type === "toolCall" && typeof b.name === "string") {
						const args = JSON.stringify(b.arguments ?? {});
						sections.push({
							kind: "tool",
							text: `Assistant called tool ${b.name} with ${truncate(args, MAX_CHARS_PER_TOOL_ENTRY)}`,
						});
					}
				}
			}
		} else if (message.role === "toolResult") {
			const text = blocks
				.filter((b) => b.type === "text" && typeof b.text === "string")
				.map((b) => b.text as string)
				.join("\n")
				.trim();
			const errorTag = message.isError ? " (error)" : "";
			sections.push({
				kind: "tool",
				text: `Tool result${errorTag} from ${message.toolName ?? "unknown"}: ${truncate(text, MAX_CHARS_PER_TOOL_ENTRY)}`,
			});
		}
	}
	return sections;
}

/**
 * Compact transcript with separate message/tool budgets. User messages are
 * selected first so tool traffic cannot evict authorization evidence. If they
 * do not all fit, keep the first user message as an intent anchor and fill the
 * remaining budget with the newest user messages.
 */
export function buildTranscript(ctx: ExtensionContext): string {
	const entries = collectTranscriptEntries(ctx);
	if (entries.length === 0) return "<no retained transcript entries>";

	const included = new Set<number>();
	const userIndices = entries
		.map((entry, index) => (entry.kind === "user" ? index : -1))
		.filter((index) => index >= 0);
	const allUserChars = userIndices.reduce((total, index) => total + entries[index]!.text.length, 0);
	let messageChars = 0;

	if (allUserChars <= MAX_MESSAGE_TRANSCRIPT_CHARS) {
		for (const index of userIndices) included.add(index);
		messageChars = allUserChars;
	} else if (userIndices.length > 0) {
		const first = userIndices[0]!;
		included.add(first);
		messageChars = entries[first]!.text.length;
		for (let i = userIndices.length - 1; i > 0; i--) {
			const index = userIndices[i]!;
			const chars = entries[index]!.text.length;
			if (messageChars + chars <= MAX_MESSAGE_TRANSCRIPT_CHARS) {
				included.add(index);
				messageChars += chars;
			}
		}
	}

	let toolChars = 0;
	let retainedNonUserEntries = 0;
	for (let index = entries.length - 1; index >= 0; index--) {
		const entry = entries[index]!;
		if (entry.kind === "user" || retainedNonUserEntries >= MAX_RECENT_NON_USER_ENTRIES) continue;
		const chars = entry.text.length;
		if (entry.kind === "tool") {
			if (toolChars + chars > MAX_TOOL_TRANSCRIPT_CHARS) continue;
			toolChars += chars;
		} else {
			if (messageChars + chars > MAX_MESSAGE_TRANSCRIPT_CHARS) continue;
			messageChars += chars;
		}
		included.add(index);
		retainedNonUserEntries += 1;
	}

	const selected = entries.filter((_entry, index) => included.has(index)).map((entry) => entry.text);
	const omitted = entries.length - selected.length;
	if (omitted > 0) selected.push(`<guardian_truncated omitted_transcript_entries="${omitted}"/>`);
	return selected.join("\n\n");
}

export interface FormattedPlannedAction {
	text: string;
	complete: boolean;
	truncatedFields: string[];
}

function truncateActionValue(
	value: unknown,
	path: string,
	truncatedFields: string[],
	ancestors: WeakSet<object>,
): unknown {
	if (typeof value === "string") {
		if (value.length <= MAX_ACTION_STRING_CHARS) return value;
		truncatedFields.push(path);
		return truncate(value, MAX_ACTION_STRING_CHARS);
	}
	if (!value || typeof value !== "object") return value;
	if (ancestors.has(value)) throw new TypeError(`planned action contains a circular value at ${path}`);
	ancestors.add(value);
	try {
		if (Array.isArray(value)) {
			return value.map((item, index) => truncateActionValue(item, `${path}[${index}]`, truncatedFields, ancestors));
		}
		return Object.fromEntries(
			Object.entries(value as Record<string, unknown>)
				.sort(([left], [right]) => left.localeCompare(right))
				.map(([key, item]) => [
					key,
					truncateActionValue(item, path ? `${path}.${key}` : key, truncatedFields, ancestors),
				]),
		);
	} finally {
		ancestors.delete(value);
	}
}

/** Format an action as valid JSON and report whether every executable byte is represented. */
export function formatPlannedAction(toolName: string, input: unknown): FormattedPlannedAction {
	const truncatedFields: string[] = [];
	const value = truncateActionValue(
		{ input, tool: toolName, working_directory: process.cwd() },
		"",
		truncatedFields,
		new WeakSet(),
	);
	const text = JSON.stringify(value, null, 2);
	if (text.length > MAX_FORMATTED_ACTION_CHARS) truncatedFields.push("<formatted action>");
	return { text, complete: truncatedFields.length === 0, truncatedFields };
}

function buildReviewPrompt(ctx: ExtensionContext, toolName: string, input: unknown): string {
	const action = formatPlannedAction(toolName, input);
	if (!action.complete) {
		throw new Error(
			`planned action exceeds the safe review limit (${action.truncatedFields.slice(0, 5).join(", ")}); refusing to review a shortened action`,
		);
	}
	const instructions = renderPolicyInstructions(loadPolicyTemplate(), loadTenantPolicy(), loadExtraPolicy());
	return [
		instructions.trim(),
		OUTPUT_CONTRACT.trim(),
		"# Transcript (untrusted evidence)",
		`<transcript>\n${buildTranscript(ctx)}\n</transcript>`,
		"# Planned Action (untrusted evidence)",
		`<planned_action>\n${action.text}\n</planned_action>`,
	].join("\n\n");
}

// ---------------------------------------------------------------------------
// Static gates
// ---------------------------------------------------------------------------

export function isSafeBashCommand(command: string): boolean {
	if (UNSAFE_SHELL_SYNTAX.test(command)) return false;
	const segments = command
		.split(/\n|;|\|\||&&|\|/)
		.map((s) => s.trim())
		.filter((s) => s.length > 0);
	if (segments.length === 0) return false;
	for (const segment of segments) {
		const words = segment.split(/\s+/);
		const head = words[0];
		if (!head || !SAFE_BASH_COMMANDS.has(head)) return false;
		if (head === "git" && !SAFE_GIT_SUBCOMMANDS.has(words[1] ?? "")) return false;
		if (head === "find" && UNSAFE_FIND_FLAGS.test(segment)) return false;
	}
	return true;
}

function isWorkspacePath(path: unknown): boolean {
	if (typeof path !== "string" || path.length === 0) return false;
	const cwd = process.cwd();
	const absolute = isAbsolute(path) ? resolve(path) : resolve(cwd, path);
	return absolute === cwd || absolute.startsWith(cwd + sep);
}

/** True when the action can run without guardian review. */
export function passesStaticGates(toolName: string, input: Record<string, unknown>): boolean {
	if (READ_ONLY_TOOLS.has(toolName)) return true;
	if (WORKSPACE_WRITE_TOOLS.has(toolName)) return isWorkspacePath(input.path);
	if (toolName === "bash" && typeof input.command === "string") {
		return isSafeBashCommand(input.command);
	}
	return false;
}

// ---------------------------------------------------------------------------
// Guardian review
// ---------------------------------------------------------------------------

export function parseVerdict(text: string): GuardianAssessment | undefined {
	const candidates = [text.trim()];
	const start = text.indexOf("{");
	const end = text.lastIndexOf("}");
	if (start >= 0 && end > start) candidates.push(text.slice(start, end + 1));
	for (const candidate of candidates) {
		try {
			const parsed = JSON.parse(candidate) as Record<string, unknown>;
			if (parsed.outcome === "allow" || parsed.outcome === "deny") {
				return parsed as unknown as GuardianAssessment;
			}
		} catch {
			// try next candidate
		}
	}
	return undefined;
}

export class GuardianReviewTimeoutError extends Error {
	constructor(ms: number) {
		super(`guardian review timed out after ${ms}ms`);
		this.name = "GuardianReviewTimeoutError";
	}
}

class GuardianReviewCancelledError extends Error {
	constructor() {
		super("guardian review cancelled");
		this.name = "GuardianReviewCancelledError";
	}
}

class GuardianVerdictParseError extends Error {
	constructor(text: string) {
		super(`unparseable guardian verdict: ${text.slice(0, 200)}`);
		this.name = "GuardianVerdictParseError";
	}
}

/** Run an operation under one abortable deadline, including any retries/backoff. */
export function withReviewDeadline<T>(
	operation: (signal: AbortSignal) => Promise<T>,
	ms: number,
	parentSignal?: AbortSignal,
): Promise<T> {
	return new Promise<T>((resolvePromise, rejectPromise) => {
		const controller = new AbortController();
		let settled = false;
		const cleanup = () => {
			clearTimeout(timer);
			parentSignal?.removeEventListener("abort", onParentAbort);
		};
		const resolveOnce = (value: T) => {
			if (settled) return;
			settled = true;
			cleanup();
			resolvePromise(value);
		};
		const rejectOnce = (error: unknown) => {
			if (settled) return;
			settled = true;
			cleanup();
			controller.abort(error);
			rejectPromise(error);
		};
		const onParentAbort = () => rejectOnce(new GuardianReviewCancelledError());
		const timer = setTimeout(() => rejectOnce(new GuardianReviewTimeoutError(ms)), ms);
		parentSignal?.addEventListener("abort", onParentAbort, { once: true });
		if (parentSignal?.aborted) {
			onParentAbort();
			return;
		}

		try {
			operation(controller.signal).then(resolveOnce, rejectOnce);
		} catch (error) {
			rejectOnce(error);
		}
	});
}

function guardianRetryDelayMs(attempt: number): number {
	const base = 200 * 2 ** Math.max(0, attempt - 1);
	return Math.round(base * (0.9 + Math.random() * 0.2));
}

function abortableSleep(ms: number, signal: AbortSignal): Promise<void> {
	return new Promise((resolvePromise, rejectPromise) => {
		if (signal.aborted) {
			rejectPromise(signal.reason ?? new GuardianReviewCancelledError());
			return;
		}
		const onAbort = () => {
			clearTimeout(timer);
			rejectPromise(signal.reason ?? new GuardianReviewCancelledError());
		};
		const timer = setTimeout(() => {
			signal.removeEventListener("abort", onAbort);
			resolvePromise();
		}, ms);
		signal.addEventListener("abort", onAbort, { once: true });
	});
}

function guardianErrorStatus(error: unknown): number | undefined {
	if (!error || typeof error !== "object") return undefined;
	const candidate = error as {
		status?: unknown;
		statusCode?: unknown;
		$metadata?: { httpStatusCode?: unknown };
		$response?: { statusCode?: unknown };
	};
	for (const status of [
		candidate.status,
		candidate.statusCode,
		candidate.$metadata?.httpStatusCode,
		candidate.$response?.statusCode,
	]) {
		if (typeof status === "number") return status;
	}
	return undefined;
}

/**
 * Retry only recoverable failures (codex-rs/ext/guardian-reviewer/src/retry.rs):
 * parse errors, rate limits, overload, and connection/stream failures with no
 * status or a 408/429/5xx status. Everything else (auth, bad request, context
 * window, 409 conflicts) fails the review immediately.
 *
 * Codex also defers the retry until any server-supplied Retry-After time. pi's
 * `complete()` collapses provider errors to an `errorMessage` string, so that
 * value is not observable here and only exponential backoff applies.
 */
function isRetryableGuardianError(error: unknown): boolean {
	if (error instanceof GuardianVerdictParseError) return true;
	if (error instanceof GuardianReviewTimeoutError || error instanceof GuardianReviewCancelledError) return false;
	const status = guardianErrorStatus(error);
	if (status !== undefined) return status === 408 || status === 429 || status >= 500;
	if (!(error instanceof Error)) return false;
	const code = (error as Error & { code?: unknown }).code;
	if (
		typeof code === "string" &&
		new Set(["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "EAI_AGAIN", "ENETDOWN", "ENETUNREACH", "EPIPE"]).has(code)
	) {
		return true;
	}
	return /(?:\b(?:408|429|5\d\d)\b|server overloaded|rate.?limit|service unavailable|fetch failed|connection (?:failed|reset|refused)|response stream (?:disconnected|connection failed))/i.test(
		error.message,
	);
}

export default function guardianExtension(pi: ExtensionAPI) {
	const guardianSessionId = randomUUID();
	const stats: GuardianStats = { reviews: 0, allowed: 0, denied: 0, overridden: 0, failures: 0 };

	let enabled = true;
	let breakerTripped = false;
	let consecutiveDenials = 0;
	const denialWindow: boolean[] = [];

	function recordReview(denied: boolean) {
		denialWindow.push(denied);
		if (denialWindow.length > DENIAL_WINDOW_SIZE) denialWindow.shift();
		consecutiveDenials = denied ? consecutiveDenials + 1 : 0;
		const windowDenials = denialWindow.filter(Boolean).length;
		if (consecutiveDenials >= MAX_CONSECUTIVE_DENIALS_PER_TURN || windowDenials >= MAX_WINDOW_DENIALS) {
			breakerTripped = true;
		}
	}

	function setStatus(ctx: ExtensionContext, text: string) {
		if (ctx.hasUI) ctx.ui.setStatus("guardian", text);
	}

	function logReview(toolName: string, entry: Record<string, unknown>) {
		if (!GUARDIAN_LOG_PATH) return;
		try {
			appendFileSync(GUARDIAN_LOG_PATH, `${JSON.stringify({ time: new Date().toISOString(), tool: toolName, ...entry })}\n`);
		} catch {
			// logging must never break the approval flow
		}
	}

	function resolveGuardianModel(ctx: ExtensionContext) {
		const preferred = ctx.modelRegistry.find(GUARDIAN_PROVIDER, GUARDIAN_MODEL_ID);
		if (preferred && ctx.modelRegistry.hasConfiguredAuth(preferred)) return preferred;
		// Codex parity: fall back to the session's main model when the preferred
		// review model is unavailable.
		if (ctx.model && ctx.modelRegistry.hasConfiguredAuth(ctx.model)) return ctx.model;
		return undefined;
	}

	async function requestVerdict(
		ctx: ExtensionContext,
		toolName: string,
		input: unknown,
	): Promise<GuardianAssessment> {
		const model = resolveGuardianModel(ctx);
		if (!model) throw new Error("no guardian model with configured auth");
		const prompt = buildReviewPrompt(ctx, toolName, input);
		const messages = [
			{
				role: "user" as const,
				content: [{ type: "text" as const, text: prompt }],
				timestamp: Date.now(),
			},
		];

		return await withReviewDeadline(
			async (signal) => {
				let lastError: unknown;
				for (let attempt = 1; attempt <= GUARDIAN_MAX_ATTEMPTS; attempt++) {
					try {
						const response = await ctx.modelRegistry.complete(
							model,
							{ messages },
							{
								effort: "low",
								sessionId: guardianSessionId,
								signal,
								maxRetries: 0,
								timeoutMs: GUARDIAN_REVIEW_TIMEOUT_MS,
							},
						);
						if (response.stopReason === "aborted") throw new GuardianReviewCancelledError();
						if (response.stopReason === "error") {
							throw new Error(response.errorMessage ?? "guardian model request failed");
						}
						const text = response.content
							.filter((c): c is { type: "text"; text: string } => c.type === "text")
							.map((c) => c.text)
							.join("\n");
						const verdict = parseVerdict(text);
						if (verdict) return verdict;
						throw new GuardianVerdictParseError(text);
					} catch (error) {
						lastError = error;
						if (attempt >= GUARDIAN_MAX_ATTEMPTS || !isRetryableGuardianError(error)) break;
						await abortableSleep(guardianRetryDelayMs(attempt), signal);
					}
				}
				throw lastError instanceof Error ? lastError : new Error(String(lastError));
			},
			GUARDIAN_REVIEW_TIMEOUT_MS,
			ctx.signal,
		);
	}

	/** Manual fallback: prompt the user when the guardian can't decide. */
	async function askUser(ctx: ExtensionContext, title: string, detail: string): Promise<boolean> {
		if (!ctx.hasUI) return false;
		return await ctx.ui.confirm(title, detail);
	}

	function denialReason(toolName: string, verdict: GuardianAssessment): string {
		const risk = verdict.risk_level ?? "unknown";
		const auth = verdict.user_authorization ?? "unknown";
		const rationale = verdict.rationale ?? "no rationale provided";
		// Post-denial agent instructions mirror codex guardian/review.rs.
		return (
			`Automatic approval review denied ${toolName} (risk: ${risk}, authorization: ${auth}): ${rationale} ` +
			`Do not attempt to work around this denial. Proceed only with a materially safer alternative, ` +
			`or ask the user to explicitly approve this exact action.`
		);
	}

	pi.on("session_start", async (_event, ctx) => {
		setStatus(ctx, "guardian: auto");
	});

	pi.on("before_agent_start", async () => {
		// New user prompt = new turn: reset the consecutive-denial counter.
		consecutiveDenials = 0;
	});

	pi.on("tool_call", async (event, ctx) => {
		if (!enabled) return undefined;
		const input = event.input as Record<string, unknown>;
		if (passesStaticGates(event.toolName, input)) return undefined;

		if (breakerTripped) {
			const approved = await askUser(
				ctx,
				"Guardian paused (circuit breaker)",
				`Run ${event.toolName}?\n\n${truncate(JSON.stringify(input, null, 2), 2_000)}`,
			);
			if (approved) return undefined;
			return { block: true, reason: "Guardian circuit breaker active; user did not approve the action." };
		}

		setStatus(ctx, "guardian: reviewing…");
		stats.reviews += 1;
		let verdict: GuardianAssessment;
		try {
			verdict = await requestVerdict(ctx, event.toolName, input);
		} catch (error) {
			stats.failures += 1;
			setStatus(ctx, "guardian: auto");
			// Fail closed: never silently allow on guardian failure.
			const message = error instanceof Error ? error.message : String(error);
			logReview(event.toolName, { result: "failure", error: message });
			if (error instanceof GuardianReviewCancelledError) {
				// The tool call itself was aborted; there is nobody to ask.
				return { block: true, reason: "Automatic approval review was cancelled before it completed." };
			}
			const timedOut = error instanceof GuardianReviewTimeoutError;
			const rationale = timedOut
				? "Automatic approval review timed out while evaluating the requested approval."
				: `Automatic approval review failed: ${message}`;
			const approved = await askUser(
				ctx,
				timedOut ? "Guardian review timed out" : "Guardian review failed",
				`${rationale}\n\nRun ${event.toolName} anyway?\n\n${truncate(JSON.stringify(input, null, 2), 2_000)}`,
			);
			if (approved) return undefined;
			// No assessment was produced, so report a review failure rather than a
			// risk finding; the agent may retry once after a timeout.
			return { block: true, reason: `${rationale}\n${timedOut ? TIMEOUT_INSTRUCTIONS : REVIEW_FAILURE_INSTRUCTIONS}` };
		}
		setStatus(ctx, "guardian: auto");
		logReview(event.toolName, {
			result: verdict.outcome,
			risk: verdict.risk_level,
			authorization: verdict.user_authorization,
			rationale: verdict.rationale,
		});

		if (verdict.outcome === "allow") {
			stats.allowed += 1;
			recordReview(false);
			return undefined;
		}

		stats.denied += 1;
		recordReview(true);
		if (breakerTripped && ctx.hasUI) {
			ctx.ui.notify("Guardian circuit breaker tripped; falling back to manual prompts.", "warning");
			setStatus(ctx, "guardian: paused");
		}

		const reason = denialReason(event.toolName, verdict);
		const approved = await askUser(
			ctx,
			"Guardian denied this action",
			`${verdict.rationale ?? "No rationale."}\n\nrisk: ${verdict.risk_level ?? "?"} | authorization: ${verdict.user_authorization ?? "?"}\n\nAllow anyway?`,
		);
		if (approved) {
			stats.overridden += 1;
			// Manual approval mirrors Codex post-denial approval: trust the user.
			consecutiveDenials = 0;
			return undefined;
		}
		return { block: true, reason };
	});

	pi.registerCommand("guardian", {
		description: "Toggle the guardian or show its stats (usage: /guardian [on|off|stats])",
		handler: async (args, ctx) => {
			const arg = (args ?? "").trim();
			if (arg === "on") {
				enabled = true;
				breakerTripped = false;
				consecutiveDenials = 0;
				denialWindow.length = 0;
				setStatus(ctx, "guardian: auto");
				ctx.ui.notify("Guardian enabled", "info");
				return;
			}
			if (arg === "off") {
				enabled = false;
				setStatus(ctx, "guardian: off");
				ctx.ui.notify("Guardian disabled", "warning");
				return;
			}
			const state = !enabled ? "off" : breakerTripped ? "paused (circuit breaker)" : "auto";
			ctx.ui.notify(
				`Guardian ${state} - reviews: ${stats.reviews}, allowed: ${stats.allowed}, denied: ${stats.denied}, overridden: ${stats.overridden}, failures: ${stats.failures}`,
				"info",
			);
		},
	});
}
