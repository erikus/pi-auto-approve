/**
 * Auto-approve extension for pi - LLM auto-approval of risky tool calls.
 *
 * Port of the OpenAI Codex "guardian" auto-review design (Apache-2.0,
 * github.com/openai/codex: codex-rs/core/src/guardian/ for request assembly,
 * codex-rs/guardian-context/ for transcript budgeting, codex-rs/ext/guardian-
 * reviewer/ for the review lifecycle, codex-rs/prompts/templates/guardian/ for
 * the prompts) onto pi's extension API. Layering mirrors Codex:
 *
 *   1. Static gates: read-only tools and an allowlist of safe bash commands
 *      run without review; writes/edits inside the workspace run without
 *      review (pi has no sandbox, so this stands in for workspace-write).
 *   2. Everything else goes to a reviewer model that judges the exact action
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
// Configuration constants (mirroring codex-rs/guardian-context/src/profile.rs
// and codex-rs/core/src/guardian/request_budget.rs; token limits converted to
// chars at CHARS_PER_TOKEN)
// ---------------------------------------------------------------------------

const AUTO_APPROVE_REVIEW_TIMEOUT_MS = 90_000;
const AUTO_APPROVE_MAX_ATTEMPTS = 3;

const MAX_CONSECUTIVE_DENIALS_PER_TURN = 3;
const DENIAL_WINDOW_SIZE = 50;
const MAX_WINDOW_DENIALS = 10;

const CHARS_PER_TOKEN = 4;
// Per-kind transcript retention. User messages are never capped or dropped
// here; they count against the message budget and are shortened only as a last
// resort by the whole-request budget below.
const MAX_RECENT_NON_USER_ENTRIES = 40;
const MAX_MESSAGE_TRANSCRIPT_CHARS = 20_000 * CHARS_PER_TOKEN;
const MAX_TOOL_TRANSCRIPT_CHARS = 10_000 * CHARS_PER_TOKEN;
const MAX_CHARS_PER_MESSAGE = 5_000 * CHARS_PER_TOKEN;
const MAX_CHARS_PER_TOOL_ENTRY = 1_000 * CHARS_PER_TOKEN;
/** The newest tool entries survive whole-request eviction. */
const MIN_RECENT_TOOL_ENTRIES = 5;
// Whole-request budget: the reviewer model's context window less a reply
// margin. The planned action is always sent complete; if it cannot fit beside
// the policy and the minimum evidence, the review fails rather than reviewing
// a shortened action.
const DEFAULT_MAX_INPUT_TOKENS = 128_000;
const INPUT_TOKEN_MARGIN = 256;
/** Floor when shortening a user message to make room (upstream: 32 tokens). */
const MIN_HISTORICAL_ENTRY_CHARS = 32 * CHARS_PER_TOKEN;

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
const PROJECT_POLICY_PATH = ".pi/auto-approve-policy.md";
const USER_POLICY_PATH = join(homedir(), ".pi", "agent", "auto-approve-policy.md");
// Optional extra policy text appended after the tenant policy (Codex's
// `[auto_review] extra_policy`). Project file wins over the user file; empty
// when neither exists.
const PROJECT_EXTRA_POLICY_PATH = ".pi/auto-approve-extra-policy.md";
const USER_EXTRA_POLICY_PATH = join(homedir(), ".pi", "agent", "auto-approve-extra-policy.md");
// Optional reviewer-model override, `{ "model": "<provider>/<model-id>" }`.
// Project file wins over the user file; with neither, the session's current
// model reviews. A malformed file is a configuration error and fails closed.
const PROJECT_REVIEWER_CONFIG_PATH = ".pi/auto-approve.json";
const USER_REVIEWER_CONFIG_PATH = join(homedir(), ".pi", "agent", "auto-approve.json");
const REVIEWER_MODEL_SEPARATOR = "/";

const TENANT_POLICY_CONFIG_PLACEHOLDER = "{{ tenant_policy_config }}";
const EXTRA_POLICY_PLACEHOLDER = "{{ extra_policy }}";

/** Set PI_AUTO_APPROVE_LOG=/path/to/file to append one JSON line per review. */
const AUTO_APPROVE_LOG_PATH = process.env.PI_AUTO_APPROVE_LOG;

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

interface AutoApproveAssessment {
	outcome: "allow" | "deny";
	risk_level?: RiskLevel;
	user_authorization?: UserAuthorization;
	rationale?: string;
}

interface AutoApproveStats {
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

// ---------------------------------------------------------------------------
// Reviewer model configuration
// ---------------------------------------------------------------------------

type ReviewerModel = NonNullable<ExtensionContext["model"]>;

export interface ReviewerModelRef {
	provider: string;
	modelId: string;
}

/**
 * Parse an auto-approve.json body. Anything other than
 * `{ "model": "<provider>/<model-id>" }` is a configuration error; the caller
 * lets it propagate so a gated action fails closed instead of silently
 * reviewing with a different model. `path` is only used in error messages.
 */
export function parseReviewerModelConfig(text: string, path: string): ReviewerModelRef {
	let parsed: unknown;
	try {
		parsed = JSON.parse(text);
	} catch (error) {
		throw new Error(`${path}: invalid JSON (${error instanceof Error ? error.message : String(error)})`);
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new Error(`${path}: expected a JSON object with a "model" field`);
	}
	const model = (parsed as Record<string, unknown>).model;
	if (typeof model !== "string") {
		throw new Error(`${path}: "model" must be a string of the form "<provider>/<model-id>"`);
	}
	// Split at the first separator only, as pi's own model resolver does: model
	// ids may themselves contain "/" (e.g. openrouter/anthropic/claude-opus-5).
	const separatorIndex = model.indexOf(REVIEWER_MODEL_SEPARATOR);
	const provider = separatorIndex === -1 ? "" : model.slice(0, separatorIndex);
	const modelId = separatorIndex === -1 ? "" : model.slice(separatorIndex + REVIEWER_MODEL_SEPARATOR.length);
	if (provider === "" || modelId === "") {
		throw new Error(
			`${path}: "model" must be "<provider>/<model-id>" with a non-empty provider and model id, got ${JSON.stringify(model)}`,
		);
	}
	return { provider, modelId };
}

interface ReviewerModelOverride {
	model: ReviewerModelRef;
	/** The config file the override was read from (for error messages). */
	path: string;
}

/** First existing config file wins; a missing file means no override. */
function loadReviewerModelConfig(): ReviewerModelOverride | undefined {
	const projectConfig = resolve(process.cwd(), PROJECT_REVIEWER_CONFIG_PATH);
	for (const path of [projectConfig, USER_REVIEWER_CONFIG_PATH]) {
		if (!existsSync(path)) continue;
		return { model: parseReviewerModelConfig(readFileSync(path, "utf8"), path), path };
	}
	return undefined;
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

/**
 * Shorten text to `maxChars`, keeping both ends around a marker so the start
 * (label, intent) and end (latest content) both survive. Mirrors
 * codex-rs/guardian-context/src/truncation.rs.
 */
export function truncate(text: string, maxChars: number): string {
	if (text.length <= maxChars) return text;
	const omittedTokens = Math.ceil((text.length - maxChars) / CHARS_PER_TOKEN);
	const marker = `<truncated omitted_approx_tokens="${omittedTokens}" />`;
	if (maxChars <= marker.length) return marker;
	const available = maxChars - marker.length;
	const prefix = Math.floor(available / 2);
	const suffix = available - prefix;
	return `${text.slice(0, prefix)}${marker}${text.slice(text.length - suffix)}`;
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
				// Only assistant text gets a per-entry cap; user text is authorization
				// evidence and is kept complete at this stage.
				if (message.role === "user") {
					sections.push({ kind: "user", text: `User: ${text}` });
				} else {
					sections.push({ kind: "assistant", text: `Assistant: ${truncate(text, MAX_CHARS_PER_MESSAGE)}` });
				}
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
 * How an item behaves under the whole-request budget (mirrors
 * codex-rs/guardian-context/src/enforcement.rs):
 *   required   - never shortened or dropped (policy, planned action, newest tools)
 *   historical - user messages: kept complete unless nothing else can make room,
 *                then shortened oldest-first with both ends preserved
 *   optional   - evicted first, lowest priority and oldest first
 */
type Retention = "required" | "historical" | { optional: BudgetPriority };
type BudgetPriority = "commentary" | "tool";
/** Eviction order: lower goes first. */
const BUDGET_PRIORITY_ORDER: Record<BudgetPriority, number> = { commentary: 0, tool: 1 };

export interface BudgetedItem {
	text: string;
	retention: Retention;
}

export interface SelectedTranscript {
	items: BudgetedItem[];
	/** Entries dropped by per-kind retention before the whole-request budget. */
	omitted: number;
}

/**
 * Per-kind transcript retention (codex-rs/guardian-context/src/profile.rs,
 * synchronous profile). Every user message is included so tool traffic can
 * never evict authorization evidence; user text still counts against the
 * message budget, so it crowds out assistant commentary rather than the
 * reverse. Non-user entries are kept newest-first within their budget.
 */
export function selectTranscript(entries: TranscriptEntry[]): SelectedTranscript {
	const included: boolean[] = entries.map(() => false);
	let messageChars = 0;
	entries.forEach((entry, index) => {
		if (entry.kind === "user") {
			included[index] = true;
			messageChars += entry.text.length;
		}
	});

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
		included[index] = true;
		retainedNonUserEntries += 1;
	}

	const items: BudgetedItem[] = [];
	entries.forEach((entry, index) => {
		if (!included[index]) return;
		const retention: Retention =
			entry.kind === "user" ? "historical" : { optional: entry.kind === "tool" ? "tool" : "commentary" };
		items.push({ text: entry.text, retention });
	});
	// Keep the newest tool evidence even when the aggregate allowance is tight.
	let protectedTools = 0;
	for (let index = items.length - 1; index >= 0 && protectedTools < MIN_RECENT_TOOL_ENTRIES; index--) {
		const item = items[index]!;
		if (typeof item.retention === "object" && item.retention.optional === "tool") {
			item.retention = "required";
			protectedTools += 1;
		}
	}
	return { items, omitted: entries.length - items.length };
}

// Reviewer-prompt marker tags keep Codex's `guardian_` names: policy_template.md
// (copied verbatim) tells the reviewer how to treat `<guardian_truncated ... />`.
function renderTranscript(selected: SelectedTranscript): string {
	if (selected.items.length === 0 && selected.omitted === 0) return "<no retained transcript entries>";
	const lines = selected.items.map((item) => item.text);
	if (selected.omitted > 0) lines.push(`<guardian_truncated omitted_transcript_entries="${selected.omitted}"/>`);
	return lines.join("\n\n");
}

/** Per-kind retention only; the whole-request budget is applied in composeReviewPrompt. */
export function buildTranscript(ctx: ExtensionContext): string {
	return renderTranscript(selectTranscript(collectTranscriptEntries(ctx)));
}

function sortActionValue(value: unknown, path: string, ancestors: WeakSet<object>): unknown {
	if (!value || typeof value !== "object") return value;
	if (ancestors.has(value)) throw new TypeError(`planned action contains a circular value at ${path}`);
	ancestors.add(value);
	try {
		if (Array.isArray(value)) {
			return value.map((item, index) => sortActionValue(item, `${path}[${index}]`, ancestors));
		}
		return Object.fromEntries(
			Object.entries(value as Record<string, unknown>)
				.sort(([left], [right]) => left.localeCompare(right))
				.map(([key, item]) => [key, sortActionValue(item, path ? `${path}.${key}` : key, ancestors)]),
		);
	} finally {
		ancestors.delete(value);
	}
}

/**
 * Format the complete action as sorted JSON. Nothing is ever shortened here:
 * the reviewer must see every executable byte, so an action that does not fit
 * the request budget fails the review instead.
 */
export function formatPlannedAction(toolName: string, input: unknown): string {
	const action = { input, tool: toolName, working_directory: process.cwd() };
	return JSON.stringify(sortActionValue(action, "", new WeakSet()), null, 2);
}

export class AutoApproveInputBudgetError extends Error {
	constructor() {
		super("the complete action and minimum review context exceed the reviewer input budget");
		this.name = "AutoApproveInputBudgetError";
	}
}

const CONTEXT_OMISSION_NOTICE =
	"<guardian_context_omission>\n" +
	"Conversation evidence was omitted or shortened to fit the review input budget. " +
	"User instructions and prior approvals may be incomplete where marked. " +
	"Do not infer authorization from missing evidence or treat a partial grant as overriding an omitted restriction.\n" +
	"</guardian_context_omission>";

const SECTION_SEPARATOR = "\n\n";

export interface ReviewPromptParts {
	/** Policy instructions and output contract (required). */
	instructions: string;
	transcript: SelectedTranscript;
	/** Complete planned action JSON (required). */
	action: string;
	maxInputTokens: number;
}

/**
 * Fit the review request into the reviewer's input budget
 * (codex-rs/guardian-context/src/enforcement.rs). Required content is never
 * touched. If the rest does not fit: shorten user messages oldest-first only
 * when required content alone overflows, then evict optional evidence lowest
 * priority and oldest first, and add an omission notice. Throws
 * AutoApproveInputBudgetError when the required content cannot fit at all.
 */
export function composeReviewPrompt(parts: ReviewPromptParts): string {
	const budgetChars = Math.max(0, parts.maxInputTokens - INPUT_TOKEN_MARGIN) * CHARS_PER_TOKEN;
	const items = parts.transcript.items.map((item) => ({ ...item }));
	const render = (kept: BudgetedItem[], omitted: number, notice: string) =>
		[
			parts.instructions,
			...(notice ? [notice] : []),
			"# Transcript (untrusted evidence)",
			`<transcript>\n${renderTranscript({ items: kept, omitted })}\n</transcript>`,
			"# Planned Action (untrusted evidence)",
			`<planned_action>\n${parts.action}\n</planned_action>`,
		].join(SECTION_SEPARATOR);

	const complete = render(items, parts.transcript.omitted, "");
	if (complete.length <= budgetChars) return complete;

	const notice = CONTEXT_OMISSION_NOTICE;
	const itemChars = (item: BudgetedItem) => item.text.length + SECTION_SEPARATOR.length;
	const isOptional = (item: BudgetedItem) => typeof item.retention === "object";
	let requiredChars = render(items.filter((item) => !isOptional(item)), parts.transcript.omitted, notice).length;
	let historyShortened = false;

	// Historical (user) entries yield oldest-first, only when required content
	// alone overflows. Both ends and the label survive around the marker.
	for (const item of items) {
		if (requiredChars <= budgetChars) break;
		if (item.retention !== "historical") continue;
		const target = Math.max(MIN_HISTORICAL_ENTRY_CHARS, item.text.length - (requiredChars - budgetChars));
		const shortened = truncate(item.text, target);
		if (shortened.length >= item.text.length) continue;
		requiredChars -= item.text.length - shortened.length;
		item.text = shortened;
		historyShortened = true;
	}
	if (requiredChars > budgetChars) throw new AutoApproveInputBudgetError();

	// Optional evidence that cannot fit beside the required content leaves
	// first; then evict lowest priority, oldest first, until within budget.
	const optionalAllowance = budgetChars - requiredChars;
	const removed = new Set<number>();
	const candidates: Array<{ order: number; index: number }> = [];
	items.forEach((item, index) => {
		if (typeof item.retention !== "object") return;
		if (itemChars(item) > optionalAllowance) removed.add(index);
		else candidates.push({ order: BUDGET_PRIORITY_ORDER[item.retention.optional], index });
	});
	candidates.sort((a, b) => a.order - b.order || a.index - b.index);
	const renderKept = () =>
		render(
			items.filter((_item, index) => !removed.has(index)),
			parts.transcript.omitted + removed.size,
			notice,
		);
	let prompt = renderKept();
	for (const candidate of candidates) {
		if (prompt.length <= budgetChars) break;
		removed.add(candidate.index);
		prompt = renderKept();
	}
	if (removed.size === 0 && !historyShortened) throw new AutoApproveInputBudgetError();
	if (prompt.length > budgetChars) throw new AutoApproveInputBudgetError();
	return prompt;
}

function buildReviewPrompt(ctx: ExtensionContext, toolName: string, input: unknown, maxInputTokens: number): string {
	const instructions = renderPolicyInstructions(loadPolicyTemplate(), loadTenantPolicy(), loadExtraPolicy());
	return composeReviewPrompt({
		instructions: `${instructions.trim()}${SECTION_SEPARATOR}${OUTPUT_CONTRACT.trim()}`,
		transcript: selectTranscript(collectTranscriptEntries(ctx)),
		action: formatPlannedAction(toolName, input),
		maxInputTokens,
	});
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

/** True when the action can run without model review. */
export function passesStaticGates(toolName: string, input: Record<string, unknown>): boolean {
	if (READ_ONLY_TOOLS.has(toolName)) return true;
	if (WORKSPACE_WRITE_TOOLS.has(toolName)) return isWorkspacePath(input.path);
	if (toolName === "bash" && typeof input.command === "string") {
		return isSafeBashCommand(input.command);
	}
	return false;
}

// ---------------------------------------------------------------------------
// Reviewer
// ---------------------------------------------------------------------------

export function parseVerdict(text: string): AutoApproveAssessment | undefined {
	const candidates = [text.trim()];
	const start = text.indexOf("{");
	const end = text.lastIndexOf("}");
	if (start >= 0 && end > start) candidates.push(text.slice(start, end + 1));
	for (const candidate of candidates) {
		try {
			const parsed = JSON.parse(candidate) as Record<string, unknown>;
			if (parsed.outcome === "allow" || parsed.outcome === "deny") {
				return parsed as unknown as AutoApproveAssessment;
			}
		} catch {
			// try next candidate
		}
	}
	return undefined;
}

export class AutoApproveReviewTimeoutError extends Error {
	constructor(ms: number) {
		super(`auto-approve review timed out after ${ms}ms`);
		this.name = "AutoApproveReviewTimeoutError";
	}
}

class AutoApproveReviewCancelledError extends Error {
	constructor() {
		super("auto-approve review cancelled");
		this.name = "AutoApproveReviewCancelledError";
	}
}

class AutoApproveVerdictParseError extends Error {
	constructor(text: string) {
		super(`unparseable reviewer verdict: ${text.slice(0, 200)}`);
		this.name = "AutoApproveVerdictParseError";
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
		const onParentAbort = () => rejectOnce(new AutoApproveReviewCancelledError());
		const timer = setTimeout(() => rejectOnce(new AutoApproveReviewTimeoutError(ms)), ms);
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

function reviewerRetryDelayMs(attempt: number): number {
	const base = 200 * 2 ** Math.max(0, attempt - 1);
	return Math.round(base * (0.9 + Math.random() * 0.2));
}

function abortableSleep(ms: number, signal: AbortSignal): Promise<void> {
	return new Promise((resolvePromise, rejectPromise) => {
		if (signal.aborted) {
			rejectPromise(signal.reason ?? new AutoApproveReviewCancelledError());
			return;
		}
		const onAbort = () => {
			clearTimeout(timer);
			rejectPromise(signal.reason ?? new AutoApproveReviewCancelledError());
		};
		const timer = setTimeout(() => {
			signal.removeEventListener("abort", onAbort);
			resolvePromise();
		}, ms);
		signal.addEventListener("abort", onAbort, { once: true });
	});
}

function reviewerErrorStatus(error: unknown): number | undefined {
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
function isRetryableReviewerError(error: unknown): boolean {
	if (error instanceof AutoApproveVerdictParseError) return true;
	if (error instanceof AutoApproveReviewTimeoutError || error instanceof AutoApproveReviewCancelledError) return false;
	const status = reviewerErrorStatus(error);
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

export default function autoApproveExtension(pi: ExtensionAPI) {
	const reviewerSessionId = randomUUID();
	const stats: AutoApproveStats = { reviews: 0, allowed: 0, denied: 0, overridden: 0, failures: 0 };

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
		if (ctx.hasUI) ctx.ui.setStatus("auto-approve", text);
	}

	function logReview(toolName: string, entry: Record<string, unknown>) {
		if (!AUTO_APPROVE_LOG_PATH) return;
		try {
			appendFileSync(AUTO_APPROVE_LOG_PATH, `${JSON.stringify({ time: new Date().toISOString(), tool: toolName, ...entry })}\n`);
		} catch {
			// logging must never break the approval flow
		}
	}

	/**
	 * A configured override must resolve to an authenticated model or the
	 * review fails closed; without an override the session's model reviews.
	 */
	function resolveReviewerModel(ctx: ExtensionContext): ReviewerModel | undefined {
		const override = loadReviewerModelConfig();
		if (override) {
			const { provider, modelId } = override.model;
			const label = `${provider}${REVIEWER_MODEL_SEPARATOR}${modelId}`;
			const model = ctx.modelRegistry.find(provider, modelId);
			if (!model) throw new Error(`${override.path}: reviewer model ${label} is not in pi's model registry`);
			if (!ctx.modelRegistry.hasConfiguredAuth(model)) {
				throw new Error(`${override.path}: reviewer model ${label} has no configured auth`);
			}
			return model;
		}
		if (ctx.model && ctx.modelRegistry.hasConfiguredAuth(ctx.model)) return ctx.model;
		return undefined;
	}

	async function requestVerdict(
		ctx: ExtensionContext,
		toolName: string,
		input: unknown,
	): Promise<AutoApproveAssessment> {
		const model = resolveReviewerModel(ctx);
		if (!model) throw new Error("no reviewer model with configured auth");
		// Codex additionally scales by the model's effective context-window
		// percent; pi has no such field, so the full window applies.
		const maxInputTokens = model.contextWindow > 0 ? model.contextWindow : DEFAULT_MAX_INPUT_TOKENS;
		const prompt = buildReviewPrompt(ctx, toolName, input, maxInputTokens);
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
				for (let attempt = 1; attempt <= AUTO_APPROVE_MAX_ATTEMPTS; attempt++) {
					try {
						const response = await ctx.modelRegistry.complete(
							model,
							{ messages },
							{
								effort: "low",
								sessionId: reviewerSessionId,
								signal,
								maxRetries: 0,
								timeoutMs: AUTO_APPROVE_REVIEW_TIMEOUT_MS,
							},
						);
						if (response.stopReason === "aborted") throw new AutoApproveReviewCancelledError();
						if (response.stopReason === "error") {
							throw new Error(response.errorMessage ?? "reviewer model request failed");
						}
						const text = response.content
							.filter((c): c is { type: "text"; text: string } => c.type === "text")
							.map((c) => c.text)
							.join("\n");
						const verdict = parseVerdict(text);
						if (verdict) return verdict;
						throw new AutoApproveVerdictParseError(text);
					} catch (error) {
						lastError = error;
						if (attempt >= AUTO_APPROVE_MAX_ATTEMPTS || !isRetryableReviewerError(error)) break;
						await abortableSleep(reviewerRetryDelayMs(attempt), signal);
					}
				}
				throw lastError instanceof Error ? lastError : new Error(String(lastError));
			},
			AUTO_APPROVE_REVIEW_TIMEOUT_MS,
			ctx.signal,
		);
	}

	/** Manual fallback: prompt the user when the reviewer can't decide. */
	async function askUser(ctx: ExtensionContext, title: string, detail: string): Promise<boolean> {
		if (!ctx.hasUI) return false;
		return await ctx.ui.confirm(title, detail);
	}

	function denialReason(toolName: string, verdict: AutoApproveAssessment): string {
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
		setStatus(ctx, "auto-approve: auto");
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
				"Auto-approve paused (circuit breaker)",
				`Run ${event.toolName}?\n\n${truncate(JSON.stringify(input, null, 2), 2_000)}`,
			);
			if (approved) return undefined;
			return { block: true, reason: "Auto-approve circuit breaker active; user did not approve the action." };
		}

		setStatus(ctx, "auto-approve: reviewing…");
		stats.reviews += 1;
		let verdict: AutoApproveAssessment;
		try {
			verdict = await requestVerdict(ctx, event.toolName, input);
		} catch (error) {
			stats.failures += 1;
			setStatus(ctx, "auto-approve: auto");
			// Fail closed: never silently allow on review failure.
			const message = error instanceof Error ? error.message : String(error);
			logReview(event.toolName, { result: "failure", error: message });
			if (error instanceof AutoApproveReviewCancelledError) {
				// The tool call itself was aborted; there is nobody to ask.
				return { block: true, reason: "Automatic approval review was cancelled before it completed." };
			}
			const timedOut = error instanceof AutoApproveReviewTimeoutError;
			const rationale = timedOut
				? "Automatic approval review timed out while evaluating the requested approval."
				: `Automatic approval review failed: ${message}`;
			const approved = await askUser(
				ctx,
				timedOut ? "Auto-approve review timed out" : "Auto-approve review failed",
				`${rationale}\n\nRun ${event.toolName} anyway?\n\n${truncate(JSON.stringify(input, null, 2), 2_000)}`,
			);
			if (approved) return undefined;
			// No assessment was produced, so report a review failure rather than a
			// risk finding; the agent may retry once after a timeout.
			return { block: true, reason: `${rationale}\n${timedOut ? TIMEOUT_INSTRUCTIONS : REVIEW_FAILURE_INSTRUCTIONS}` };
		}
		setStatus(ctx, "auto-approve: auto");
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
			ctx.ui.notify("Auto-approve circuit breaker tripped; falling back to manual prompts.", "warning");
			setStatus(ctx, "auto-approve: paused");
		}

		const reason = denialReason(event.toolName, verdict);
		const approved = await askUser(
			ctx,
			"Auto-approve denied this action",
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

	pi.registerCommand("auto-approve", {
		description: "Toggle auto-approve or show its stats (usage: /auto-approve [on|off|stats])",
		handler: async (args, ctx) => {
			const arg = (args ?? "").trim();
			if (arg === "on") {
				enabled = true;
				breakerTripped = false;
				consecutiveDenials = 0;
				denialWindow.length = 0;
				setStatus(ctx, "auto-approve: auto");
				ctx.ui.notify("Auto-approve enabled", "info");
				return;
			}
			if (arg === "off") {
				enabled = false;
				setStatus(ctx, "auto-approve: off");
				ctx.ui.notify("Auto-approve disabled", "warning");
				return;
			}
			const state = !enabled ? "off" : breakerTripped ? "paused (circuit breaker)" : "auto";
			ctx.ui.notify(
				`Auto-approve ${state} - reviews: ${stats.reviews}, allowed: ${stats.allowed}, denied: ${stats.denied}, overridden: ${stats.overridden}, failures: ${stats.failures}`,
				"info",
			);
		},
	});
}
