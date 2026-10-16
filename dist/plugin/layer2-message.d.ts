import { type AuditContext } from "./redact.js";
import type { Finding } from "../engine/types.js";
/** Minimal structural types for the V2 session hook events we consume. */
export type SessionPromptEvent = {
    sessionID?: string;
    prompt?: {
        text?: unknown;
    };
};
export type SessionContextEvent = {
    sessionID?: string;
    system?: unknown;
    messages?: unknown;
};
type Audit = {
    auditPath?: string;
    sessionId?: string;
};
/** Redact every text-bearing part of an array of messages, in place. */
export declare function redactMessages(messages: unknown, source: Finding["source"], ctx: Audit): void;
/**
 * `ctx.session.hook("prompt")` — redact the incoming user prompt before it is
 * durably admitted and before attachments/skills are resolved. This is the
 * earliest supported point that still affects persisted input.
 */
export declare function handlePrompt(event: SessionPromptEvent, ctx: AuditContext): Promise<void>;
/**
 * `ctx.session.hook("context")` — redact the assembled system instructions and
 * message transcript immediately before the agent model request. This covers
 * normal prompts, tool-driven continuations, and everything else in the agent
 * loop, including the already-redacted tool results.
 */
export declare function handleContext(event: SessionContextEvent, ctx: AuditContext): Promise<void>;
export type SessionGenerateEvent = SessionContextEvent;
export type SessionTitleEvent = SessionContextEvent & {
    /** When set, the plugin supplies the title and the model call is skipped. */
    result?: unknown;
};
/**
 * `ctx.session.hook("generate")` — transient `ctx.session.generate` requests.
 * Same request shape as `context`, so the same redaction applies. Without this
 * hook, text supplied to `session.generate` would be sent uninspected.
 */
export declare function handleGenerate(event: SessionGenerateEvent, ctx: AuditContext): Promise<void>;
/**
 * `ctx.session.hook("title")` — title generation. System/messages have the same
 * shape as `context`; additionally redact an explicitly supplied `result`
 * string so a title cannot persist a secret either.
 */
export declare function handleTitle(event: SessionTitleEvent, ctx: AuditContext): Promise<void>;
/**
 * Detection-only handler for the V2 event stream. Events are observational
 * (they arrive after admission/transmission), so this cannot prevent
 * disclosure; it records findings for the audit log. Prevention happens in the
 * `prompt`, `context`, `compaction`, `generate`, and `execute.after` hooks.
 *
 * V2 event types are namespaced `session.*` (for example `session.text.ended`,
 * `session.tool.success`, `session.synthetic`). Per-token `*.delta` frames are
 * skipped on purpose: they are chatty and the completed event carries the same
 * text, so auditing them would only duplicate records.
 */
export declare function handleMessageEvent(event: unknown, ctx: AuditContext): void;
export {};
//# sourceMappingURL=layer2-message.d.ts.map