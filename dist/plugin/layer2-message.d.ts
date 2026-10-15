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
/**
 * Detection-only handler for the V2 event stream. Events are observational
 * (they arrive after admission/transmission), so this cannot prevent
 * disclosure; it records findings for the audit log. Prevention happens in the
 * `prompt`, `context`, `compaction`, and `execute.after` hooks.
 */
export declare function handleMessageEvent(event: unknown, ctx: AuditContext): void;
export {};
//# sourceMappingURL=layer2-message.d.ts.map