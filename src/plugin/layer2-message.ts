import { scanAndRedact } from "../engine/scanner.js";
import { redactText, redactStructured, recordFindings, type AuditContext } from "./redact.js";
import type { Finding } from "../engine/types.js";

/** Minimal structural types for the V2 session hook events we consume. */

export type SessionPromptEvent = {
    sessionID?: string;
    prompt?: { text?: unknown };
};

export type SessionContextEvent = {
    sessionID?: string;
    system?: unknown;
    messages?: unknown;
};

type Audit = { auditPath?: string; sessionId?: string };

function withSession(ctx: AuditContext, sessionID?: string): Audit {
    return { auditPath: ctx.auditPath, sessionId: sessionID };
}

/** Redact the `text` field of a message part in place, based on its type. */
function redactMessagePart(part: unknown, source: Finding["source"], ctx: Audit): void {
    if (!part || typeof part !== "object") return;
    const p = part as Record<string, any>;
    switch (p.type) {
        case "text":
        case "reasoning":
        case "compaction":
            if (typeof p.text === "string") p.text = redactText(p.text, source, ctx);
            break;
        case "tool-call":
            if (p.input !== undefined) p.input = redactStructured(p.input, source, ctx);
            break;
        case "tool-result": {
            const r = p.result;
            if (r && typeof r === "object") {
                if (r.type === "content" && Array.isArray(r.value)) {
                    for (const c of r.value) {
                        if (c && typeof c === "object" && typeof c.text === "string") {
                            c.text = redactText(c.text, source, ctx);
                        }
                    }
                } else if (typeof r.value === "string") {
                    r.value = redactText(r.value, source, ctx);
                } else if (r.value !== undefined) {
                    r.value = redactStructured(r.value, source, ctx);
                }
            }
            break;
        }
        default:
            // Unknown part kinds (media, effort, ...) are left untouched.
            break;
    }
}

/** Redact every text-bearing part of an array of messages, in place. */
export function redactMessages(messages: unknown, source: Finding["source"], ctx: Audit): void {
    if (!Array.isArray(messages)) return;
    for (const message of messages) {
        if (!message || typeof message !== "object") continue;
        const content = (message as Record<string, any>).content;
        if (Array.isArray(content)) {
            for (const part of content) redactMessagePart(part, source, ctx);
        }
    }
}

/**
 * `ctx.session.hook("prompt")` — redact the incoming user prompt before it is
 * durably admitted and before attachments/skills are resolved. This is the
 * earliest supported point that still affects persisted input.
 */
export async function handlePrompt(event: SessionPromptEvent, ctx: AuditContext): Promise<void> {
    try {
        const prompt = event.prompt;
        if (!prompt || typeof prompt.text !== "string") return;
        prompt.text = redactText(prompt.text, "message", withSession(ctx, event.sessionID));
    } catch {
        // Never block prompt admission.
    }
}

/**
 * `ctx.session.hook("context")` — redact the assembled system instructions and
 * message transcript immediately before the agent model request. This covers
 * normal prompts, tool-driven continuations, and everything else in the agent
 * loop, including the already-redacted tool results.
 */
export async function handleContext(event: SessionContextEvent, ctx: AuditContext): Promise<void> {
    try {
        const audit = withSession(ctx, event.sessionID);
        if (Array.isArray(event.system)) {
            for (const part of event.system) {
                if (part && typeof part === "object" && typeof (part as any).text === "string") {
                    (part as any).text = redactText((part as any).text, "context", audit);
                }
            }
        }
        redactMessages(event.messages, "context", audit);
    } catch {
        // Never break a model request.
    }
}

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
export async function handleGenerate(event: SessionGenerateEvent, ctx: AuditContext): Promise<void> {
    await handleContext(event, ctx);
}

/**
 * `ctx.session.hook("title")` — title generation. System/messages have the same
 * shape as `context`; additionally redact an explicitly supplied `result`
 * string so a title cannot persist a secret either.
 */
export async function handleTitle(event: SessionTitleEvent, ctx: AuditContext): Promise<void> {
    try {
        await handleContext(event, ctx);
        if (typeof event.result === "string") {
            event.result = redactText(event.result, "context", withSession(ctx, event.sessionID));
        }
    } catch {
        // Never break title generation.
    }
}

/** Largest single text field scanned from an event (events are untrusted input). */
const MAX_EVENT_TEXT = 200_000;

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
export function handleMessageEvent(event: unknown, ctx: AuditContext): void {
    try {
        const e = event as Record<string, any> | null | undefined;
        if (!e || typeof e !== "object") return;
        const type = typeof e.type === "string" ? e.type : "";
        if (!type.startsWith("session.") || type.endsWith(".delta")) return;

        const data = e.data;
        if (!data || typeof data !== "object") return;

        const texts: string[] = [];
        const push = (v: unknown): void => {
            if (typeof v === "string" && v.length > 0 && v.length <= MAX_EVENT_TEXT) texts.push(v);
        };
        push(data.text);
        if (Array.isArray(data.content)) {
            for (const c of data.content) {
                if (c && typeof c === "object") push((c as Record<string, unknown>).text);
            }
        }
        if (data.error && typeof data.error === "object") push((data.error as Record<string, unknown>).message);

        for (const text of texts) {
            const { findings } = scanAndRedact(text, "message");
            recordFindings(findings, "message", ctx);
        }
    } catch {
        // Never break the event loop.
    }
}
