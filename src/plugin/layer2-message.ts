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

/**
 * Detection-only handler for the V2 event stream. Events are observational
 * (they arrive after admission/transmission), so this cannot prevent
 * disclosure; it records findings for the audit log. Prevention happens in the
 * `prompt`, `context`, `compaction`, and `execute.after` hooks.
 */
export function handleMessageEvent(event: unknown, ctx: AuditContext): void {
    try {
        const e = event as Record<string, any> | undefined;
        const type = e && typeof e.type === "string" ? e.type : "";
        if (!type.startsWith("message")) return;

        const texts: string[] = [];
        const push = (v: unknown): void => {
            if (typeof v === "string" && v.length > 0 && v.length <= 200_000) texts.push(v);
        };
        if (e?.part && typeof e.part === "object") push(e.part.text);
        if (e?.properties && typeof e.properties === "object") push(e.properties.text);
        push(e?.text);

        for (const text of texts) {
            const { findings } = scanAndRedact(text, "message");
            recordFindings(findings, "message", ctx);
        }
    } catch {
        // Never break the event loop.
    }
}
