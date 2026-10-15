import { scanAndRedact } from "../engine/scanner.js";
import { redactText, redactStructured, recordFindings } from "./redact.js";
function withSession(ctx, sessionID) {
    return { auditPath: ctx.auditPath, sessionId: sessionID };
}
/** Redact the `text` field of a message part in place, based on its type. */
function redactMessagePart(part, source, ctx) {
    if (!part || typeof part !== "object")
        return;
    const p = part;
    switch (p.type) {
        case "text":
        case "reasoning":
        case "compaction":
            if (typeof p.text === "string")
                p.text = redactText(p.text, source, ctx);
            break;
        case "tool-call":
            if (p.input !== undefined)
                p.input = redactStructured(p.input, source, ctx);
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
                }
                else if (typeof r.value === "string") {
                    r.value = redactText(r.value, source, ctx);
                }
                else if (r.value !== undefined) {
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
export function redactMessages(messages, source, ctx) {
    if (!Array.isArray(messages))
        return;
    for (const message of messages) {
        if (!message || typeof message !== "object")
            continue;
        const content = message.content;
        if (Array.isArray(content)) {
            for (const part of content)
                redactMessagePart(part, source, ctx);
        }
    }
}
/**
 * `ctx.session.hook("prompt")` — redact the incoming user prompt before it is
 * durably admitted and before attachments/skills are resolved. This is the
 * earliest supported point that still affects persisted input.
 */
export async function handlePrompt(event, ctx) {
    try {
        const prompt = event.prompt;
        if (!prompt || typeof prompt.text !== "string")
            return;
        prompt.text = redactText(prompt.text, "message", withSession(ctx, event.sessionID));
    }
    catch {
        // Never block prompt admission.
    }
}
/**
 * `ctx.session.hook("context")` — redact the assembled system instructions and
 * message transcript immediately before the agent model request. This covers
 * normal prompts, tool-driven continuations, and everything else in the agent
 * loop, including the already-redacted tool results.
 */
export async function handleContext(event, ctx) {
    try {
        const audit = withSession(ctx, event.sessionID);
        if (Array.isArray(event.system)) {
            for (const part of event.system) {
                if (part && typeof part === "object" && typeof part.text === "string") {
                    part.text = redactText(part.text, "context", audit);
                }
            }
        }
        redactMessages(event.messages, "context", audit);
    }
    catch {
        // Never break a model request.
    }
}
/**
 * Detection-only handler for the V2 event stream. Events are observational
 * (they arrive after admission/transmission), so this cannot prevent
 * disclosure; it records findings for the audit log. Prevention happens in the
 * `prompt`, `context`, `compaction`, and `execute.after` hooks.
 */
export function handleMessageEvent(event, ctx) {
    try {
        const e = event;
        const type = e && typeof e.type === "string" ? e.type : "";
        if (!type.startsWith("message"))
            return;
        const texts = [];
        const push = (v) => {
            if (typeof v === "string" && v.length > 0 && v.length <= 200_000)
                texts.push(v);
        };
        if (e?.part && typeof e.part === "object")
            push(e.part.text);
        if (e?.properties && typeof e.properties === "object")
            push(e.properties.text);
        push(e?.text);
        for (const text of texts) {
            const { findings } = scanAndRedact(text, "message");
            recordFindings(findings, "message", ctx);
        }
    }
    catch {
        // Never break the event loop.
    }
}
//# sourceMappingURL=layer2-message.js.map