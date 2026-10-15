import { redactText, redactStructured, type AuditContext } from "./redact.js";

export type ToolResultLike = {
    content?: unknown;
    output?: unknown;
    metadata?: unknown;
};

export type Layer3Event = {
    tool?: string;
    sessionID?: string;
    status?: "completed" | "error" | string;
    result?: ToolResultLike;
    error?: { message?: string; error?: unknown };
};

/**
 * Post-execution redaction of tool results (`ctx.tool.hook("execute.after")`).
 *
 * This is the boundary that keeps secrets out of the model context when a tool
 * (read, bash, grep, fetch, ...) returns them. It redacts:
 *
 *   - `result.content` when it is a string, or the `text` of text content parts;
 *   - `result.output` (structured output) by redacting string leaves only, so
 *     the shape and types are preserved;
 *   - `result.metadata` likewise.
 *
 * Scanning is chunk-safe and bounded (see `scanAndRedactBounded`): large
 * outputs are fully covered, and content that cannot be inspected fails closed
 * with an explicit marker instead of leaking.
 */
export async function handleLayer3(event: Layer3Event, ctx: AuditContext): Promise<void> {
    try {
        const audit: AuditContext = { ...ctx, sessionId: event.sessionID };

        if (event.status === "error") {
            const message = event.error?.message;
            if (typeof message === "string") event.error!.message = redactText(message, "output", audit);
            if (event.error && "error" in event.error) {
                event.error.error = redactStructured(event.error.error, "output", audit);
            }
            return;
        }

        const result = event.result;
        if (!result || typeof result !== "object") return;

        if (typeof result.content === "string") {
            result.content = redactText(result.content, "output", audit);
        } else if (Array.isArray(result.content)) {
            for (const part of result.content) {
                if (part && typeof part === "object") {
                    const p = part as { type?: unknown; text?: unknown };
                    if (typeof p.text === "string") p.text = redactText(p.text, "output", audit);
                }
            }
        }

        if (result.output !== undefined) {
            result.output = redactStructured(result.output, "output", audit);
        }
        if (result.metadata !== undefined) {
            result.metadata = redactStructured(result.metadata, "output", audit);
        }
    } catch {
        // Degrade gracefully — never break a tool call.
    }
}
