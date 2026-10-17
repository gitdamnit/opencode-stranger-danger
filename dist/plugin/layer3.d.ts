import { type AuditContext } from "./redact.js";
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
    error?: {
        message?: string;
        error?: unknown;
        metadata?: unknown;
    };
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
export declare function handleLayer3(event: Layer3Event, ctx: AuditContext): Promise<void>;
//# sourceMappingURL=layer3.d.ts.map