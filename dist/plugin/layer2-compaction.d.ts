import { type AuditContext } from "./redact.js";
export type SessionCompactionEvent = {
    sessionID?: string;
    messages?: unknown;
    result?: {
        summary?: unknown;
    } | undefined;
};
/**
 * `ctx.session.hook("compaction")` — redact the transcript that is about to be
 * summarized in a checkpoint compaction, and, when the plugin supplies its own
 * summary via `event.result`, the summary text as well.
 *
 * Without this, a secret that survived in earlier history would be copied into
 * the compaction summary and re-injected into every later request.
 */
export declare function handleCompaction(event: SessionCompactionEvent, ctx: AuditContext): Promise<void>;
//# sourceMappingURL=layer2-compaction.d.ts.map