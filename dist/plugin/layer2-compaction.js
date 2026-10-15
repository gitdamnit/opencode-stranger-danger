import { redactText } from "./redact.js";
import { redactMessages } from "./layer2-message.js";
/**
 * `ctx.session.hook("compaction")` — redact the transcript that is about to be
 * summarized in a checkpoint compaction, and, when the plugin supplies its own
 * summary via `event.result`, the summary text as well.
 *
 * Without this, a secret that survived in earlier history would be copied into
 * the compaction summary and re-injected into every later request.
 */
export async function handleCompaction(event, ctx) {
    try {
        const audit = { ...ctx, sessionId: event.sessionID };
        redactMessages(event.messages, "context", audit);
        if (event.result && typeof event.result.summary === "string") {
            event.result.summary = redactText(event.result.summary, "context", audit);
        }
    }
    catch {
        // Never block compaction.
    }
}
//# sourceMappingURL=layer2-compaction.js.map