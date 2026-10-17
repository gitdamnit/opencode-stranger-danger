import { Plugin } from "@opencode/plugin";
/**
 * strangerDanger — OpenCode V2 plugin.
 *
 * Protection boundaries (all supported V2 APIs):
 *   - `session.prompt`      → redact the incoming user prompt before admission.
 *   - `tool.execute.after`  → redact tool results (read/bash/grep/fetch/...).
 *   - `session.context`     → redact the assembled agent-loop model request.
 *   - `session.generate`    → redact transient `session.generate` requests.
 *   - `session.title`       → redact title-generation requests.
 *   - `session.compaction`  → redact the transcript being summarized.
 *   - `tool.execute.before` → read-only detection/audit for file tools (never writes).
 *
 * The V1 `event` callback is migrated to `ctx.event.subscribe()` and is used for
 * detection/audit only: the event stream is observational and cannot prevent an
 * already-admitted request from being transmitted.
 *
 * Known limitations (documented in the README):
 *   - `http.request`/`http.response` bodies are not inspected; the message-level
 *     hooks above cover the supported request path.
 *   - Provider-native WebSocket traffic is not covered. OpenCode exposes
 *     experimental `experimental.ws.handshake/send/receive` hooks; registering
 *     them is deliberately out of scope.
 */
export declare const strangerDanger: Plugin.Plugin;
export default strangerDanger;
//# sourceMappingURL=index.d.ts.map