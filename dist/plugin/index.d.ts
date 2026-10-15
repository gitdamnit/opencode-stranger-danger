import { Plugin } from "@opencode/plugin";
/**
 * strangerDanger — OpenCode V2 plugin.
 *
 * Protection boundaries (all supported V2 APIs):
 *   - `session.prompt`      → redact the incoming user prompt before admission.
 *   - `tool.execute.after`  → redact tool results (read/bash/grep/fetch/...).
 *   - `session.context`     → redact the assembled model request (system + messages).
 *   - `session.compaction`  → redact the transcript being summarized.
 *   - `tool.execute.before` → read-only detection/audit for file tools (never writes).
 *
 * The V1 `event` callback is migrated to `ctx.event.subscribe()` and is used for
 * detection/audit only: the event stream is observational and cannot prevent an
 * already-admitted request from being transmitted.
 *
 * Known limitation: provider-native WebSocket traffic that bypasses the
 * session HTTP pipeline is not covered by these hooks. Everything routed
 * through the session model-request pipeline is.
 */
export declare const strangerDanger: Plugin.Plugin;
export default strangerDanger;
//# sourceMappingURL=index.d.ts.map