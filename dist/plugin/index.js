import { Plugin } from "@opencode/plugin";
import { resolveAuditPath } from "../engine/audit.js";
import { handleLayer1 } from "./layer1.js";
import { handleLayer3 } from "./layer3.js";
import { handlePrompt, handleContext, handleMessageEvent } from "./layer2-message.js";
import { handleCompaction } from "./layer2-compaction.js";
import { sdStatus, sdAudit, sdAllowlistAdd, sdAllowlistShow, sdScan } from "./tools.js";
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
export const strangerDanger = Plugin.define({
    id: "gitdamnit.stranger-danger",
    async setup(ctx) {
        const auditPath = resolveAuditPath({ directory: ctx.location?.directory });
        const audit = { auditPath };
        // --- Tools ---------------------------------------------------------
        await ctx.tool.transform((editor) => {
            editor.add({
                name: "sd_status",
                description: "Show strangerDanger status — rule count, findings this session, audit log path",
                input: { type: "object", properties: {}, additionalProperties: false },
                execute: async () => ({ content: sdStatus({ auditPath }) }),
            });
            editor.add({
                name: "sd_audit",
                description: "Show the strangerDanger audit log — redactions made, with timestamps and rule IDs (no raw secrets)",
                input: { type: "object", properties: {}, additionalProperties: false },
                execute: async () => ({ content: sdAudit({ auditPath }) }),
            });
            editor.add({
                name: "sd_allowlist_add",
                description: "Add an entry to the allowlist — by fingerprint, ruleId, path, or regex",
                input: {
                    type: "object",
                    properties: {
                        description: { type: "string" },
                        fingerprint: { type: "string" },
                        ruleId: { type: "string" },
                        path: { type: "string" },
                        regex: { type: "string" },
                    },
                    additionalProperties: false,
                },
                execute: async (input) => ({ content: sdAllowlistAdd(input ?? {}) }),
            });
            editor.add({
                name: "sd_allowlist_show",
                description: "Show current allowlist entries",
                input: { type: "object", properties: {}, additionalProperties: false },
                execute: async () => ({ content: sdAllowlistShow() }),
            });
            editor.add({
                name: "sd_scan",
                description: "Manually scan a file or string against all rules — returns secret-free findings metadata",
                input: {
                    type: "object",
                    properties: {
                        content: { type: "string" },
                        source: { type: "string", enum: ["file", "context", "output", "message"] },
                    },
                    required: ["content"],
                    additionalProperties: false,
                },
                execute: async (input) => ({ content: sdScan(input) }),
            });
        });
        // --- Hooks ---------------------------------------------------------
        await ctx.tool.hook("execute.before", (event) => handleLayer1({ tool: event.tool, sessionID: String(event.sessionID), input: event.input }, audit));
        await ctx.tool.hook("execute.after", (event) => handleLayer3(event, audit));
        await ctx.session.hook("prompt", (event) => handlePrompt({ sessionID: String(event.sessionID), prompt: event.prompt }, audit));
        await ctx.session.hook("context", (event) => handleContext({ sessionID: String(event.sessionID), system: event.system, messages: event.messages }, audit));
        await ctx.session.hook("compaction", (event) => handleCompaction({ sessionID: String(event.sessionID), messages: event.messages, result: event.result }, audit));
        // --- Event subscription (detection/audit only) ---------------------
        const controller = new AbortController();
        void (async () => {
            try {
                for await (const event of ctx.event.subscribe({ signal: controller.signal })) {
                    handleMessageEvent(event, audit);
                }
            }
            catch {
                // Stream ended or aborted.
            }
        })();
        return () => controller.abort();
    },
});
export default strangerDanger;
//# sourceMappingURL=index.js.map