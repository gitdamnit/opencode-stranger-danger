import { Plugin } from "@opencode/plugin";
import { resolveAuditPath } from "../engine/audit.js";
import { handleLayer1 } from "./layer1.js";
import { handleLayer3 } from "./layer3.js";
import { handlePrompt, handleContext, handleGenerate, handleTitle, handleMessageEvent } from "./layer2-message.js";
import { handleCompaction } from "./layer2-compaction.js";
import { sdStatus, sdAudit, sdAllowlistAdd, sdAllowlistShow, sdScan } from "./tools.js";
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
        //
        // Every hook callback is wrapped so that accessing a field of an
        // unexpected/malformed event can never throw out of the hook. A thrown
        // hook could cascade into other plugins or abort the runtime; failing
        // closed *inside* the handler (which already catches) is safe, but
        // throwing from the wrapper is not. This keeps Stranger Danger from
        // ever breaking a companion plugin or the OpenCode runtime.
        const sid = (event) => event && typeof event.sessionID === "string" ? event.sessionID : undefined;
        await ctx.tool.hook("execute.before", (event) => {
            try {
                return handleLayer1({ tool: event?.tool, sessionID: sid(event), input: event?.input }, audit);
            }
            catch { /* never throw from a hook */ }
        });
        await ctx.tool.hook("execute.after", (event) => {
            try {
                return handleLayer3(event, audit);
            }
            catch { /* never throw from a hook */ }
        });
        await ctx.session.hook("prompt", (event) => {
            try {
                return handlePrompt({ sessionID: sid(event), prompt: event?.prompt }, audit);
            }
            catch { /* never throw from a hook */ }
        });
        await ctx.session.hook("context", (event) => {
            try {
                return handleContext({ sessionID: sid(event), system: event?.system, messages: event?.messages }, audit);
            }
            catch { /* never throw from a hook */ }
        });
        // `context` only covers the agent loop. `generate` (transient
        // `session.generate`) and `title` (title generation) are separate V2
        // request kinds with the same request shape; without these hooks their
        // requests would be sent uninspected.
        await ctx.session.hook("generate", (event) => {
            try {
                return handleGenerate({ sessionID: sid(event), system: event?.system, messages: event?.messages }, audit);
            }
            catch { /* never throw from a hook */ }
        });
        await ctx.session.hook("title", (event) => {
            try {
                return handleTitle({ sessionID: sid(event), system: event?.system, messages: event?.messages, result: event?.result }, audit);
            }
            catch { /* never throw from a hook */ }
        });
        await ctx.session.hook("compaction", (event) => {
            try {
                return handleCompaction({ sessionID: sid(event), messages: event?.messages, result: event?.result }, audit);
            }
            catch { /* never throw from a hook */ }
        });
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