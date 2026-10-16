import { test, describe } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { strangerDanger } from "../src/plugin/index.js";
import { handleLayer3 } from "../src/plugin/layer3.js";
import {
    handleContext,
    handleGenerate,
    handleTitle,
    handleMessageEvent,
} from "../src/plugin/layer2-message.js";
import {
    scanAndRedactBounded,
    MAX_BOUNDED_SCAN_BYTES,
    UNSCANNABLE_MARKER,
} from "../src/engine/scanner.js";
import { sdScan, MAX_SD_SCAN_CHARS } from "../src/plugin/tools.js";
import { readAuditLog } from "../src/engine/audit.js";

const AWS = "AKIAIOSFODNN7EXAMPLE";
const GH = "ghp_" + "aB3xK9mQ2pR7vL4nJ8wC5tY1cF6hA0sD8gE2";
const REDACTED = "[REDACTED:";

function tempDir(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), "sd-coverage-"));
}
function cleanup(dir: string): void {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}
function auditPathIn(dir: string): string {
    return path.join(dir, ".opencode", "state", "strangerdanger-audit.jsonl");
}

/** Minimal V2 plugin-context fake that captures registered tools and hooks. */
function makeCtx(directory: string) {
    const tools: any[] = [];
    const hooks: Record<string, Array<(e: any) => unknown>> = {};
    const reg = { dispose: async () => {} };
    const ctx: any = {
        location: { directory, project: { id: "proj", directory, canonical: directory } },
        options: {},
        tool: {
            transform: async (cb: (editor: any) => void) => {
                cb({
                    add: (t: any) => tools.push(t),
                    namespace: () => {},
                    list: () => tools,
                    get: () => undefined,
                    update: () => {},
                    remove: () => {},
                });
                return reg;
            },
            hook: async (name: string, cb: (e: any) => unknown) => {
                (hooks[name] ||= []).push(cb);
                return reg;
            },
            list: async () => tools,
            reload: async () => {},
        },
        session: {
            hook: async (name: string, cb: (e: any) => unknown) => {
                (hooks[`session.${name}`] ||= []).push(cb);
                return reg;
            },
        },
        event: {
            subscribe: () => ({ async *[Symbol.asyncIterator]() { /* no events */ } }),
        },
    };
    return { ctx, tools, hooks };
}

// ============================================================
// Missing request kinds: generate + title
// ============================================================

describe("security coverage — auxiliary request kinds", () => {
    test("setup registers generate and title hooks", async () => {
        const dir = tempDir();
        try {
            const { ctx, hooks } = makeCtx(dir);
            await strangerDanger.setup(ctx);
            assert.ok(hooks["session.generate"]?.length, "session.generate hook registered");
            assert.ok(hooks["session.title"]?.length, "session.title hook registered");
        } finally {
            cleanup(dir);
        }
    });

    test("generate hook redacts system and message text", async () => {
        const dir = tempDir();
        try {
            const { ctx, hooks } = await (async () => {
                const made = makeCtx(dir);
                await strangerDanger.setup(made.ctx);
                return made;
            })();
            const event: any = {
                sessionID: "s1",
                system: [{ type: "text", text: `key=${AWS}` }],
                messages: [{ content: [{ type: "text", text: `tok=${GH}` }] }],
            };
            await hooks["session.generate"][0](event);
            assert.ok(!event.system[0].text.includes(AWS), "system secret redacted");
            assert.ok(event.system[0].text.includes(REDACTED));
            assert.ok(!event.messages[0].content[0].text.includes(GH), "message secret redacted");
        } finally {
            cleanup(dir);
        }
    });

    test("title hook redacts system, messages, and an explicit result", async () => {
        const event: any = {
            sessionID: "s1",
            system: [{ type: "text", text: AWS }],
            messages: [{ content: [{ type: "text", text: GH }] }],
            result: `Title: ${AWS}`,
        };
        await handleTitle(event, {});
        assert.ok(!JSON.stringify(event).includes(AWS), "no AWS secret survives");
        assert.ok(!JSON.stringify(event).includes(GH), "no GH secret survives");
        assert.ok(typeof event.result === "string" && event.result.includes(REDACTED));
    });

    test("handleGenerate and handleContext are equivalent for the same shape", async () => {
        const a: any = { system: [{ type: "text", text: AWS }], messages: [] };
        const b: any = { system: [{ type: "text", text: AWS }], messages: [] };
        await handleContext(a, {});
        await handleGenerate(b, {});
        assert.deepStrictEqual(a, b);
        assert.ok(!a.system[0].text.includes(AWS));
    });
});

// ============================================================
// tool.execute.after — error path
// ============================================================

describe("security coverage — tool error path", () => {
    test("redacts error.message, error.error, and error.metadata", async () => {
        const dir = tempDir();
        try {
            const auditPath = auditPathIn(dir);
            const event: any = {
                status: "error",
                sessionID: "s1",
                error: {
                    message: `failed with ${AWS}`,
                    error: { detail: GH },
                    metadata: { nested: { token: AWS } },
                },
            };
            await handleLayer3(event, { auditPath });
            const serialized = JSON.stringify(event);
            assert.ok(!serialized.includes(AWS), "no AWS secret in redacted error");
            assert.ok(!serialized.includes(GH), "no GH secret in redacted error");
            assert.ok(serialized.includes(REDACTED));
        } finally {
            cleanup(dir);
        }
    });
});

// ============================================================
// Structured redaction fail-safe behavior
// ============================================================

describe("security coverage — structured redaction fail-safe", () => {
    test("a cyclic output is handled without a stack overflow and still redacts siblings", async () => {
        const dir = tempDir();
        try {
            const auditPath = auditPathIn(dir);
            const output: any = { token: AWS };
            output.self = output; // self-reference
            const event: any = { status: "completed", sessionID: "s1", result: { output } };

            await handleLayer3(event, { auditPath });

            // If recursion had overflowed, the hook's catch would have left the
            // whole result untouched (silent leak). Assert it did not.
            const serialized = JSON.stringify(event.result.output);
            assert.ok(!serialized.includes(AWS), "sibling secret is still redacted");
            assert.ok(serialized.includes(REDACTED));
            assert.ok(serialized.includes(UNSCANNABLE_MARKER), "cyclic branch fails closed");
        } finally {
            cleanup(dir);
        }
    });

    test("content beyond the depth cap fails closed instead of silently leaking", async () => {
        const dir = tempDir();
        try {
            const auditPath = auditPathIn(dir);
            let deep: any = { token: AWS };
            for (let i = 0; i < 60; i++) deep = { nested: deep };
            const event: any = { status: "completed", result: { metadata: deep } };

            await handleLayer3(event, { auditPath });

            const serialized = JSON.stringify(event.result.metadata);
            assert.ok(!serialized.includes(AWS), "deep secret does not survive");
            assert.ok(serialized.includes(UNSCANNABLE_MARKER), "over-deep branch fails closed");
        } finally {
            cleanup(dir);
        }
    });
});

// ============================================================
// V2 event stream detection (previously matched no real event)
// ============================================================

describe("security coverage — V2 event stream", () => {
    test("records a finding from a real completed-text event", () => {
        const dir = tempDir();
        try {
            const auditPath = auditPathIn(dir);
            handleMessageEvent(
                { type: "session.text.ended", data: { sessionID: "s1", text: `leaked ${AWS}` } },
                { auditPath, sessionId: "s1" },
            );
            const log = readAuditLog(auditPath);
            assert.ok(log.includes("aws-access-token"), "audit records the finding");
            assert.ok(!log.includes(AWS), "audit never stores the raw secret");
        } finally {
            cleanup(dir);
        }
    });

    test("records from tool success/failed content and skips per-token deltas", () => {
        const dir = tempDir();
        try {
            const auditPath = auditPathIn(dir);
            handleMessageEvent(
                { type: "session.tool.success", data: { sessionID: "s1", content: [{ type: "text", text: GH }] } },
                { auditPath },
            );
            const afterSuccess = readAuditLog(auditPath);
            assert.ok(afterSuccess.includes("github-pat"), "tool content audited");

            handleMessageEvent(
                { type: "session.text.delta", data: { sessionID: "s1", delta: AWS } },
                { auditPath },
            );
            assert.strictEqual(readAuditLog(auditPath), afterSuccess, "delta frames are not audited");
        } finally {
            cleanup(dir);
        }
    });

    test("ignores malformed and non-session events without throwing", () => {
        const dir = tempDir();
        try {
            const auditPath = auditPathIn(dir);
            for (const ev of [null, undefined, 42, "nope", {}, { type: "server.connected" }, { type: "session.idle" }, { type: "session.text.ended", data: null }]) {
                handleMessageEvent(ev, { auditPath });
            }
            assert.strictEqual(readAuditLog(auditPath), "");
        } finally {
            cleanup(dir);
        }
    });
});

// ============================================================
// Bounded scan size limits and fail-closed branches
// ============================================================

describe("security coverage — bounded scan limits", () => {
    test("the hard ceiling is 256 MiB (characters)", () => {
        assert.strictEqual(MAX_BOUNDED_SCAN_BYTES, 256 * 1024 * 1024);
    });

    test("oversized input fails closed before scanning", () => {
        const r = scanAndRedactBounded("hello world", "output", undefined, { window: 4, maxBytes: 5 });
        assert.strictEqual(r.complete, false);
        assert.strictEqual(r.policy, "oversized");
        assert.strictEqual(r.redacted, UNSCANNABLE_MARKER);
        assert.deepStrictEqual(r.findings, []);
    });

    test("a window that exceeds its time budget fails closed", () => {
        let n = 0;
        const now = () => (n++ % 2 === 0 ? 0 : 10_000);
        const r = scanAndRedactBounded("x".repeat(200), "output", undefined, {
            window: 10,
            overlap: 2,
            windowBudgetMs: 5,
            now,
        });
        assert.strictEqual(r.complete, false);
        assert.strictEqual(r.policy, "window-timeout");
        assert.strictEqual(r.redacted, UNSCANNABLE_MARKER);
    });

    test("windowing still finds a secret that spans a window boundary", () => {
        const content = ".".repeat(50) + AWS + ".".repeat(50);
        const r = scanAndRedactBounded(content, "output", undefined, { window: 64, overlap: 32 });
        assert.strictEqual(r.complete, true);
        assert.ok(r.findings.some((f) => f.ruleId === "aws-access-token"));
        assert.ok(!r.redacted.includes(AWS));
    });

    test("sd_scan refuses oversized content and stays bounded otherwise", () => {
        const huge = "a".repeat(MAX_SD_SCAN_CHARS + 1);
        assert.match(sdScan({ content: huge }), /too large/i);
        const ok = sdScan({ content: `token=${AWS}`, source: "output" });
        assert.ok(ok.includes("aws-access-token"));
        assert.ok(!ok.includes(AWS), "sd_scan output never contains the raw secret");
    });
});

// ============================================================
// Multi-session audit isolation (companion can't corrupt state)
// ============================================================

describe("security coverage — audit isolation", () => {
    test("two plugin instances write only to their own project audit log", async () => {
        const a = tempDir();
        const b = tempDir();
        try {
            const A = makeCtx(a);
            const B = makeCtx(b);
            await strangerDanger.setup(A.ctx);
            await strangerDanger.setup(B.ctx);
            await A.hooks["session.context"][0]({ sessionID: "sa", system: [{ type: "text", text: AWS }], messages: [] });
            await B.hooks["session.context"][0]({ sessionID: "sb", system: [{ type: "text", text: GH }], messages: [] });

            const logA = readAuditLog(auditPathIn(a));
            const logB = readAuditLog(auditPathIn(b));
            assert.ok(logA.includes("aws-access-token"), "A recorded its own finding");
            assert.ok(!logA.includes("github-pat"), "A did not receive B's finding");
            assert.ok(logB.includes("github-pat"), "B recorded its own finding");
            assert.ok(!logB.includes("aws-access-token"), "B did not receive A's finding");
            assert.ok(!logA.includes(AWS) && !logB.includes(GH), "no raw secrets stored");
        } finally {
            cleanup(a);
            cleanup(b);
        }
    });
});
