import { test, describe } from "node:test";
import assert from "node:assert";
import assertStrict from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { strangerDanger } from "../../src/plugin/index.js";
import { handleLayer1 } from "../../src/plugin/layer1.js";
import { handleLayer3 } from "../../src/plugin/layer3.js";
import { handlePrompt, handleContext, handleMessageEvent } from "../../src/plugin/layer2-message.js";
import { handleCompaction } from "../../src/plugin/layer2-compaction.js";

const AWS = "AKIAIOSFODNN7EXAMPLE";
// Synthetic GitHub PAT with realistic (high) entropy so the rule's entropy
// gate accepts it. Real tokens are not low-entropy runs of one character.
const GH = "ghp_" + "aB3xK9mQ2pR7vL4nJ8wC5tY1cF6hA0sD8gE2";
const REDACTED = "[REDACTED:";

function tempDir(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), "sd-plugin-"));
}

function cleanup(dir: string): void {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

/**
 * Minimal fake of the V2 plugin context: captures the tools and hooks the
 * plugin registers so tests can exercise them without a live OpenCode server.
 */
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
            subscribe: () => ({
                async *[Symbol.asyncIterator]() { /* no events */ },
            }),
        },
    };
    return { ctx, tools, hooks };
}

async function setup(directory: string) {
    const made = makeCtx(directory);
    await strangerDanger.setup(made.ctx);
    return made;
}

describe("plugin — V2 definition and registration", () => {
    test("default export is a V2 plugin with a stable id and setup", () => {
        assert.strictEqual(strangerDanger.id, "gitdamnit.stranger-danger");
        assert.strictEqual(typeof strangerDanger.setup, "function");
    });

    test("setup registers exactly the five tools", async () => {
        const dir = tempDir();
        try {
            const { tools } = await setup(dir);
            const names = tools.map((t) => t.name).sort();
            assert.deepStrictEqual(names, ["sd_allowlist_add", "sd_allowlist_show", "sd_audit", "sd_scan", "sd_status"]);
        } finally {
            cleanup(dir);
        }
    });

    test("setup registers the expected hooks", async () => {
        const dir = tempDir();
        try {
            const { hooks } = await setup(dir);
            for (const name of ["execute.before", "execute.after", "session.prompt", "session.context", "session.compaction"]) {
                assert.ok(hooks[name]?.length, `hook ${name} should be registered`);
            }
        } finally {
            cleanup(dir);
        }
    });

    test("setup returns a cleanup function", async () => {
        const dir = tempDir();
        try {
            const { ctx } = makeCtx(dir);
            const cleanupFn = await strangerDanger.setup(ctx);
            assert.strictEqual(typeof cleanupFn, "function");
            await cleanupFn!();
        } finally {
            cleanup(dir);
        }
    });
});

describe("plugin — tools", () => {
    test("sd_status reports version and rule count", async () => {
        const dir = tempDir();
        try {
            const { tools } = await setup(dir);
            const status = tools.find((t) => t.name === "sd_status");
            const out = await status.execute({});
            assert.ok(out.content.includes("strangerDanger v"));
            assert.ok(out.content.includes("Rules:"));
        } finally {
            cleanup(dir);
        }
    });

    test("sd_scan detects a secret and never returns the raw value", async () => {
        const dir = tempDir();
        try {
            const { tools } = await setup(dir);
            const scan = tools.find((t) => t.name === "sd_scan");
            const out = await scan.execute({ content: `const key = "${AWS}";`, source: "file" });
            assert.ok(out.content.includes("aws-access-token"));
            assert.ok(!out.content.includes(AWS), "tool output must not contain the raw secret");
            assert.ok(out.content.includes("Fingerprint:"));
        } finally {
            cleanup(dir);
        }
    });

    test("sd_scan on clean content reports none", async () => {
        const dir = tempDir();
        try {
            const { tools } = await setup(dir);
            const scan = tools.find((t) => t.name === "sd_scan");
            const out = await scan.execute({ content: "const x = 42;" });
            assert.strictEqual(out.content, "No secrets detected.");
        } finally {
            cleanup(dir);
        }
    });

    test("sd_allowlist_add rejects an invalid fingerprint", async () => {
        const dir = tempDir();
        try {
            const { tools } = await setup(dir);
            const add = tools.find((t) => t.name === "sd_allowlist_add");
            const out = await add.execute({ fingerprint: "nothex" });
            assert.ok(out.content.toLowerCase().includes("fingerprint"));
        } finally {
            cleanup(dir);
        }
    });

    test("sd_audit reports no entries on a fresh project", async () => {
        const dir = tempDir();
        try {
            const { tools } = await setup(dir);
            const audit = tools.find((t) => t.name === "sd_audit");
            const out = await audit.execute({});
            assert.ok(out.content.includes("No audit entries") || out.content.includes("Audit log"));
        } finally {
            cleanup(dir);
        }
    });
});

describe("plugin — layer1 (read interception never writes)", () => {
    test("a read containing a secret leaves the file byte-for-byte unchanged", async () => {
        const dir = tempDir();
        try {
            const file = path.join(dir, "config.ts");
            const original = `const key = "${AWS}";`;
            fs.writeFileSync(file, original);
            const auditPath = path.join(dir, "audit.jsonl");

            await handleLayer1({ tool: "read", sessionID: "s1", input: { filePath: file } }, { auditPath });

            assert.strictEqual(fs.readFileSync(file, "utf8"), original, "file must not be modified");
            const log = fs.readFileSync(auditPath, "utf8");
            assert.ok(log.includes("aws-access-token"), "finding should be audited");
        } finally {
            cleanup(dir);
        }
    });

    test("edit and write tools are inspected but never modified", async () => {
        const dir = tempDir();
        try {
            const file = path.join(dir, "config.txt");
            const original = `TOKEN=${GH}`;
            fs.writeFileSync(file, original);
            for (const tool of ["edit", "write"]) {
                await handleLayer1({ tool, sessionID: "s1", input: { filePath: file } }, {});
            }
            assert.strictEqual(fs.readFileSync(file, "utf8"), original);
        } finally {
            cleanup(dir);
        }
    });

    test("handles missing filePath, non-existent file, and non-file tools gracefully", async () => {
        const dir = tempDir();
        try {
            await handleLayer1({ tool: "read", sessionID: "s1", input: {} }, {});
            await handleLayer1({ tool: "read", sessionID: "s1", input: { filePath: path.join(dir, "nope.ts") } }, {});
            await handleLayer1({ tool: "bash", sessionID: "s1", input: { filePath: "/etc/hostname" } }, {});
            assert.ok(true);
        } finally {
            cleanup(dir);
        }
    });

    test("skips binary files without modifying them", async () => {
        const dir = tempDir();
        try {
            const file = path.join(dir, "image.png");
            fs.writeFileSync(file, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x1a]));
            await handleLayer1({ tool: "read", sessionID: "s1", input: { filePath: file } }, {});
            const content = fs.readFileSync(file);
            assert.strictEqual(content[0], 0x89);
        } finally {
            cleanup(dir);
        }
    });
});

describe("plugin — layer3 (tool result redaction)", () => {
    test("redacts string content", async () => {
        const event = { tool: "read", sessionID: "s1", status: "completed", result: { content: `AWS ${AWS}` } };
        await handleLayer3(event as any, {});
        assert.ok(event.result.content.includes(REDACTED));
        assert.ok(!event.result.content.includes(AWS));
    });

    test("redacts text content parts", async () => {
        const event = {
            tool: "read",
            sessionID: "s1",
            status: "completed",
            result: { content: [{ type: "text", text: `key ${GH}` }, { type: "file", uri: "file://x", mime: "text/plain" }] },
        };
        await handleLayer3(event as any, {});
        assert.ok((event.result.content[0] as any).text.includes(REDACTED));
        assert.ok(!JSON.stringify(event.result.content).includes(GH));
    });

    test("redacts structured output string leaves while preserving shape", async () => {
        const event = {
            tool: "query",
            sessionID: "s1",
            status: "completed",
            result: { output: { token: GH, nested: { count: 3, list: ["ok", AWS] } } },
        };
        await handleLayer3(event as any, {});
        const out: any = event.result.output;
        assert.strictEqual(typeof out.token, "string");
        assert.ok(out.token.includes(REDACTED));
        assert.strictEqual(out.nested.count, 3);
        assert.deepStrictEqual(out.nested.list[0], "ok");
        assert.ok(out.nested.list[1].includes(REDACTED));
    });

    test("scans the whole large output, including a secret past the old 1 MB limit", async () => {
        const filler = "A".repeat(1024 * 1024 + 5000);
        const event = { tool: "bash", sessionID: "s1", status: "completed", result: { content: filler + GH } };
        await handleLayer3(event as any, {});
        assert.ok(event.result.content.includes(REDACTED));
        assert.ok(!event.result.content.includes(GH), "secret past 1 MB must be redacted");
    });

    test("ignores null/undefined results and errors without throwing", async () => {
        await handleLayer3({ tool: "x", sessionID: "s1", status: "completed", result: null } as any, {});
        await handleLayer3(null as any, {});
        await handleLayer3({ tool: "x", sessionID: "s1", status: "error", error: { message: `boom ${AWS}` } } as any, {});
        assert.ok(true);
    });
});

describe("plugin — layer2 prompt and context redaction", () => {
    test("prompt hook redacts the outgoing prompt text", async () => {
        const event = { sessionID: "s1", prompt: { text: `please use ${GH} carefully` } } as any;
        await handlePrompt(event, {});
        assert.ok(event.prompt.text.includes(REDACTED));
        assert.ok(!event.prompt.text.includes(GH));
    });

    test("context hook redacts system parts and message text", async () => {
        const event: any = {
            sessionID: "s1",
            system: [{ type: "text", text: `system ${AWS}` }],
            messages: [
                { role: "user", content: [{ type: "text", text: `hi ${GH}` }] },
                { role: "assistant", content: [{ type: "tool-call", id: "1", name: "x", input: { key: AWS } }] },
                { role: "tool", content: [{ type: "tool-result", id: "1", name: "x", result: { type: "text", value: GH } }] },
            ],
        };
        await handleContext(event, {});
        assert.ok(event.system[0].text.includes(REDACTED));
        assert.ok(event.messages[0].content[0].text.includes(REDACTED));
        assert.ok(event.messages[1].content[0].input.key.includes(REDACTED));
        assert.ok(event.messages[2].content[0].result.value.includes(REDACTED));
        assert.ok(!JSON.stringify(event).includes(AWS));
        assert.ok(!JSON.stringify(event).includes(GH));
    });

    test("compaction hook redacts the transcript and its summary", async () => {
        const event: any = {
            sessionID: "s1",
            messages: [{ role: "user", content: [{ type: "text", text: `secret ${GH}` }] }],
            result: { summary: `summary leaks ${AWS}` },
        };
        await handleCompaction(event, {});
        assert.ok(event.messages[0].content[0].text.includes(REDACTED));
        assert.ok(event.result.summary.includes(REDACTED));
    });

    test("message event detector does not throw on arbitrary payloads", () => {
        handleMessageEvent({ type: "message.created", text: GH }, {});
        handleMessageEvent({ type: "session.idle" }, {});
        handleMessageEvent(null, {});
        handleMessageEvent({ type: "message.updated", part: { text: AWS } }, {});
        assert.ok(true);
    });
});

describe("plugin — end-to-end hook wiring", () => {
    test("execute.after hook registered by setup redacts a tool result", async () => {
        const dir = tempDir();
        try {
            const { hooks } = await setup(dir);
            const event: any = { tool: "bash", sessionID: "s1", status: "completed", result: { content: GH } };
            for (const h of hooks["execute.after"]) await h(event);
            assert.ok(!event.result.content.includes(GH));
            assert.ok(event.result.content.includes(REDACTED));
        } finally {
            cleanup(dir);
        }
    });

    test("session.context hook registered by setup redacts the request", async () => {
        const dir = tempDir();
        try {
            const { hooks } = await setup(dir);
            const event: any = { sessionID: "s1", system: [], messages: [{ role: "user", content: [{ type: "text", text: AWS }] }] };
            for (const h of hooks["session.context"]) await h(event);
            assert.ok(!JSON.stringify(event).includes(AWS));
        } finally {
            cleanup(dir);
        }
    });
});
