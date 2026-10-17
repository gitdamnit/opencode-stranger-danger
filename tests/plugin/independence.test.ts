import { test, describe } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { strangerDanger } from "../../src/plugin/index.js";
import { handleLayer1 } from "../../src/plugin/layer1.js";
import { handleLayer3 } from "../../src/plugin/layer3.js";
import { handlePrompt, handleContext, handleMessageEvent } from "../../src/plugin/layer2-message.js";
import { handleCompaction } from "../../src/plugin/layer2-compaction.js";
import { resolveAuditPath } from "../../src/engine/audit.js";

const AWS = "AKIAIOSFODNN7EXAMPLE";
const GH = "ghp_" + "aB3xK9mQ2pR7vL4nJ8wC5tY1cF6hA0sD8gE2";
const GH2 = "ghp_" + "Z9yQ2wE4rT6uI8oP0aS1dF3gH5jK7lM9nBVb";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

function tempDir(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), "sd-indep-"));
}
function cleanup(dir: string): void {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
}

/**
 * A context exposing ONLY the documented V2 plugin surface this plugin uses.
 * No companion-plugin data, no extra domains: proves the plugin initializes
 * without any other toolkit plugin present.
 */
function makeMinimalCtx(directory: string) {
    const tools: any[] = [];
    const hooks: Record<string, Array<(e: any) => unknown>> = {};
    const reg = { dispose: async () => {} };
    const ctx: any = {
        location: { directory, project: { id: "proj", directory, canonical: directory } },
        options: {},
        tool: {
            transform: async (cb: any) => { cb({ add: (t: any) => tools.push(t), namespace() {}, list: () => tools, get() {}, update() {}, remove() {} }); return reg; },
            hook: async (n: string, cb: any) => { (hooks[n] ||= []).push(cb); return reg; },
            list: async () => tools,
            reload: async () => {},
        },
        session: { hook: async (n: string, cb: any) => { (hooks["session." + n] ||= []).push(cb); return reg; } },
        event: { subscribe: () => ({ async *[Symbol.asyncIterator]() { /* no events */ } }) },
    };
    return { ctx, tools, hooks };
}

async function setup(directory: string) {
    const made = makeMinimalCtx(directory);
    const dispose = await strangerDanger.setup(made.ctx);
    return { ...made, dispose };
}

describe("independence — no cross-plugin coupling", () => {
    test("source does not import or reference other toolkit plugins", () => {
        const forbidden = /(git[-_]?that[-_]?shit|checkpoint[-_]?orchestrator|cheapcode|@gitdamnit\/(?!stranger-danger))/i;
        const offenders: string[] = [];
        const walk = (dir: string) => {
            for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
                const p = path.join(dir, entry.name);
                if (entry.isDirectory()) { walk(p); continue; }
                if (!p.endsWith(".ts") && !p.endsWith(".js") && !p.endsWith(".json")) continue;
                const src = fs.readFileSync(p, "utf8");
                for (const m of src.matchAll(/(?:from|require\()\s*["'`]([^"'`]+)["'`]/g)) {
                    if (forbidden.test(m[1])) offenders.push(`${path.relative(repoRoot, p)} → ${m[1]}`);
                }
            }
        };
        walk(path.join(repoRoot, "src"));
        assert.deepStrictEqual(offenders, [], `forbidden cross-plugin imports: ${offenders.join(", ")}`);
    });

    test("package.json declares no toolkit-plugin dependencies", () => {
        const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, "package.json"), "utf8"));
        const all = { ...pkg.dependencies, ...pkg.peerDependencies, ...pkg.devDependencies };
        for (const name of Object.keys(all)) {
            assert.ok(
                !/git-that-shit|checkpoint-orchestrator/i.test(name),
                `must not depend on toolkit plugin ${name}`,
            );
        }
    });

    test("tool names are namespaced with the sd_ prefix (collision avoidance)", async () => {
        const dir = tempDir();
        try {
            const { tools } = await setup(dir);
            assert.ok(tools.length > 0);
            for (const t of tools) assert.ok(t.name.startsWith("sd_"), `tool ${t.name} is not namespaced`);
        } finally { cleanup(dir); }
    });
});

describe("independence — installs and runs alone", () => {
    test("setup succeeds with only the documented V2 surface and empty options", async () => {
        const dir = tempDir();
        try {
            const { tools, hooks } = await setup(dir);
            assert.deepStrictEqual(
                tools.map((t) => t.name).sort(),
                ["sd_allowlist_add", "sd_allowlist_show", "sd_audit", "sd_scan", "sd_status"],
            );
            for (const h of ["execute.before", "execute.after", "session.prompt", "session.context", "session.compaction"]) {
                assert.ok(hooks[h]?.length, `missing hook ${h}`);
            }
        } finally { cleanup(dir); }
    });

    test("unknown options are ignored", async () => {
        const dir = tempDir();
        try {
            const made = makeMinimalCtx(dir);
            made.ctx.options = { somethingFromACompanionPlugin: true };
            const dispose = await strangerDanger.setup(made.ctx);
            assert.strictEqual(typeof dispose, "function");
            await dispose!();
        } finally { cleanup(dir); }
    });

    test("audit storage is owned and namespaced under the project", () => {
        const resolved = resolveAuditPath({ directory: "/tmp/some-project" });
        assert.strictEqual(resolved, path.join("/tmp/some-project", ".opencode", "state", "strangerdanger-audit.jsonl"));
    });
});

describe("independence — session and project isolation", () => {
    test("two plugin instances write only to their own project audit file", async () => {
        const dirA = tempDir();
        const dirB = tempDir();
        try {
            const a = await setup(dirA);
            const b = await setup(dirB);
            const fileA = resolveAuditPath({ directory: dirA });
            const fileB = resolveAuditPath({ directory: dirB });

            // Each instance sees a different secret with a different session id.
            for (const h of a.hooks["execute.after"]) {
                await h({ tool: "bash", sessionID: "session-A", status: "completed", result: { content: GH } });
            }
            for (const h of b.hooks["execute.after"]) {
                await h({ tool: "bash", sessionID: "session-B", status: "completed", result: { content: GH2 } });
            }

            const logA = fs.readFileSync(fileA, "utf8");
            const logB = fs.readFileSync(fileB, "utf8");
            assert.ok(logA.includes("session-A"));
            assert.ok(!logA.includes("session-B"), "instance A must not record instance B's session");
            assert.ok(logB.includes("session-B"));
            assert.ok(!logB.includes("session-A"), "instance B must not record instance A's session");
            assert.ok(!logA.includes(GH) && !logB.includes(GH2), "audit logs must not contain raw secrets");
        } finally {
            cleanup(dirA);
            cleanup(dirB);
        }
    });
});

describe("independence — no execution-order dependency", () => {
    test("execute.before does not mutate tool arguments", async () => {
        const dir = tempDir();
        try {
            const file = path.join(dir, "config.ts");
            fs.writeFileSync(file, `const key = "${AWS}";`);
            const input = { filePath: file, content: `const key = "${AWS}";` };
            const before = JSON.stringify(input);
            await handleLayer1({ tool: "read", sessionID: "s", input }, {});
            assert.strictEqual(JSON.stringify(input), before, "read-only hook must not mutate inputs");
        } finally { cleanup(dir); }
    });

    test("redaction does not depend on execute.after ordering", async () => {
        // The context hook is the ordering-independent backstop: even if another
        // plugin rewrites a tool result *after* Stranger Danger's after-hook, the
        // secret is still removed from the assembled model request.
        const event: any = {
            tool: "bash",
            sessionID: "s",
            status: "completed",
            result: { content: "clean" },
        };
        // Stranger Danger after-hook runs first on clean content...
        await handleLayer3(event, {});
        // ...then a hypothetical companion replaces the result with a secret.
        event.result.content = `leaked ${GH}`;

        const messages = [
            { role: "tool", content: [{ type: "tool-result", id: "1", name: "bash", result: { type: "text", value: event.result.content } }] },
        ];
        const contextEvent: any = { sessionID: "s", system: [], messages };
        await handleContext(contextEvent, {});
        assert.ok(!JSON.stringify(contextEvent).includes(GH), "context hook must redact regardless of after-hook order");
    });

    test("after-hook redacts content already transformed by another plugin", async () => {
        const event: any = { tool: "bash", sessionID: "s", status: "completed", result: { content: "prefix " + GH + " suffix" } };
        await handleLayer3(event, {});
        assert.ok(!event.result.content.includes(GH));
    });
});

describe("independence — failure isolation", () => {
    test("no registered hook throws on malformed events", async () => {
        const dir = tempDir();
        try {
            const { hooks } = await setup(dir);
            const malformed: any[] = [undefined, null, {}, { result: null }, { tool: 123 }, {
                sessionID: 42, system: "not-an-array", messages: [{ content: "not-an-array" }],
                result: { content: 12345, output: Symbol("x"), metadata: null },
                prompt: { text: 99 },
                error: { message: { nested: true } },
            }];
            for (const [name, list] of Object.entries(hooks)) {
                for (const fn of list) {
                    for (const ev of malformed) {
                        let threw = false;
                        try { await fn(ev); } catch { threw = true; }
                        assert.ok(!threw, `hook ${name} threw on malformed event: ${String(JSON.stringify(ev))}`);
                    }
                }
            }
        } finally { cleanup(dir); }
    });

    test("a malformed event cannot stop the event subscription loop", () => {
        let threw = false;
        try {
            handleMessageEvent({ type: "message.created", text: GH }, {});
            handleMessageEvent({ type: "message.created", part: { text: 123 } }, {});
            handleMessageEvent({ type: "message.updated", properties: null }, {});
        } catch { threw = true; }
        assert.ok(!threw);
    });
});

describe("independence — reload and cleanup", () => {
    test("dispose is safe to call and a fresh instance can be created afterwards", async () => {
        const dir = tempDir();
        try {
            const first = await setup(dir);
            assert.strictEqual(typeof first.dispose, "function");
            await first.dispose!();
            // Idempotent-ish: calling again must not throw.
            await first.dispose!();

            const second = await setup(dir);
            for (const h of second.hooks["session.prompt"]) {
                const e: any = { sessionID: "s2", prompt: { text: GH } };
                await h(e);
                assert.ok(!e.prompt.text.includes(GH));
            }
        } finally { cleanup(dir); }
    });
});

describe("independence — companion-absent behavior", () => {
    test("hooks run when events carry no companion fields", async () => {
        const dir = tempDir();
        try {
            const { hooks } = await setup(dir);
            for (const h of hooks["execute.after"]) {
                await h({ tool: "read", sessionID: "s", status: "completed", result: { content: AWS } });
            }
            for (const h of hooks["session.context"]) {
                await h({ sessionID: "s", system: [{ type: "text", text: AWS }], messages: [] });
            }
            assert.ok(true);
        } finally { cleanup(dir); }
    });

    test("standalone handlers work with an empty AuditContext (no shared state)", async () => {
        // With no explicit audit path, the plugin layer must not write anywhere.
        const e: any = { sessionID: "s", prompt: { text: GH } };
        await handlePrompt(e, {});
        await handleCompaction({ sessionID: "s", messages: [] } as any, {});
        assert.ok(!e.prompt.text.includes(GH));
    });
});
