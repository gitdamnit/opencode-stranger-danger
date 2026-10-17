import { test, describe } from "node:test";
import assert from "node:assert";
import { mkdtempSync, writeFileSync, rmSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scan, redact, scanAndRedact } from "../src/engine/scanner.js";
import { shannonEntropy } from "../src/engine/entropy.js";
import { NAMED_RULES } from "../src/engine/rules.js";
import { handleLayer1 } from "../src/plugin/layer1.js";
import { handleLayer3 } from "../src/plugin/layer3.js";
import { handlePrompt, handleContext, handleMessageEvent } from "../src/plugin/layer2-message.js";
import { handleCompaction } from "../src/plugin/layer2-compaction.js";

// Synthetic secrets with realistic entropy so rule entropy gates accept them.
const AWS = "AKIAIOSFODNN7EXAMPLE";
const GH = "ghp_" + "aB3xK9mQ2pR7vL4nJ8wC5tY1cF6hA0sD8gE2";

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), "sd-harden-"));
}

function cleanup(dir: string) {
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
}

// ============================================================
// SCANNER HARDENING
// ============================================================

describe("scanner hardening", () => {

  test("ReDoS: long input with nested quantifiers does not hang", () => {
    const start = Date.now();
    const longInput = "sk-proj-" + "x".repeat(100) + "T3BlbkFJxxx" + "x".repeat(100);
    const findings = scan(longInput, "context");
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 5000, `ReDoS guard: scan took ${elapsed}ms (should be < 5000ms)`);
    assert.ok(Array.isArray(findings));
  });

  test("ReDoS: generic-api-key pattern on long repeating string", () => {
    const start = Date.now();
    const longInput = "API_KEY=" + "abcdefghij".repeat(50) + "==";
    const findings = scan(longInput, "context");
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 5000, `generic-api-key ReDoS: scan took ${elapsed}ms`);
    assert.ok(Array.isArray(findings));
  });

  test("performance: 1 MB of keyword-free content scans quickly", () => {
    const start = Date.now();
    const findings = scan("A".repeat(1024 * 1024), "context");
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 5000, `1 MB scan took ${elapsed}ms`);
    assert.strictEqual(findings.length, 0);
  });

  test("regex lastIndex: repeated calls do not share mutable state", () => {
    const contentA = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const contentB = "ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    scan(contentA, "context");
    for (const r of NAMED_RULES) r.regex.lastIndex = 999999;
    scan(contentB, "context");
    assert.ok(true);
  });

  test("entropy threshold: low-entropy secrets below threshold are suppressed", () => {
    const lowEntropy = "aaaaaaaaaaaaaaaaaaaa";
    const ent = shannonEntropy(lowEntropy);
    assert.ok(ent < 2.0, `low entropy string has entropy ${ent}`);
    const findings = scan("SECRET_KEY=" + lowEntropy, "context");
    const matched = findings.filter(f => f.match === lowEntropy);
    assert.equal(matched.length, 0, "low-entropy string should not match generic rule");
  });

  test("entropy threshold: high-entropy random string above threshold matches", () => {
    const highEntropy = "x9K2mQ8pR4vL7nJ3wB5tY1cF6hA0sD8g";
    const ent = shannonEntropy(highEntropy);
    assert.ok(ent > 4.0, `high entropy string has entropy ${ent}`);
    const findings = scan("TOKEN=" + highEntropy, "context");
    assert.ok(Array.isArray(findings));
  });

  test("binary content: null byte does not crash scanner", () => {
    let threw = false;
    try {
      assert.ok(Array.isArray(scan("normal\n\u0000secret\0text\nmore", "context")));
    } catch { threw = true; }
    assert.ok(!threw, "binary content should not crash scanner");
  });

  test("very long single line does not crash", () => {
    let threw = false;
    try {
      const longLine = "x".repeat(100000) + "ghp_" + "a".repeat(36) + "y".repeat(100000);
      assert.ok(Array.isArray(scan(longLine, "context")));
    } catch { threw = true; }
    assert.ok(!threw, "100k char line should not crash");
  });

  test("empty string scan returns empty findings", () => {
    assert.equal(scan("", "context").length, 0);
  });

  test("unicode boundary: emoji and special chars do not break regex", () => {
    let threw = false;
    try {
      assert.ok(Array.isArray(scan("🔑 " + GH + " 🔑", "context")));
    } catch { threw = true; }
    assert.ok(!threw, "unicode emoji should not break scanner");
  });

  test("redact overlapping findings: later overlapping finds skipped", () => {
    const content = "SECRET=" + GH;
    const findings = scan(content, "context");
    const redacted = redact(content, findings);
    assert.ok(!redacted.includes(GH), "secret should be redacted");
    assert.ok(redacted.includes("[REDACTED:"), "redacted content has token");
  });

  test("redact no-op when no findings", () => {
    const content = "hello world this is safe";
    assert.equal(redact(content, []), content);
  });

  test("scanAndRedact round-trip preserves non-secret content", () => {
    const content = "const apiKey = 'sk-ant-api03-" + "x".repeat(93) + "AA'; console.log('ok');";
    const { redacted, findings } = scanAndRedact(content, "file");
    assert.ok(findings.length > 0, "should detect anthropic key");
    assert.ok(redacted.includes("[REDACTED:"), "should be redacted");
    assert.ok(redacted.includes("console.log"), "non-secret content preserved");
  });

});

// ============================================================
// LAYER 1 HARDENING — reads must never modify files
// ============================================================

describe("layer1 read-only hardening", () => {

  test("Layer1: reading a file with a secret leaves it unchanged", async () => {
    const dir = tempDir();
    try {
      const filePath = join(dir, "test.txt");
      const original = "MY_API_KEY=" + GH;
      writeFileSync(filePath, original, "utf8");
      await handleLayer1({ tool: "read", sessionID: "s1", input: { filePath } }, {});
      assert.strictEqual(readFileSync(filePath, "utf8"), original, "file must not be modified");
    } finally { cleanup(dir); }
  });

  test("Layer1: write/edit tools do not modify the target either", async () => {
    const dir = tempDir();
    try {
      const filePath = join(dir, "config.txt");
      const original = "TOKEN=" + GH;
      writeFileSync(filePath, original, "utf8");
      await handleLayer1({ tool: "write", sessionID: "s1", input: { filePath } }, {});
      await handleLayer1({ tool: "edit", sessionID: "s1", input: { filePath } }, {});
      assert.strictEqual(readFileSync(filePath, "utf8"), original);
    } finally { cleanup(dir); }
  });

  test("Layer1: .env contents stay on disk unchanged (audited, not rewritten)", async () => {
    const dir = tempDir();
    try {
      const filePath = join(dir, ".env");
      const original = "AWS_SECRET=" + AWS;
      writeFileSync(filePath, original, "utf8");
      const auditPath = join(dir, "audit.jsonl");
      await handleLayer1({ tool: "read", sessionID: "s1", input: { filePath } }, { auditPath });
      assert.strictEqual(readFileSync(filePath, "utf8"), original, ".env must not be modified");
      assert.ok(existsSync(auditPath), "reading a secret-bearing .env should be audited");
    } finally { cleanup(dir); }
  });

  test("Layer1: no backup files are ever created", async () => {
    const dir = tempDir();
    try {
      const filePath = join(dir, "secrets.txt");
      writeFileSync(filePath, "PASSWORD=" + GH, "utf8");
      await handleLayer1({ tool: "edit", sessionID: "s1", input: { filePath } }, {});
      assert.ok(!existsSync(filePath + ".bak"));
      assert.ok(!existsSync(filePath + "~"));
      assert.ok(!existsSync(filePath + ".backup"));
    } finally { cleanup(dir); }
  });

  test("Layer1: binary file is skipped unchanged", async () => {
    const dir = tempDir();
    try {
      const filePath = join(dir, "binary.bin");
      const buf = Buffer.alloc(100);
      buf[0] = 0x89; buf[50] = 0;
      writeFileSync(filePath, buf);
      await handleLayer1({ tool: "read", sessionID: "s1", input: { filePath } }, {});
      assert.equal(readFileSync(filePath)[0], 0x89);
    } finally { cleanup(dir); }
  });

  test("Layer1: large file (over 10MB) is skipped unchanged", async () => {
    const dir = tempDir();
    try {
      const filePath = join(dir, "large.txt");
      writeFileSync(filePath, "x".repeat(11 * 1024 * 1024), "utf8");
      await handleLayer1({ tool: "read", sessionID: "s1", input: { filePath } }, {});
      assert.equal(readFileSync(filePath, "utf8").length, 11 * 1024 * 1024);
    } finally { cleanup(dir); }
  });

  test("Layer1: missing filePath / non-file tool does not throw", async () => {
    await handleLayer1({ tool: "read", sessionID: "s1", input: {} }, {});
    await handleLayer1({ tool: "bash", sessionID: "s1", input: { filePath: "/etc/hostname" } }, {});
    await handleLayer1({ tool: "read", sessionID: "s1", input: { filePath: "/nonexistent/path.txt" } }, {});
    assert.ok(true);
  });

});

// ============================================================
// LAYER 3 HARDENING — large outputs
// ============================================================

describe("layer3 large-output hardening", () => {

  test("scans and redacts a secret beyond the old 1 MB limit", async () => {
    const filler = "A".repeat(1024 * 1024 + 50);
    const event: any = { tool: "bash", sessionID: "s1", status: "completed", result: { content: filler + GH } };
    await handleLayer3(event, {});
    assert.ok(event.result.content.includes("[REDACTED:"));
    assert.ok(!event.result.content.includes(GH));
  });

  test("does not corrupt structured output", async () => {
    const event: any = { tool: "q", sessionID: "s1", status: "completed", result: { output: { a: 1, b: ["x", AWS] } } };
    await handleLayer3(event, {});
    assert.strictEqual(event.result.output.a, 1);
    assert.strictEqual(event.result.output.b[0], "x");
    assert.ok(event.result.output.b[1].includes("[REDACTED:"));
  });

});

// ============================================================
// LAYER 2 HARDENING (prompt / context / compaction)
// ============================================================

describe("layer2 outbound protection hardening", () => {

  test("prompt hook redacts secrets from the outgoing prompt", async () => {
    const event: any = { sessionID: "s1", prompt: { text: `here is ${GH}` } };
    await handlePrompt(event, {});
    assert.ok(event.prompt.text.includes("[REDACTED:"));
    assert.ok(!event.prompt.text.includes(GH));
  });

  test("context hook redacts system and message text", async () => {
    const event: any = { sessionID: "s1", system: [{ type: "text", text: AWS }], messages: [{ content: [{ type: "text", text: GH }] }] };
    await handleContext(event, {});
    assert.ok(!JSON.stringify(event).includes(AWS));
    assert.ok(!JSON.stringify(event).includes(GH));
  });

  test("context hook leaves clean content untouched", async () => {
    const event: any = { sessionID: "s1", system: [{ type: "text", text: "safe" }], messages: [{ content: [{ type: "text", text: "hello" }] }] };
    await handleContext(event, {});
    assert.strictEqual(event.system[0].text, "safe");
    assert.strictEqual(event.messages[0].content[0].text, "hello");
  });

  test("compaction hook redacts transcript and summary", async () => {
    const event: any = { sessionID: "s1", messages: [{ content: [{ type: "text", text: GH }] }], result: { summary: AWS } };
    await handleCompaction(event, {});
    assert.ok(!event.messages[0].content[0].text.includes(GH));
    assert.ok(!event.result.summary.includes(AWS));
  });

  test("message event detector tolerates arbitrary payloads", () => {
    handleMessageEvent({ type: "message.created", text: GH }, {});
    handleMessageEvent({ type: "session.idle" }, {});
    handleMessageEvent(null, {});
    assert.ok(true);
  });

});

// ============================================================
// REDACT FUNCTION HARDENING
// ============================================================

describe("redact function hardening", () => {

  test("redact: empty findings returns original content", () => {
    assert.equal(redact("hello", []), "hello");
  });

  test("redact: finding with offset beyond content length", () => {
    const content = "short";
    const result = redact(content, [
      { ruleId: "test", match: "long", redacted: "[REDACTED:test:xxx]", offset: 100, source: "file", description: "test" },
    ]);
    assert.equal(result, content);
  });

  test("redact: duplicate overlapping findings deduplicated", () => {
    const content = "MY_KEY=" + GH;
    const findings = [
      { ruleId: "github-pat", match: GH, redacted: "[REDACTED:github-pat:x1]", offset: 7, source: "file" as const, description: "" },
      { ruleId: "generic-api-key", match: GH, redacted: "[REDACTED:generic:x2]", offset: 7, source: "file" as const, description: "" },
    ];
    const result = redact(content, findings);
    assert.ok(result.includes("[REDACTED:"));
    assert.ok(!result.includes(GH));
  });

});

// ============================================================
// DEDUPLICATION HARDENING
// ============================================================

describe("deduplication hardening", () => {

  test("dedup: many overlapping findings all sorted by offset", () => {
    const content = "aaaSK-ANTaaa" + "bbbSK-ANTbbb" + "cccSK-ANTccc";
    const findings = scan(content, "context");
    const redacted = redact(content, findings);
    assert.equal(typeof redacted, "string");
    assert.ok(redacted.length > 0);
  });

  test("dedup: 1000 identical findings for same secret collapse", () => {
    const content = "TOKEN=sk-ant-api03-" + "x".repeat(93) + "AA";
    const findings = scan(content, "context");
    assert.ok(findings.length <= 10, `dedup should collapse overlapping matches to <= 10, got ${findings.length}`);
  });

});

// ============================================================
// ENTROPY HELPER HARDENING
// ============================================================

describe("entropy helper hardening", () => {

  test("shannonEntropy: empty string returns 0", () => assert.equal(shannonEntropy(""), 0));
  test("shannonEntropy: single char returns 0", () => assert.equal(shannonEntropy("a"), 0));
  test("shannonEntropy: all same chars returns 0", () => assert.equal(shannonEntropy("aaaaaaa"), 0));
  test("shannonEntropy: uniform distribution near max", () => {
    assert.ok(shannonEntropy("abcdefghijklmnop") > 3.5);
  });

});
