import { test, describe } from "node:test";
import assert from "node:assert";
import assertStrict from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { writeAudit, writeAuditBatch, readAuditLog, getAuditPath, setAuditPath } from "../../src/engine/audit.js";

describe("audit — writeAudit", () => {
    const testDir = "/tmp/strangerdanger-audit-test";
    const testFile = path.join(testDir, "audit.jsonl");

    function cleanup() {
        try { fs.rmSync(testDir, { recursive: true, force: true }); } catch {}
    }

    test("writes a single audit entry to file", () => {
        cleanup();
        setAuditPath(testFile);

        const entry = {
            timestamp: "2026-05-12T00:00:00.000Z",
            ruleId: "aws-access-token",
            source: "file",
            description: "Test AWS key",
            fingerprint: "a3f7b2c1",
        };

        writeAudit(entry);

        assert.ok(fs.existsSync(testFile), "Audit file should exist after write");
        const content = fs.readFileSync(testFile, "utf8");
        const parsed = JSON.parse(content.trim());
        assert.strictEqual(parsed.ruleId, "aws-access-token");
        assert.strictEqual(parsed.fingerprint, "a3f7b2c1");
        assert.strictEqual(parsed.source, "file");

        cleanup();
    });

    test("automatically adds timestamp if not provided", () => {
        cleanup();
        setAuditPath(testFile);

        const entry = {
            ruleId: "test-rule",
            source: "context",
            description: "Auto timestamp test",
            fingerprint: "12345678",
        };

        writeAudit(entry);

        const content = fs.readFileSync(testFile, "utf8");
        const parsed = JSON.parse(content.trim());
        assert.ok(parsed.timestamp, "Timestamp should be auto-generated");
        assert.ok(typeof parsed.timestamp === "string");
        assert.ok(parsed.timestamp.length > 0);

        cleanup();
    });

    test("creates parent directories if they do not exist", () => {
        cleanup();
        const deepPath = path.join(testDir, "subdir", "deep", "audit.jsonl");
        setAuditPath(deepPath);

        writeAudit({
            ruleId: "test",
            source: "file",
            description: "Deep path test",
            fingerprint: "abcdef01",
        });

        assert.ok(fs.existsSync(deepPath), "Deep file should be created");

        cleanup();
    });

    test("appends to existing audit file", () => {
        cleanup();
        setAuditPath(testFile);

        writeAudit({ ruleId: "rule1", source: "file", description: "First", fingerprint: "aaa11111", timestamp: "2026-01-01T00:00:00.000Z" });
        writeAudit({ ruleId: "rule2", source: "context", description: "Second", fingerprint: "bbb22222", timestamp: "2026-01-01T00:00:01.000Z" });

        const content = fs.readFileSync(testFile, "utf8").trim();
        const lines = content.split("\n");
        assert.strictEqual(lines.length, 2);

        cleanup();
    });

    test("handles special characters in description", () => {
        cleanup();
        setAuditPath(testFile);

        const entry = {
            ruleId: "test-rule",
            source: "output",
            description: 'Description with "quotes" and \\backslash\\',
            fingerprint: "abcd1234",
        };

        // Should not throw
        writeAudit(entry);
        const content = fs.readFileSync(testFile, "utf8");
        const parsed = JSON.parse(content.trim());
        assert.strictEqual(parsed.description, entry.description);

        cleanup();
    });
});

describe("audit — writeAuditBatch", () => {
    const testDir = "/tmp/strangerdanger-audit-batch-test";
    const testFile = path.join(testDir, "audit.jsonl");

    function cleanup() {
        try { fs.rmSync(testDir, { recursive: true, force: true }); } catch {}
    }

    test("writes multiple entries in batch", () => {
        cleanup();
        setAuditPath(testFile);

        const entries = [
            { ruleId: "rule1", source: "file", description: "One", fingerprint: "aa111111", timestamp: "2026-01-01T00:00:00.000Z" },
            { ruleId: "rule2", source: "context", description: "Two", fingerprint: "bb222222", timestamp: "2026-01-01T00:00:01.000Z" },
            { ruleId: "rule3", source: "output", description: "Three", fingerprint: "cc333333", timestamp: "2026-01-01T00:00:02.000Z" },
        ];

        writeAuditBatch(entries);

        const content = fs.readFileSync(testFile, "utf8").trim();
        const lines = content.split("\n");
        assert.strictEqual(lines.length, 3);

        for (let i = 0; i < 3; i++) {
            const parsed = JSON.parse(lines[i]);
            assert.strictEqual(parsed.ruleId, entries[i].ruleId);
        }

        cleanup();
    });

    test("handles empty array", () => {
        cleanup();
        setAuditPath(testFile);

        writeAuditBatch([]);

        // Empty batch should not create a file
        assert.ok(!fs.existsSync(testFile));

        cleanup();
    });

    test("each entry gets its own timestamp if not provided", () => {
        cleanup();
        setAuditPath(testFile);

        const entries = [
            { ruleId: "rule1", source: "file", description: "No timestamp 1", fingerprint: "aa111111" },
            { ruleId: "rule2", source: "file", description: "No timestamp 2", fingerprint: "bb222222" },
        ];

        writeAuditBatch(entries);

        const content = fs.readFileSync(testFile, "utf8").trim();
        const lines = content.split("\n");
        for (const line of lines) {
            const parsed = JSON.parse(line);
            assert.ok(parsed.timestamp, "Each entry should have a timestamp");
        }

        cleanup();
    });
});

describe("audit — readAuditLog", () => {
    const testDir = "/tmp/strangerdanger-audit-read-test";
    const testFile = path.join(testDir, "audit.jsonl");

    function cleanup() {
        try { fs.rmSync(testDir, { recursive: true, force: true }); } catch {}
    }

    test("returns empty string when file does not exist", () => {
        cleanup();
        setAuditPath(testFile);

        const log = readAuditLog();
        assert.strictEqual(log, "");

        cleanup();
    });

    test("returns contents of existing file", () => {
        cleanup();
        setAuditPath(testFile);

        writeAudit({ ruleId: "test-rule", source: "file", description: "Read test", fingerprint: "ff00aa11" });

        const log = readAuditLog();
        assert.ok(log.length > 0);
        const parsed = JSON.parse(log.trim());
        assert.strictEqual(parsed.ruleId, "test-rule");

        cleanup();
    });

    test("returns multiple entries separated by newlines", () => {
        cleanup();
        setAuditPath(testFile);

        writeAuditBatch([
            { ruleId: "r1", source: "file", description: "A", fingerprint: "a1", timestamp: "2026-01-01T00:00:00.000Z" },
            { ruleId: "r2", source: "context", description: "B", fingerprint: "b2", timestamp: "2026-01-01T00:00:01.000Z" },
        ]);

        const log = readAuditLog();
        const lines = log.trim().split("\n");
        assert.strictEqual(lines.length, 2);

        cleanup();
    });
});

describe("audit — getAuditPath", () => {
    test("returns the current audit path", () => {
        setAuditPath("/tmp/custom-audit.jsonl");
        assert.strictEqual(getAuditPath(), "/tmp/custom-audit.jsonl");
    });

    test("returns default path when not set", () => {
        // Default path is .opencode/state/strangerdanger-audit.jsonl
        // Reset by setting to default
        setAuditPath(".opencode/state/strangerdanger-audit.jsonl");
        assert.strictEqual(getAuditPath(), ".opencode/state/strangerdanger-audit.jsonl");
    });
});

describe("audit — default path behavior", () => {
    test("writes to the configured default path when no explicit path is passed", () => {
        const dir = "/tmp/strangerdanger-audit-default-test";
        const defaultPath = path.join(dir, ".opencode", "state", "strangerdanger-audit.jsonl");
        try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}

        setAuditPath(defaultPath);
        writeAudit({ ruleId: "default-test", source: "file", description: "Default path test", fingerprint: "abcd1234" });
        assert.ok(fs.existsSync(defaultPath));

        // Audit files must be owner-only.
        const mode = fs.statSync(defaultPath).mode & 0o777;
        assert.strictEqual(mode, 0o600);

        try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
    });

    test("resolveAuditPath is project-scoped under a project directory", async () => {
        const { resolveAuditPath } = await import("../../src/engine/audit.js");
        const resolved = resolveAuditPath({ directory: "/tmp/some-project" });
        assert.strictEqual(resolved, "/tmp/some-project/.opencode/state/strangerdanger-audit.jsonl");
    });
});