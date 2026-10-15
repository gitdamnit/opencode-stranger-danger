import { test, describe } from "node:test";
import assert from "node:assert";
import assertStrict from "node:assert/strict";
import { cmdScan } from "../../src/cli/commands/scan.js";
import { cmdRedact } from "../../src/cli/commands/redact.js";
import { cmdAudit } from "../../src/cli/commands/audit.js";
import { cmdRules } from "../../src/cli/commands/rules.js";
import { cmdAllowlist } from "../../src/cli/commands/allowlist.js";
import { scanAndRedact } from "../../src/engine/scanner.js";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

describe("cli — cmdScan", () => {
    test("scan detects AWS key in string", () => {
        const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
        const { findings } = scanAndRedact(content, "file");
        const awsFindings = findings.filter((f) => f.ruleId === "aws-access-token");
        assertStrict.ok(awsFindings.length >= 1);
    });

    test("scan returns empty array for clean content", () => {
        const content = "const x = 42;";
        const { findings } = scanAndRedact(content, "file");
        assert.strictEqual(findings.length, 0);
    });

    test("scan handles empty string", () => {
        const { findings } = scanAndRedact("", "file");
        assert.strictEqual(findings.length, 0);
    });

    test("scan handles whitespace-only content", () => {
        const { findings } = scanAndRedact("   \n\n  ", "file");
        assert.strictEqual(findings.length, 0);
    });

    test("scan with source 'context' works", () => {
        const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
        const { findings } = scanAndRedact(content, "context");
        const awsFindings = findings.filter((f) => f.ruleId === "aws-access-token");
        assertStrict.ok(awsFindings.length >= 1);
    });

test("scan with source 'message' works", () => {
         const content = 'const key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";';
         const { findings } = scanAndRedact(content, "message");
         const ghFindings = findings.filter((f) => f.ruleId === "github-pat");
         assertStrict.ok(ghFindings.length >= 1);
     });

    test("scan with source 'output' works", () => {
        const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
        const { findings } = scanAndRedact(content, "output");
        const awsFindings = findings.filter((f) => f.ruleId === "aws-access-token");
        assertStrict.ok(awsFindings.length >= 1);
    });

    test("scan produces valid redacted output", () => {
        const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
        const { redacted } = scanAndRedact(content, "file");
        assert.ok(redacted.includes("[REDACTED:"));
        assert.ok(redacted.includes("aws-access-token:"));
        assert.ok(!redacted.includes("AKIAIOSFODNN7EXAMPLE"));
        // Non-secret parts should be preserved
        assert.ok(redacted.includes("const key ="));
    });
});

describe("cli — cmdRedact", () => {
    test("redact modifies the file atomically and writes NO plaintext backup by default", async () => {
        const { cmdRedact } = await import("../../src/cli/commands/redact.js");
        const { setAuditPath } = await import("../../src/engine/audit.js");
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sd-redact-"));
        const filePath = path.join(tmpDir, "config.ts");
        try {
            setAuditPath(path.join(tmpDir, "audit.jsonl"));
            fs.writeFileSync(filePath, 'const key = "AKIAIOSFODNN7EXAMPLE";');

            await cmdRedact([filePath], {});

            const after = fs.readFileSync(filePath, "utf8");
            assert.ok(!after.includes("AKIAIOSFODNN7EXAMPLE"));
            assert.ok(after.includes("[REDACTED:"));
            assert.ok(!fs.existsSync(filePath + ".backup"), "no plaintext .backup in the working tree");
            assert.ok(!fs.existsSync(filePath + ".bak"));
        } finally {
            try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
        }
    });

    test("redact --backup-dir writes a permission-restricted backup outside the working tree", async () => {
        const { cmdRedact } = await import("../../src/cli/commands/redact.js");
        const { setAuditPath } = await import("../../src/engine/audit.js");
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sd-redact-"));
        const backupDir = path.join(tmpDir, "outside", "backups");
        const filePath = path.join(tmpDir, "config.ts");
        try {
            setAuditPath(path.join(tmpDir, "audit.jsonl"));
            const original = 'const key = "AKIAIOSFODNN7EXAMPLE";';
            fs.writeFileSync(filePath, original);

            await cmdRedact([filePath], { "backup-dir": backupDir });

            const backups = fs.readdirSync(backupDir);
            assert.ok(backups.length >= 1, "a backup should exist in the requested directory");
            const backupContent = fs.readFileSync(path.join(backupDir, backups[0]), "utf8");
            assert.strictEqual(backupContent, original, "backup preserves the original content");
            const mode = fs.statSync(path.join(backupDir, backups[0])).mode & 0o777;
            assert.strictEqual(mode, 0o600, "backup must be owner-only");
        } finally {
            try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
        }
    });

    test("redact leaves a clean file unchanged", async () => {
        const { cmdRedact } = await import("../../src/cli/commands/redact.js");
        const { setAuditPath } = await import("../../src/engine/audit.js");
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sd-redact-"));
        const filePath = path.join(tmpDir, "clean.ts");
        try {
            setAuditPath(path.join(tmpDir, "audit.jsonl"));
            fs.writeFileSync(filePath, "const x = 42;");
            await cmdRedact([filePath], {});
            assert.strictEqual(fs.readFileSync(filePath, "utf8"), "const x = 42;");
        } finally {
            try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
        }
    });
});

describe("cli — cmdScan JSON output is secret-free", () => {
    test("--json output never contains the raw secret", async () => {
        const { cmdScan } = await import("../../src/cli/commands/scan.js");
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "sd-scan-"));
        const filePath = path.join(tmpDir, "config.ts");
        const secret = "AKIAIOSFODNN7EXAMPLE";
        const logs: string[] = [];
        const original = console.log;
        try {
            fs.writeFileSync(filePath, `const key = "${secret}";`);
            console.log = (...args: unknown[]) => { logs.push(args.join(" ")); };
            await cmdScan([filePath], { json: true });
        } finally {
            console.log = original;
            try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
        }
        const output = logs.join("\n");
        const parsed = JSON.parse(output);
        assert.ok(Array.isArray(parsed.findings) && parsed.findings.length >= 1);
        assert.ok(!output.includes(secret), "JSON output must not contain the raw secret");
        assert.ok(parsed.findings[0].fingerprint, "safe metadata should include a fingerprint");
    });
});

describe("cli — cmdRules", () => {
    test("rules command lists all rule categories", async () => {
        const { NAMED_RULES, ENTROPY_RULES, CLEAN_ROOM_RULES } = await import("../../src/engine/rules.js");

        const allRules = [...NAMED_RULES, ...CLEAN_ROOM_RULES, ...ENTROPY_RULES];
        assert.ok(allRules.length > 170);
        assertStrict.ok(NAMED_RULES.length >= 160);
        assertStrict.ok(CLEAN_ROOM_RULES.length >= 10);
        assertStrict.strictEqual(ENTROPY_RULES.length, 3);
    });

    test("every rule has a printable description", async () => {
        const { NAMED_RULES, ENTROPY_RULES, CLEAN_ROOM_RULES } = await import("../../src/engine/rules.js");
        const allRules = [...NAMED_RULES, ...CLEAN_ROOM_RULES, ...ENTROPY_RULES];
        for (const rule of allRules) {
            assert.ok(rule.description.length > 0);
        }
    });
});

describe("cli — cmdAudit", () => {
    test("audit reads and formats JSONL log", async () => {
        const { writeAudit, readAuditLog, setAuditPath } = await import("../../src/engine/audit.js");
        const tmpFile = "/tmp/sd-audit-display-test.jsonl";

        setAuditPath(tmpFile);
        try { fs.unlinkSync(tmpFile); } catch {}

        writeAudit({
            ruleId: "aws-access-token",
            source: "file",
            description: "AWS key found",
            fingerprint: "a3f7b2c1",
            timestamp: "2026-05-12T10:00:00.000Z",
        });

        writeAudit({
            ruleId: "github-pat",
            source: "context",
            description: "GitHub PAT found",
            fingerprint: "b4c8d3e2",
            timestamp: "2026-05-12T10:00:01.000Z",
        });

        const log = readAuditLog();
        const lines = log.trim().split("\n");
        assert.strictEqual(lines.length, 2);

        // Parse and verify
        const entry1 = JSON.parse(lines[0]);
        assert.strictEqual(entry1.ruleId, "aws-access-token");
        assert.strictEqual(entry1.source, "file");

        const entry2 = JSON.parse(lines[1]);
        assert.strictEqual(entry2.ruleId, "github-pat");
        assert.strictEqual(entry2.source, "context");

        try { fs.unlinkSync(tmpFile); } catch {}
    });

    test("audit handles empty log", async () => {
        const { readAuditLog, setAuditPath } = await import("../../src/engine/audit.js");
        const tmpFile = "/tmp/sd-audit-empty-test.jsonl";

        setAuditPath(tmpFile);
        try { fs.unlinkSync(tmpFile); } catch {}

        const log = readAuditLog();
        assert.strictEqual(log, "");
    });
});

describe("cli — cmdAllowlist", () => {
    test("allowlist add writes to file", async () => {
        const { saveAllowlistEntry } = await import("../../src/engine/allowlist.js");
        const tmpFile = "/tmp/sd-allowlist-add-test.toml";

        try { fs.unlinkSync(tmpFile); } catch {}

        saveAllowlistEntry({
            description: "Test allowlist entry",
            fingerprint: "abcdef12",
        }, tmpFile);

        const content = fs.readFileSync(tmpFile, "utf8");
        assert.ok(content.includes("[[entries]]"));
        assert.ok(content.includes("fingerprint = \"abcdef12\""));

        try { fs.unlinkSync(tmpFile); } catch {}
    });

    test("allowlist filterByAllowlist removes matching entries", async () => {
        const { filterByAllowlist } = await import("../../src/engine/allowlist.js");
        const { fingerprint } = await import("../../src/shared/fingerprint.js");

        const fp = fingerprint("AKIAIOSFODNN7EXAMPLE");
        const finding = {
            ruleId: "aws-access-token",
            description: "Test",
            match: "AKIAIOSFODNN7EXAMPLE",
            redacted: `[REDACTED:aws-access-token:${fp}]`,
            offset: 0,
            source: "file",
        };

        const allowlist = {
            entries: [{ fingerprint: fingerprint("AKIAIOSFODNN7EXAMPLE") }],
        };

        const filtered = filterByAllowlist([finding], allowlist);
        assert.strictEqual(filtered.length, 0);
    });
});