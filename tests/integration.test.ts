import { test, describe } from "node:test";
import assert from "node:assert";
import assertStrict from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { scanAndRedact } from "../src/engine/scanner.js";
import { loadAllowlist, saveAllowlistEntry, filterByAllowlist } from "../src/engine/allowlist.js";
import { writeAuditBatch, auditEntryFromFinding, readAuditLog, setAuditPath } from "../src/engine/audit.js";
import { fingerprint } from "../src/shared/fingerprint.js";

describe("integration — scan → redact → verify pipeline", () => {
    test("full pipeline: scan file with secret, redact, verify clean", () => {
        const tmpDir = "/tmp/sd-integration-pipeline";
        const filePath = path.join(tmpDir, "config.ts");

        try {
            fs.mkdirSync(tmpDir, { recursive: true });

            // 1. Write a file with a known secret
            const originalContent = 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\nconst PORT = 3000;';
            fs.writeFileSync(filePath, originalContent);

            // 2. Scan the file
            const content = fs.readFileSync(filePath, "utf8");
            const { findings } = scanAndRedact(content, "file", filePath);

            assertStrict.ok(findings.length > 0, "Should find at least one secret");
            const awsFindings = findings.filter((f) => f.ruleId === "aws-access-token");
            assertStrict.ok(awsFindings.length >= 1, "Should find AWS access key");

            // 3. Verify redacted content doesn't contain the secret
            const redacted = scanAndRedact(content, "file", filePath).redacted;
            assert.ok(!redacted.includes("AKIAIOSFODNN7EXAMPLE"), "Secret should be redacted");
            assert.ok(redacted.includes("PORT"), "Non-secret content should be preserved");
            assert.ok(redacted.includes("[REDACTED:"), "Should contain redaction markers");

            // 4. Write redacted content back
            fs.writeFileSync(filePath, redacted, "utf8");

            // 5. Re-scan and verify no findings
            const rescanned = fs.readFileSync(filePath, "utf8");
            const { findings: rescannedFindings } = scanAndRedact(rescanned, "file", filePath);
            const awsRescanned = rescannedFindings.filter((f) => f.ruleId === "aws-access-token");
            assertStrict.strictEqual(awsRescanned.length, 0, "No AWS keys should remain after redaction");
        } finally {
            try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
        }
    });

    test("scanAndRedact with allowlist filters expected findings", () => {
        // This tests that scanAndRedact → filterByAllowlist integration works
        const knownKey = "AKIAIOSFODNN7EXAMPLE";
        const content = `const key = "${knownKey}";`;

        // First scan without allowlist
        const { findings: unfiltered } = scanAndRedact(content, "file");
        const awsUnfiltered = unfiltered.filter((f) => f.ruleId === "aws-access-token");
        assertStrict.ok(awsUnfiltered.length >= 1, "Should find AWS key without allowlist");

        // Now add to allowlist and use manual scan + filter
        const tmpAllowlist = "/tmp/sd-allowlist-integration.toml";
        try { fs.unlinkSync(tmpAllowlist); } catch {}

        saveAllowlistEntry({ fingerprint: fingerprint(knownKey) }, tmpAllowlist);

        // Verify allowlist loads
        const allowlist = loadAllowlist(tmpAllowlist);
        assertStrict.strictEqual(allowlist.entries.length, 1);
        assertStrict.strictEqual(allowlist.entries[0].fingerprint, fingerprint(knownKey));

        // Scan (which loads default allowlist, not our test one) then manually filter
        const { findings: rawFindings } = scanAndRedact(content, "file");
        const filtered = filterByAllowlist(rawFindings, allowlist);

        const awsFiltered = filtered.filter((f) => f.ruleId === "aws-access-token");
        assertStrict.strictEqual(awsFiltered.length, 0, "AWS key should be filtered by allowlist");

        try { fs.unlinkSync(tmpAllowlist); } catch {}
    });

    test("audit records findings without storing raw secrets", () => {
        const tmpDir = "/tmp/sd-integration-audit";
        const filePath = path.join(tmpDir, "config.ts");
        const auditPath = path.join(tmpDir, "audit.jsonl");

        try {
            fs.mkdirSync(tmpDir, { recursive: true });
            setAuditPath(auditPath);

            const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
            fs.writeFileSync(filePath, content);

            // scanAndRedact is pure detection + redaction; the caller records
            // audit entries (the plugin/CLI layers do this at their boundaries).
            const { findings } = scanAndRedact(content, "file", filePath);
            assert.ok(findings.length > 0);
            writeAuditBatch(findings.map((f) => auditEntryFromFinding(f, { filePath, sessionId: "sess-1" })));

            assert.ok(fs.existsSync(auditPath));
            const logContent = readAuditLog();
            const lines = logContent.trim().split("\n").filter(Boolean);
            assert.ok(lines.length >= 1);

            const lastEntry = JSON.parse(lines[lines.length - 1]);
            assert.strictEqual(lastEntry.ruleId, findings[0].ruleId);
            assert.strictEqual(lastEntry.source, "file");
            assert.strictEqual(lastEntry.sessionId, "sess-1");
            assert.ok(lastEntry.fingerprint);
            assert.ok(!logContent.includes("AKIAIOSFODNN7EXAMPLE"), "audit log must not contain the raw secret");
        } finally {
            try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
        }
    });

    test("clean fixture yields zero findings through scanAndRedact", async () => {
        // Use the clean fixture
        const { cleanContent } = await import("./fixtures/clean.js");
        const { findings, redacted } = scanAndRedact(cleanContent, "file");
        assert.strictEqual(findings.length, 0);
        assert.strictEqual(redacted, cleanContent);
    });

    test("multiple secret types detected in single scan", () => {
        const content = `
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const GH_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234";
const MONGO = "mongodb+srv://admin:password@cluster0.example.mongodb.net/mydb";
const JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
`;
        const { findings } = scanAndRedact(content, "file");

        const ruleIds = findings.map((f) => f.ruleId);
        assertStrict.ok(ruleIds.includes("aws-access-token"), "Should detect AWS key");
        assertStrict.ok(ruleIds.includes("github-pat"), "Should detect GitHub PAT");
        assertStrict.ok(ruleIds.includes("mongodb-connection-string"), "Should detect MongoDB URI");
        assertStrict.ok(ruleIds.includes("jwt"), "Should detect JWT");
    });

    test("redacted content preserves file structure", () => {
        const content = [
            'import { config } from "dotenv";',
            "",
            'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";',
            'const DB_URI = "mongodb+srv://admin:pass@cluster.mongodb.net/mydb";',
            'const PORT = process.env.PORT || 3000;',
            "",
            "export { AWS_KEY, DB_URI, PORT };",
        ].join("\n");

        const { redacted } = scanAndRedact(content, "file");
        const lines = redacted.split("\n");

        assert.strictEqual(lines[0], 'import { config } from "dotenv";');
        assert.ok(lines[2].includes("[REDACTED:"));
        assert.ok(lines[3].includes("[REDACTED:"));
        assert.strictEqual(lines[4], 'const PORT = process.env.PORT || 3000;');
        assert.strictEqual(lines[6], "export { AWS_KEY, DB_URI, PORT };");
    });
});