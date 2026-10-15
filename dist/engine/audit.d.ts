import { fingerprint as fingerprintOf } from "../shared/fingerprint.js";
import type { AuditEntry, Finding } from "./types.js";
/**
 * Resolve the default audit path for a project directory. Audit logs are
 * per-project runtime state: they live under the project's own
 * `.opencode/state/` directory and are kept out of version control.
 */
export declare function resolveAuditPath(options?: {
    directory?: string;
}): string;
/** Override the path used when no explicit path is supplied (CLI/tests). */
export declare function setAuditPath(path: string): void;
/** Get the path used when no explicit path is supplied. */
export declare function getAuditPath(): string;
/**
 * Write one audit record as a single JSONL line. Each line is appended with
 * O_APPEND semantics, so concurrent writers interleave whole lines rather than
 * corrupting each other's records.
 */
export declare function writeAudit(entry: AuditEntry, path?: string): void;
export declare function writeAuditBatch(entries: AuditEntry[], path?: string): void;
export declare function readAuditLog(path?: string): string;
/**
 * Build a safe audit record from a finding. Only metadata is recorded — never
 * the raw matched secret or the redacted replacement (which can embed the
 * secret's fingerprint but is still not the secret).
 */
export declare function auditEntryFromFinding(finding: Finding, options?: {
    sessionId?: string;
    filePath?: string;
    source?: AuditEntry["source"];
}): AuditEntry;
/** Fingerprint helper re-export for callers that only need the audit module. */
export { fingerprintOf };
//# sourceMappingURL=audit.d.ts.map