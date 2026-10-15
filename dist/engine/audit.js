import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync, } from "node:fs";
import { dirname, join } from "node:path";
import { fingerprint as fingerprintOf } from "../shared/fingerprint.js";
const STATE_DIRNAME = ".opencode";
const STATE_SUBDIR = "state";
const AUDIT_FILENAME = "strangerdanger-audit.jsonl";
/** File mode for audit files (owner read/write only — never world-readable). */
const AUDIT_FILE_MODE = 0o600;
/** File mode for the directory holding audit files. */
const AUDIT_DIR_MODE = 0o700;
/** Rotate the log once it passes this size, keeping at most `MAX_ROTATIONS` files. */
const MAX_AUDIT_BYTES = 10 * 1024 * 1024;
const MAX_ROTATIONS = 3;
/**
 * The audit path used by the standalone CLI and by callers that do not pass an
 * explicit path. It is intentionally NOT a shared, mutable, process-global
 * value that the plugin relies on: the OpenCode plugin resolves a path per
 * project/session and passes it explicitly to every write, so that concurrent
 * projects in one server process never mix their audit records.
 */
let auditPathOverride;
/**
 * Resolve the default audit path for a project directory. Audit logs are
 * per-project runtime state: they live under the project's own
 * `.opencode/state/` directory and are kept out of version control.
 */
export function resolveAuditPath(options) {
    const base = options?.directory && options.directory.length > 0 ? options.directory : process.cwd();
    return join(base, STATE_DIRNAME, STATE_SUBDIR, AUDIT_FILENAME);
}
/** Override the path used when no explicit path is supplied (CLI/tests). */
export function setAuditPath(path) {
    auditPathOverride = path;
}
/** Get the path used when no explicit path is supplied. */
export function getAuditPath() {
    return auditPathOverride ?? resolveAuditPath();
}
function ensureDirectory(dir) {
    if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true, mode: AUDIT_DIR_MODE });
    }
}
/**
 * Bound on-disk growth. Existing records are preserved by renaming the log to
 * `.1`, `.2`, ... before truncating, rather than deleting content outright.
 */
function maybeRotate(path) {
    let size = 0;
    try {
        size = statSync(path).size;
    }
    catch {
        return;
    }
    if (size < MAX_AUDIT_BYTES)
        return;
    for (let i = MAX_ROTATIONS - 1; i >= 1; i--) {
        const from = `${path}.${i}`;
        const to = `${path}.${i + 1}`;
        if (existsSync(from)) {
            try {
                renameSync(from, to);
            }
            catch {
                // Best-effort rotation — never lose the live log over this.
            }
        }
    }
    try {
        renameSync(path, `${path}.1`);
    }
    catch {
        // If rotation fails, keep appending rather than discarding records.
    }
}
/**
 * Write one audit record as a single JSONL line. Each line is appended with
 * O_APPEND semantics, so concurrent writers interleave whole lines rather than
 * corrupting each other's records.
 */
export function writeAudit(entry, path) {
    const target = path ?? getAuditPath();
    const dir = dirname(target);
    ensureDirectory(dir);
    maybeRotate(target);
    const line = JSON.stringify({
        ...entry,
        timestamp: entry.timestamp || new Date().toISOString(),
    });
    appendFileSync(target, line + "\n", { encoding: "utf8", mode: AUDIT_FILE_MODE });
}
export function writeAuditBatch(entries, path) {
    for (const entry of entries) {
        writeAudit(entry, path);
    }
}
export function readAuditLog(path) {
    const target = path ?? getAuditPath();
    if (!existsSync(target))
        return "";
    return readFileSync(target, "utf8");
}
/**
 * Build a safe audit record from a finding. Only metadata is recorded — never
 * the raw matched secret or the redacted replacement (which can embed the
 * secret's fingerprint but is still not the secret).
 */
export function auditEntryFromFinding(finding, options) {
    const fpMatch = finding.redacted.match(/:([a-f0-9]{8})\]/);
    return {
        timestamp: new Date().toISOString(),
        ...(options?.sessionId ? { sessionId: options.sessionId } : {}),
        source: (options?.source ?? finding.source),
        ruleId: finding.ruleId,
        description: finding.description,
        fingerprint: fpMatch ? fpMatch[1] : "",
        ...((options?.filePath ?? finding.filePath) ? { filePath: options?.filePath ?? finding.filePath } : {}),
    };
}
/** Fingerprint helper re-export for callers that only need the audit module. */
export { fingerprintOf };
//# sourceMappingURL=audit.js.map