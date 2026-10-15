import { scanAndRedact, toSafeFinding } from "../engine/scanner.js";
import { readAuditLog, resolveAuditPath } from "../engine/audit.js";
import { loadAllowlist, saveAllowlistEntry } from "../engine/allowlist.js";
import { NAMED_RULES, ENTROPY_RULES, CLEAN_ROOM_RULES } from "../engine/rules.js";
import { VERSION } from "../shared/version.js";
/** Rule count across every rule family. */
export function ruleCount() {
    return NAMED_RULES.length + CLEAN_ROOM_RULES.length + ENTROPY_RULES.length;
}
/** `sd_status` */
export function sdStatus(deps = {}) {
    const path = deps.auditPath ?? resolveAuditPath();
    let findingCount = 0;
    try {
        findingCount = readAuditLog(path).split("\n").filter((l) => l.trim()).length;
    }
    catch {
        // Audit log may not exist yet.
    }
    return `strangerDanger v${VERSION}\nRules: ${ruleCount()}\nFindings this session: ${findingCount}\nAudit log: ${path}`;
}
/** `sd_audit` */
export function sdAudit(deps = {}) {
    const path = deps.auditPath ?? resolveAuditPath();
    let log;
    try {
        log = readAuditLog(path);
    }
    catch {
        return "Audit log not found.";
    }
    if (!log.trim())
        return "No audit entries yet.";
    return log
        .trim()
        .split("\n")
        .map((line) => {
        try {
            const entry = JSON.parse(line);
            return `[${entry.timestamp}] ${entry.ruleId} — fingerprint: ${entry.fingerprint} — source: ${entry.source}`;
        }
        catch {
            return line;
        }
    })
        .join("\n");
}
/** `sd_allowlist_show` */
export function sdAllowlistShow() {
    const allowlist = loadAllowlist();
    if (allowlist.entries.length === 0)
        return "No allowlist entries.";
    return allowlist.entries
        .map((e, i) => `${i + 1}. ${e.description || "(no description)"} | fingerprint: ${e.fingerprint || "—"} | ruleId: ${e.ruleId || "—"} | path: ${e.path || "—"} | regex: ${e.regex || "—"}`)
        .join("\n");
}
/** `sd_allowlist_add` */
export function sdAllowlistAdd(args) {
    const entry = {};
    if (args.description)
        entry.description = args.description;
    if (args.fingerprint)
        entry.fingerprint = args.fingerprint;
    if (args.ruleId)
        entry.ruleId = args.ruleId;
    if (args.path)
        entry.path = args.path;
    if (args.regex)
        entry.regex = args.regex;
    if (!entry.fingerprint && !entry.ruleId && !entry.path && !entry.regex) {
        return "No allowlist criteria supplied (need one of fingerprint, ruleId, path, regex).";
    }
    if (entry.regex) {
        try {
            new RegExp(entry.regex);
        }
        catch (err) {
            return `Invalid regex: ${err instanceof Error ? err.message : String(err)}`;
        }
    }
    if (entry.fingerprint && !/^[a-f0-9]{8}$/i.test(entry.fingerprint)) {
        return "Fingerprint must be 8 hexadecimal characters.";
    }
    saveAllowlistEntry(entry);
    return "Allowlist entry added.";
}
/** `sd_scan` — returns secret-free metadata only. */
export function sdScan(args) {
    const source = args.source ?? "file";
    const { findings } = scanAndRedact(args.content, source);
    if (findings.length === 0)
        return "No secrets detected.";
    return findings
        .map((f) => {
        const safe = toSafeFinding(f, args.content);
        return `${safe.ruleId}: ${safe.description}\n  Location: line ${safe.line ?? "?"}, column ${(safe.column ?? 0) + 1}\n  Fingerprint: ${safe.fingerprint}\n  Redaction: ${safe.redaction}`;
    })
        .join("\n\n");
}
//# sourceMappingURL=tools.js.map