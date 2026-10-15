import { readAuditLog, getAuditPath } from "../../engine/audit.js";
export async function cmdAudit() {
    const log = readAuditLog();
    if (!log.trim()) {
        console.log("No audit entries yet.");
        return;
    }
    const lines = log.trim().split("\n");
    console.log(`Audit log: ${getAuditPath()}`);
    console.log(`Entries: ${lines.length}`);
    console.log("");
    for (const line of lines) {
        try {
            const entry = JSON.parse(line);
            const session = entry.sessionId ? ` — session: ${entry.sessionId}` : "";
            const where = entry.filePath ? ` — ${entry.filePath}` : "";
            console.log(`[${entry.timestamp}] ${entry.ruleId} — ${entry.source} — fingerprint: ${entry.fingerprint}${session}${where}`);
        }
        catch {
            console.log(line);
        }
    }
}
//# sourceMappingURL=audit.js.map