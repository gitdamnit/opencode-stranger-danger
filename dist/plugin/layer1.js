import { readFileSync, statSync } from "node:fs";
import { scan } from "../engine/scanner.js";
import { loadAllowlist, filterByAllowlist } from "../engine/allowlist.js";
import { recordFindings } from "./redact.js";
/**
 * A file larger than this is not inspected here. The tool-result boundary
 * (layer 3) still handles it with bounded, chunk-safe scanning.
 */
const MAX_FILE_SIZE = 10 * 1024 * 1024;
function isBinary(content) {
    for (let i = 0; i < Math.min(content.length, 8192); i++) {
        if (content[i] === 0)
            return true;
    }
    return false;
}
/**
 * Pre-execution inspection for file-oriented tools.
 *
 * IMPORTANT: this hook is strictly read-only. Reading a file must never modify
 * its contents. Earlier versions rewrote the file on disk when they detected a
 * secret, which silently corrupted the user's working tree. This hook now only
 * *detects* secrets and records an audit entry. Redaction of what the model
 * actually sees happens at the supported V2 boundaries:
 *
 *   - `ctx.tool.hook("execute.after")` rewrites the tool result (layer 3).
 *   - `ctx.session.hook("context")` rewrites the assembled model request.
 *
 * Files that cannot be safely inspected (non-regular files such as FIFOs or
 * device nodes, binaries, or very large files) are skipped here and left to the
 * result/context boundaries, so a `read` never blocks on a named pipe.
 */
export async function handleLayer1(event, ctx) {
    try {
        const tool = event.tool;
        if (tool !== "read" && tool !== "edit" && tool !== "write")
            return;
        const input = event.input;
        const filePath = input?.filePath;
        if (typeof filePath !== "string" || filePath.length === 0)
            return;
        let stats;
        try {
            stats = statSync(filePath);
        }
        catch {
            return;
        }
        // Only regular files: never read FIFOs, sockets, or devices (would block).
        if (!stats.isFile())
            return;
        if (stats.size > MAX_FILE_SIZE)
            return;
        const raw = readFileSync(filePath);
        if (isBinary(raw))
            return;
        const content = raw.toString("utf8");
        const findings = filterByAllowlist(scan(content, "file", filePath), loadAllowlist());
        recordFindings(findings, "file", { ...ctx, sessionId: event.sessionID }, filePath);
        // Intentionally no writeFileSync. The original file is never modified.
    }
    catch {
        // Degrade gracefully — never block tool execution.
    }
}
//# sourceMappingURL=layer1.js.map