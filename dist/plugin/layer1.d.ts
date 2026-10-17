import { type AuditContext } from "./redact.js";
export type Layer1Event = {
    tool: string;
    sessionID?: string;
    input?: unknown;
};
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
export declare function handleLayer1(event: Layer1Event, ctx: AuditContext): Promise<void>;
//# sourceMappingURL=layer1.d.ts.map