import type { Finding } from "../engine/types.js";
/**
 * Everything the plugin layers need to write safe audit records without
 * relying on shared, mutable, process-global state.
 */
export type AuditContext = {
    /** Explicit audit path for this plugin instance (project-scoped). */
    auditPath?: string;
    /** Session ID when the surrounding hook supplies one. */
    sessionId?: string;
};
/**
 * Record findings as secret-free audit entries.
 *
 * Requires an explicit, project-scoped `auditPath`. Hooks must never fall back
 * to a shared, mutable, process-global path, because one OpenCode server
 * process can host plugins for several projects at once.
 */
export declare function recordFindings(findings: Finding[], source: Finding["source"], ctx: AuditContext, filePath?: string): void;
/**
 * Redact a single string. Uses bounded scanning so arbitrarily large text is
 * fully inspected (or fails closed) rather than silently truncated.
 */
export declare function redactText(text: string, source: Finding["source"], ctx: AuditContext, filePath?: string): string;
/**
 * Redact string leaves of a structured value (tool output, metadata, message
 * part inputs/results) while preserving its shape and types. Exotic objects are
 * left untouched so we never corrupt non-plain data.
 */
export declare function redactStructured(value: unknown, source: Finding["source"], ctx: AuditContext, depth?: number): unknown;
/** Redact in place, replacing only string leaves of a plain object/array. */
export declare function redactStructuredInPlace(value: unknown, source: Finding["source"], ctx: AuditContext, depth?: number): void;
//# sourceMappingURL=redact.d.ts.map