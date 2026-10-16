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
 * part inputs/results) while preserving its shape and types.
 *
 * Fail-safe behavior:
 *   - A cyclic structure is detected with a `seen` set instead of recursing
 *     until the stack overflows. (Before this guard, a self-referential object
 *     threw a `RangeError`, the surrounding hook caught it, and *every* string
 *     in the result was left unredacted — a silent fail-open.)
 *   - A value that cannot be safely inspected (beyond `MAX_STRUCTURED_DEPTH`)
 *     is replaced with the explicit fail-closed marker, never passed through
 *     silently.
 *   - Exotic objects (anything whose prototype is not `Object.prototype`/`null`)
 *     are left untouched so non-plain data is never corrupted; this residual
 *     limit is documented in the README.
 */
export declare function redactStructured(value: unknown, source: Finding["source"], ctx: AuditContext, depth?: number, seen?: WeakSet<object>): unknown;
/**
 * Redact in place, replacing only string leaves of a plain object/array.
 * Cycle-safe; a cyclic or over-deep branch is left untouched (this helper is a
 * best-effort in-place variant and cannot fail closed by substituting a value).
 */
export declare function redactStructuredInPlace(value: unknown, source: Finding["source"], ctx: AuditContext, depth?: number, seen?: WeakSet<object>): void;
//# sourceMappingURL=redact.d.ts.map