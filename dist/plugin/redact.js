import { scanAndRedactBounded, UNSCANNABLE_MARKER } from "../engine/scanner.js";
import { writeAuditBatch, auditEntryFromFinding } from "../engine/audit.js";
/**
 * Record findings as secret-free audit entries.
 *
 * Requires an explicit, project-scoped `auditPath`. Hooks must never fall back
 * to a shared, mutable, process-global path, because one OpenCode server
 * process can host plugins for several projects at once.
 */
export function recordFindings(findings, source, ctx, filePath) {
    if (findings.length === 0 || !ctx.auditPath)
        return;
    writeAuditBatch(findings.map((f) => auditEntryFromFinding(f, { sessionId: ctx.sessionId, source, filePath })), ctx.auditPath);
}
/**
 * Redact a single string. Uses bounded scanning so arbitrarily large text is
 * fully inspected (or fails closed) rather than silently truncated.
 */
export function redactText(text, source, ctx, filePath) {
    if (!text)
        return text;
    const { redacted, findings, complete, policy } = scanAndRedactBounded(text, source, filePath);
    recordFindings(findings, source, ctx, filePath);
    if (!complete) {
        // Fail closed: mark the uninspectable content explicitly for the reader.
        return `${redacted}\n[strangerdanger: content not fully inspected (${policy})]`;
    }
    return redacted;
}
/**
 * Maximum nesting depth traversed when redacting structured values. Plain JSON
 * produced by tools is shallow; anything deeper than this is treated as
 * unexpected and fails closed (below) rather than being walked further.
 */
const MAX_STRUCTURED_DEPTH = 32;
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
export function redactStructured(value, source, ctx, depth = 0, seen = new WeakSet()) {
    if (typeof value === "string")
        return redactText(value, source, ctx);
    if (value === null || typeof value !== "object")
        return value;
    if (depth >= MAX_STRUCTURED_DEPTH)
        return UNSCANNABLE_MARKER;
    if (Array.isArray(value)) {
        if (seen.has(value))
            return UNSCANNABLE_MARKER;
        seen.add(value);
        const out = new Array(value.length);
        for (let i = 0; i < value.length; i++)
            out[i] = redactStructured(value[i], source, ctx, depth + 1, seen);
        seen.delete(value);
        return out;
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null)
        return value;
    if (seen.has(value))
        return UNSCANNABLE_MARKER;
    seen.add(value);
    const out = {};
    for (const [k, v] of Object.entries(value)) {
        out[k] = redactStructured(v, source, ctx, depth + 1, seen);
    }
    seen.delete(value);
    return out;
}
/**
 * Redact in place, replacing only string leaves of a plain object/array.
 * Cycle-safe; a cyclic or over-deep branch is left untouched (this helper is a
 * best-effort in-place variant and cannot fail closed by substituting a value).
 */
export function redactStructuredInPlace(value, source, ctx, depth = 0, seen = new WeakSet()) {
    if (value === null || typeof value !== "object" || depth >= MAX_STRUCTURED_DEPTH)
        return;
    if (seen.has(value))
        return;
    if (Array.isArray(value)) {
        seen.add(value);
        for (let i = 0; i < value.length; i++) {
            const v = value[i];
            if (typeof v === "string")
                value[i] = redactText(v, source, ctx);
            else
                redactStructuredInPlace(v, source, ctx, depth + 1, seen);
        }
        seen.delete(value);
        return;
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null)
        return;
    seen.add(value);
    for (const [k, v] of Object.entries(value)) {
        if (typeof v === "string")
            value[k] = redactText(v, source, ctx);
        else
            redactStructuredInPlace(v, source, ctx, depth + 1, seen);
    }
    seen.delete(value);
}
//# sourceMappingURL=redact.js.map