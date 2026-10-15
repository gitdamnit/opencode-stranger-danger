import { scanAndRedactBounded } from "../engine/scanner.js";
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
/** Maximum nesting depth traversed when redacting structured values. */
const MAX_STRUCTURED_DEPTH = 8;
/**
 * Redact string leaves of a structured value (tool output, metadata, message
 * part inputs/results) while preserving its shape and types. Exotic objects are
 * left untouched so we never corrupt non-plain data.
 */
export function redactStructured(value, source, ctx, depth = 0) {
    if (typeof value === "string")
        return redactText(value, source, ctx);
    if (value === null || typeof value !== "object" || depth >= MAX_STRUCTURED_DEPTH)
        return value;
    if (Array.isArray(value)) {
        const out = new Array(value.length);
        for (let i = 0; i < value.length; i++)
            out[i] = redactStructured(value[i], source, ctx, depth + 1);
        return out;
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null)
        return value;
    const out = {};
    for (const [k, v] of Object.entries(value)) {
        out[k] = redactStructured(v, source, ctx, depth + 1);
    }
    return out;
}
/** Redact in place, replacing only string leaves of a plain object/array. */
export function redactStructuredInPlace(value, source, ctx, depth = 0) {
    if (value === null || typeof value !== "object" || depth >= MAX_STRUCTURED_DEPTH)
        return;
    if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
            const v = value[i];
            if (typeof v === "string")
                value[i] = redactText(v, source, ctx);
            else
                redactStructuredInPlace(v, source, ctx, depth + 1);
        }
        return;
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null)
        return;
    for (const [k, v] of Object.entries(value)) {
        if (typeof v === "string")
            value[k] = redactText(v, source, ctx);
        else
            redactStructuredInPlace(v, source, ctx, depth + 1);
    }
}
//# sourceMappingURL=redact.js.map