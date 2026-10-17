import type { Finding } from "./types.js";
/**
 * Scan content against all rules and return findings.
 */
export declare function scan(content: string, source: Finding["source"], filePath?: string): Finding[];
/**
 * Redact all findings in the content, replacing each secret with its redaction token.
 * Overlapping matches are handled by keeping the earliest (lowest offset) match.
 */
export declare function redact(content: string, findings: Finding[]): string;
/**
 * Scan and redact in one step. Returns the redacted content and the findings.
 */
export declare function scanAndRedact(content: string, source: Finding["source"], filePath?: string): {
    redacted: string;
    findings: Finding[];
};
/** Hard ceiling to avoid unbounded memory/time on absurd input. */
export declare const MAX_BOUNDED_SCAN_BYTES: number;
/** Explicit marker used when content cannot be inspected safely. */
export declare const UNSCANNABLE_MARKER = "[REDACTED:strangerdanger-oversized-unscannable]";
export type BoundedScanResult = {
    redacted: string;
    findings: Finding[];
    /** True when the whole input was inspected. */
    complete: boolean;
    /** Machine-readable reason when `complete` is false. */
    policy?: "oversized" | "window-timeout" | "window-error";
};
/**
 * Overridable bounds for `scanAndRedactBounded`. Production callers use the
 * defaults; tests inject small values so the oversized/timeout fail-closed
 * branches can be exercised with a controlled payload instead of hundreds of
 * megabytes of real input.
 */
export type BoundedScanOptions = {
    /** Hard ceiling on input length (characters). */
    maxBytes?: number;
    /** Characters scanned per window. */
    window?: number;
    /** Characters of overlap between windows; must be < `window`. */
    overlap?: number;
    /** Per-window time budget in milliseconds. */
    windowBudgetMs?: number;
    /** Clock injection for deterministic timeout tests. */
    now?: () => number;
};
/**
 * Scan and redact arbitrarily large text without silently truncating it.
 *
 * Large content is scanned in overlapping windows so secrets that cross a
 * window boundary are still detected. Findings are collected across windows,
 * deduplicated, and applied once to the whole input, so non-sensitive content
 * is preserved byte-for-byte. If a window cannot be inspected (timeout, error,
 * or input beyond the hard ceiling), the result fails closed with an explicit
 * marker and `complete: false` rather than emitting uninspected content.
 */
export declare function scanAndRedactBounded(content: string, source: Finding["source"], filePath?: string, options?: BoundedScanOptions): BoundedScanResult;
/**
 * Safe, machine-readable projection of a finding. Never includes the raw
 * matched secret, so it is safe to print, log, or return from a tool.
 */
export type SafeFinding = {
    ruleId: string;
    description: string;
    source: Finding["source"];
    /** 1-based line number, when the finding has a location in text. */
    line?: number;
    /** 0-based column on `line`. */
    column?: number;
    offset: number;
    filePath?: string;
    fingerprint: string;
    /** The redaction token that replaced the secret. */
    redaction: string;
};
/** Convert a finding to a secret-free projection for output. */
export declare function toSafeFinding(finding: Finding, content?: string): SafeFinding;
//# sourceMappingURL=scanner.d.ts.map