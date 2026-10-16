import { NAMED_RULES, ENTROPY_RULES, CLEAN_ROOM_RULES } from "./rules.js";
import { shannonEntropy, BASE64_CHARSET, HEX_CHARSET, matchesCharset } from "./entropy.js";
import { filterByAllowlist, loadAllowlist } from "./allowlist.js";
import { fingerprint } from "../shared/fingerprint.js";
const REDACTION_PREFIX = "[REDACTED:";
const REDACTION_SUFFIX = "]";
function makeRedactionToken(ruleId, value) {
    return `${REDACTION_PREFIX}${ruleId}:${fingerprint(value)}${REDACTION_SUFFIX}`;
}
/**
 * Deduplicate findings by preferring shorter/more specific matches.
 * When multiple rules match overlapping regions, the shortest match (most specific) wins.
 */
function deduplicateFindings(findings) {
    if (findings.length <= 1)
        return findings;
    // Sort by:
    // 1. Match length ascending (shorter/more-specific wins)
    // 2. Offset ascending (earlier first)
    // 3. Non-generic rules before generic ones (specific wins)
    const GENERIC_RULES = new Set(["generic-api-key", "generic-api-key-2"]);
    const sorted = [...findings].sort((a, b) => {
        const lenDiff = a.match.length - b.match.length;
        if (lenDiff !== 0)
            return lenDiff;
        const offsetDiff = a.offset - b.offset;
        if (offsetDiff !== 0)
            return offsetDiff;
        // Prefer specific (non-generic) rules over generic ones
        const aGeneric = GENERIC_RULES.has(a.ruleId);
        const bGeneric = GENERIC_RULES.has(b.ruleId);
        if (aGeneric !== bGeneric)
            return aGeneric ? 1 : -1;
        return a.ruleId.localeCompare(b.ruleId);
    });
    const deduped = [];
    for (const finding of sorted) {
        const fStart = finding.offset;
        const fEnd = finding.offset + finding.match.length;
        // Skip if this finding overlaps with any already-kept (shorter/more specific) finding
        const overlaps = deduped.some((kept) => {
            const kStart = kept.offset;
            const kEnd = kept.offset + kept.match.length;
            return fStart < kEnd && fEnd > kStart;
        });
        if (!overlaps) {
            deduped.push(finding);
        }
    }
    // Return sorted by offset for deterministic output
    return deduped.sort((a, b) => a.offset - b.offset);
}
function hasKeyword(text, keywords) {
    const lower = text.toLowerCase();
    return keywords.some((kw) => lower.includes(kw.toLowerCase()));
}
/**
 * Scan content against all rules and return findings.
 */
export function scan(content, source, filePath) {
    const findings = [];
    // Whole-content keyword prefilter. A rule whose `keywords` do not appear
    // anywhere cannot match (its regex requires the keyword in context), so it
    // is skipped entirely. This turns the scan from "run 236 regexes over every
    // character" into "run only the handful of plausible rules", which is the
    // difference between ~100 s and a few ms on a multi-megabyte line.
    const lowerContent = content.toLowerCase();
    for (const rule of [...NAMED_RULES, ...CLEAN_ROOM_RULES]) {
        if (rule.keywords.length > 0 && !rule.keywords.some((kw) => lowerContent.includes(kw.toLowerCase()))) {
            continue;
        }
        rule.regex.lastIndex = 0;
        let match;
        while ((match = rule.regex.exec(content)) !== null) {
            const secretValue = match[1] ?? match[0];
            const offset = match[1] !== undefined
                ? match.index + match[0].indexOf(match[1])
                : match.index;
            if (secretValue.length < 6) {
                rule.regex.lastIndex = match.index + 1;
                continue;
            }
            if (rule.keywords.length > 0) {
                const contextStart = Math.max(0, offset - 80);
                const contextEnd = Math.min(content.length, offset + secretValue.length + 80);
                const context = content.slice(contextStart, contextEnd);
                if (!hasKeyword(context, rule.keywords)) {
                    rule.regex.lastIndex = match.index + 1;
                    continue;
                }
            }
            if (rule.entropy !== undefined) {
                const entropy = shannonEntropy(secretValue);
                if (entropy < rule.entropy) {
                    rule.regex.lastIndex = match.index + 1;
                    continue;
                }
            }
            findings.push({
                ruleId: rule.id,
                description: rule.description,
                match: secretValue,
                redacted: makeRedactionToken(rule.id, secretValue),
                offset,
                source,
                ...(filePath ? { filePath } : {}),
            });
        }
    }
    for (const rule of ENTROPY_RULES) {
        rule.regex.lastIndex = 0;
        let match;
        while ((match = rule.regex.exec(content)) !== null) {
            const candidate = match[1] ?? match[0];
            const offset = match[1] !== undefined
                ? match.index + match[0].indexOf(match[1])
                : match.index;
            if (candidate.length < 20) {
                rule.regex.lastIndex = match.index + 1;
                continue;
            }
            let threshold = 4.0;
            if (matchesCharset(candidate, BASE64_CHARSET)) {
                threshold = 4.5;
            }
            else if (matchesCharset(candidate, HEX_CHARSET)) {
                threshold = 3.0;
            }
            const entropy = shannonEntropy(candidate);
            if (entropy < threshold) {
                rule.regex.lastIndex = match.index + 1;
                continue;
            }
            findings.push({
                ruleId: rule.id,
                description: rule.description,
                match: candidate,
                redacted: makeRedactionToken(rule.id, candidate),
                offset,
                source,
                ...(filePath ? { filePath } : {}),
            });
        }
    }
    return deduplicateFindings(findings);
}
/**
 * Redact all findings in the content, replacing each secret with its redaction token.
 * Overlapping matches are handled by keeping the earliest (lowest offset) match.
 */
export function redact(content, findings) {
    if (findings.length === 0)
        return content;
    // Defensive: ignore findings that do not point at real, non-empty ranges of
    // this content (bad offsets from custom callers, or empty matches).
    const valid = findings.filter((f) => f.offset >= 0 && f.offset < content.length && f.match.length > 0 && f.offset + f.match.length <= content.length);
    if (valid.length === 0)
        return content;
    const sorted = [...valid].sort((a, b) => a.offset - b.offset);
    const nonOverlapping = [];
    let lastEnd = 0;
    for (const finding of sorted) {
        if (finding.offset >= lastEnd) {
            nonOverlapping.push(finding);
            lastEnd = finding.offset + finding.match.length;
        }
    }
    let result = "";
    let prevEnd = 0;
    for (const finding of nonOverlapping) {
        result += content.slice(prevEnd, finding.offset);
        result += finding.redacted;
        prevEnd = finding.offset + finding.match.length;
    }
    result += content.slice(prevEnd);
    return result;
}
/**
 * Scan and redact in one step. Returns the redacted content and the findings.
 */
export function scanAndRedact(content, source, filePath) {
    const rawFindings = scan(content, source, filePath);
    const allowlist = loadAllowlist();
    const findings = filterByAllowlist(rawFindings, allowlist);
    const redacted = redact(content, findings);
    return { redacted, findings };
}
/**
 * Size of each scanning window for large content. Content at or below this size
 * is scanned in a single pass.
 */
const SCAN_WINDOW = 1024 * 1024;
/**
 * Overlap between consecutive windows. Must be at least the length of the
 * longest match any rule can produce so a secret that straddles a window
 * boundary is still fully contained in one window.
 */
const SCAN_OVERLAP = 64 * 1024;
/** Per-window time budget. A window that exceeds it makes the scan fail closed. */
const SCAN_WINDOW_BUDGET_MS = 2500;
/** Hard ceiling to avoid unbounded memory/time on absurd input. */
export const MAX_BOUNDED_SCAN_BYTES = 256 * 1024 * 1024;
/** Explicit marker used when content cannot be inspected safely. */
export const UNSCANNABLE_MARKER = "[REDACTED:strangerdanger-oversized-unscannable]";
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
export function scanAndRedactBounded(content, source, filePath, options = {}) {
    const windowSize = options.window ?? SCAN_WINDOW;
    const overlap = Math.min(options.overlap ?? SCAN_OVERLAP, Math.max(0, windowSize - 1));
    const maxBytes = options.maxBytes ?? MAX_BOUNDED_SCAN_BYTES;
    const budgetMs = options.windowBudgetMs ?? SCAN_WINDOW_BUDGET_MS;
    const now = options.now ?? Date.now;
    if (content.length === 0) {
        return { redacted: content, findings: [], complete: true };
    }
    if (content.length <= windowSize) {
        const { redacted, findings } = scanAndRedact(content, source, filePath);
        return { redacted, findings, complete: true };
    }
    if (content.length > maxBytes) {
        return { redacted: UNSCANNABLE_MARKER, findings: [], complete: false, policy: "oversized" };
    }
    const stride = windowSize - overlap;
    const collected = [];
    const seen = new Set();
    for (let start = 0; start < content.length; start += stride) {
        const end = Math.min(start + windowSize, content.length);
        const window = content.slice(start, end);
        const windowStart = now();
        let windowFindings;
        try {
            windowFindings = scan(window, source, filePath);
        }
        catch {
            return { redacted: UNSCANNABLE_MARKER, findings: collected, complete: false, policy: "window-error" };
        }
        if (now() - windowStart > budgetMs) {
            return { redacted: UNSCANNABLE_MARKER, findings: collected, complete: false, policy: "window-timeout" };
        }
        for (const f of windowFindings) {
            const absolute = { ...f, offset: start + f.offset };
            const key = `${absolute.ruleId}:${absolute.offset}:${absolute.match.length}`;
            if (!seen.has(key)) {
                seen.add(key);
                collected.push(absolute);
            }
        }
        if (end >= content.length)
            break;
    }
    const allowlist = loadAllowlist();
    const findings = filterByAllowlist(collected, allowlist);
    return { redacted: redact(content, findings), findings, complete: true };
}
/** Convert a finding to a secret-free projection for output. */
export function toSafeFinding(finding, content) {
    const fpMatch = finding.redacted.match(/:([a-f0-9]{8})\]/);
    const safe = {
        ruleId: finding.ruleId,
        description: finding.description,
        source: finding.source,
        offset: finding.offset,
        fingerprint: fpMatch ? fpMatch[1] : "",
        redaction: finding.redacted,
    };
    if (finding.filePath)
        safe.filePath = finding.filePath;
    if (content !== undefined) {
        const before = content.slice(0, finding.offset);
        const lastNewline = before.lastIndexOf("\n");
        safe.line = before.split("\n").length;
        safe.column = finding.offset - (lastNewline + 1);
    }
    return safe;
}
//# sourceMappingURL=scanner.js.map