import { readFileSync, statSync, readdirSync, lstatSync } from "node:fs";
import { join, extname } from "node:path";
import { scanAndRedactBounded, toSafeFinding } from "../../engine/scanner.js";
const SKIP_EXTENSIONS = new Set([
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".tiff", ".webp",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".o", ".obj",
    ".lock", ".lockb",
]);
const SKIP_DIRECTORIES = new Set(["node_modules", ".git"]);
/** Refuse to slurp absurdly large files into memory; report them explicitly. */
const MAX_READ_BYTES = 64 * 1024 * 1024;
function isBinary(content) {
    for (let i = 0; i < Math.min(content.length, 8192); i++) {
        if (content[i] === 0)
            return true;
    }
    return false;
}
function isRegularFile(filePath) {
    try {
        return lstatSync(filePath).isFile();
    }
    catch {
        return false;
    }
}
function scanText(text, source, filePath) {
    const { findings, complete, policy } = scanAndRedactBounded(text, source, filePath);
    const safe = findings.map((f) => toSafeFinding(f, text));
    if (!complete) {
        return { findings: safe, skipped: `${filePath ?? "<stdin>"}: could not be fully inspected (${policy})` };
    }
    return { findings: safe };
}
function scanFile(filePath, source) {
    if (!isRegularFile(filePath)) {
        return { findings: [], skipped: `${filePath}: not a regular file` };
    }
    let size = 0;
    try {
        size = statSync(filePath).size;
    }
    catch {
        return { findings: [], skipped: `${filePath}: unreadable` };
    }
    if (size > MAX_READ_BYTES) {
        return { findings: [], skipped: `${filePath}: exceeds ${MAX_READ_BYTES} byte read limit` };
    }
    const raw = readFileSync(filePath);
    if (isBinary(raw))
        return { findings: [] };
    return scanText(raw.toString("utf8"), source, filePath);
}
function scanDirectory(dirPath, source) {
    const allFindings = [];
    const skipped = [];
    function walk(dir, depth) {
        if (depth > 64)
            return;
        let entries;
        try {
            entries = readdirSync(dir, { withFileTypes: true });
        }
        catch {
            skipped.push(`${dir}: unreadable directory`);
            return;
        }
        for (const entry of entries) {
            const fullPath = join(dir, entry.name);
            // Never follow symlinks while walking: avoids cycles and traversal.
            if (entry.isSymbolicLink())
                continue;
            if (entry.isDirectory()) {
                if (SKIP_DIRECTORIES.has(entry.name))
                    continue;
                walk(fullPath, depth + 1);
            }
            else if (entry.isFile()) {
                const ext = extname(entry.name).toLowerCase();
                if (SKIP_EXTENSIONS.has(ext))
                    continue;
                const outcome = scanFile(fullPath, source);
                allFindings.push(...outcome.findings);
                if (outcome.skipped)
                    skipped.push(outcome.skipped);
            }
        }
    }
    walk(dirPath, 0);
    return { findings: allFindings, skipped };
}
function printHuman(target, findings, skipped) {
    if (findings.length === 0 && skipped.length === 0) {
        console.log(`No secrets detected in ${target}.`);
        return;
    }
    if (findings.length > 0) {
        console.log(`Found ${findings.length} secret(s) in ${target}:`);
        for (const f of findings) {
            const where = f.filePath ? `${f.filePath}${f.line ? `:${f.line}:${(f.column ?? 0) + 1}` : ""}` : f.source;
            console.log(`  ${f.ruleId}: ${f.description}`);
            console.log(`    Location: ${where}`);
            console.log(`    Fingerprint: ${f.fingerprint}`);
            console.log(`    Redaction: ${f.redaction}`);
        }
    }
    else {
        console.log(`No secrets detected in ${target}.`);
    }
    for (const s of skipped)
        console.error(`Warning: ${s}`);
}
export async function cmdScan(positional, flags) {
    const source = flags.source || "file";
    const asJson = !!flags.json;
    if (positional.length === 0) {
        console.error("Usage: sd scan <file|directory|->");
        process.exit(1);
    }
    const target = positional[0];
    if (target === "-") {
        let input = "";
        for await (const chunk of process.stdin) {
            input += chunk.toString();
        }
        const outcome = scanText(input, source);
        if (asJson) {
            console.log(JSON.stringify({ findings: outcome.findings, skipped: outcome.skipped ? [outcome.skipped] : [] }, null, 2));
            return;
        }
        printHuman("<stdin>", outcome.findings, outcome.skipped ? [outcome.skipped] : []);
        return;
    }
    try {
        const stats = statSync(target);
        let findings;
        let skipped = [];
        if (stats.isDirectory()) {
            const result = scanDirectory(target, source);
            findings = result.findings;
            skipped = result.skipped;
        }
        else {
            const outcome = scanFile(target, source);
            findings = outcome.findings;
            if (outcome.skipped)
                skipped = [outcome.skipped];
        }
        if (asJson) {
            console.log(JSON.stringify({ findings, skipped }, null, 2));
        }
        else {
            printHuman(target, findings, skipped);
        }
    }
    catch (err) {
        console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
    }
}
//# sourceMappingURL=scan.js.map