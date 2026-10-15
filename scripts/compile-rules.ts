import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const TOML_PATH = join(__dirname, "..", "rules", "gitleaks-rules.toml");
const OUTPUT_PATH = join(__dirname, "..", "src", "engine", "rules.ts");

interface TomlRule {
    id: string;
    description: string;
    regex: string;
    keywords: string[];
    entropy?: number;
}

function parseGitleaksToml(content: string): TomlRule[] {
    const rules: TomlRule[] = [];
    let current: Partial<TomlRule> | null = null;
    let inArray = false;
    let arrayKey = "";

    for (const rawLine of content.split("\n")) {
        const line = rawLine.trim();

        if (line.startsWith("[[rules]]")) {
            if (current && current.id) {
                rules.push(current as TomlRule);
            }
            current = { keywords: [] };
            inArray = false;
            continue;
        }

        if (line.startsWith("[[rules.allowlists]]") || line.startsWith("[rules.allowlists]")) {
            if (current && current.id) {
                rules.push(current as TomlRule);
            }
            current = null;
            inArray = false;
            continue;
        }

        if (line === "[allowlist]" || line.startsWith("[[allowlists]]")) {
            current = null;
            inArray = false;
            continue;
        }

        if (!current) continue;

        if (line.startsWith("keywords = ")) {
            const afterEq = line.slice(11).trim();
            if (afterEq.startsWith("[") && afterEq.endsWith("]")) {
                const inline = afterEq.slice(1, -1);
                current.keywords = inline.split(",").map((s) => s.replace(/'''/g, "").replace(/"/g, "").trim()).filter(Boolean);
            } else if (afterEq.startsWith("[")) {
                inArray = true;
                arrayKey = "keywords";
            }
            continue;
        }

        if (line.startsWith("regexes = [") || line.startsWith("paths = [")) {
            inArray = false;
            continue;
        }

        if (inArray && arrayKey === "keywords") {
            if (line === "]") {
                inArray = false;
                continue;
            }
            const cleaned = line.replace(/,$/, "").replace(/'''/g, "").replace(/"/g, "").trim();
            if (cleaned && current.keywords) {
                current.keywords.push(cleaned);
            }
            continue;
        }

        if (line.startsWith("id = ")) {
            current.id = line.slice(5).replace(/"/g, "").trim();
        } else if (line.startsWith("description = ")) {
            current.description = line.slice(14).replace(/"/g, "").trim();
        } else if (line.startsWith("regex = ")) {
            current.regex = line.slice(8).replace(/'''/g, "").trim();
        } else if (line.startsWith("entropy = ")) {
            current.entropy = parseFloat(line.slice(10).trim());
        } else if (line.startsWith("keywords = ") && !line.includes("[")) {
            const val = line.slice(11).replace(/"/g, "").trim();
            if (val) current.keywords = [val];
        }
    }

    if (current && current.id) {
        rules.push(current as TomlRule);
    }

    return rules;
}

/**
 * Translate the subset of RE2 / PCRE syntax used by gitleaks into plain
 * JavaScript RegExp source.
 *
 * JavaScript has no inline-flag groups, POSIX character classes, or `\z`
 * anchor, so rules that use them crash at `new RegExp(...)` time. This
 * function rewrites:
 *
 *   - POSIX classes  `[[:alnum:]]` → `[A-Za-z0-9]`
 *   - `\z`                            → `$`
 *   - named groups   `(?P<name>…)` / `(?<name>…)` → `(?:…)`
 *   - inline flags   `(?i:…)`, `(?s:…)`, `(?i)`   → global flags + `(?:…)`
 *
 * `(?-i:…)` (disable case-insensitivity for a region) has no JavaScript
 * equivalent. It is unwrapped to `(?:…)`, so a region that explicitly opted
 * out of case-insensitivity may be matched case-insensitively when the whole
 * rule enables the `i` flag. This only widens matching (more coverage, a few
 * more false positives) and never produces an invalid pattern.
 */
function processGitleaksRegex(raw: string): { pattern: string; flags: string } {
    let pattern = raw
        .replace(/\[\[:alnum:\]\]/g, "[A-Za-z0-9]")
        .replace(/\[\[:alpha:\]\]/g, "[A-Za-z]")
        .replace(/\[\[:digit:\]\]/g, "[0-9]")
        .replace(/\[\[:xdigit:\]\]/g, "[0-9A-Fa-f]")
        .replace(/\[\[:space:\]\]/g, "\\s")
        .replace(/\[\[:word:\]\]/g, "[A-Za-z0-9_]")
        .replace(/\[\[:upper:\]\]/g, "[A-Z]")
        .replace(/\[\[:lower:\]\]/g, "[a-z]")
        .replace(/\[\[:punct:\]\]/g, "[\\x21-\\x2f\\x3a-\\x40\\x5b-\\x60\\x7b-\\x7e]");

    let caseInsensitive = false;
    let dotAll = false;
    let multiline = false;

    let out = "";
    let i = 0;
    const n = pattern.length;

    while (i < n) {
        const ch = pattern[i];

        // Escapes: translate `\z` (RE2 end-of-string) to `$`.
        if (ch === "\\") {
            if (pattern[i + 1] === "z") {
                out += "$";
                i += 2;
                continue;
            }
            out += ch + (pattern[i + 1] ?? "");
            i += 2;
            continue;
        }

        // Copy character classes verbatim so their contents are never rewritten.
        if (ch === "[") {
            let j = i + 1;
            if (pattern[j] === "^") j++;
            if (pattern[j] === "]") j++;
            while (j < n && pattern[j] !== "]") {
                if (pattern[j] === "\\") j++;
                j++;
            }
            out += pattern.slice(i, j + 1);
            i = j + 1;
            continue;
        }

        if (ch === "(" && pattern[i + 1] === "?") {
            const rest = pattern.slice(i);

            // Named groups → non-capturing groups.
            const named = /^\(\?P<[^>]*>/.exec(rest) ?? /^\(\?<[A-Za-z_][^>]*>/.exec(rest);
            if (named) {
                out += "(?:";
                i += named[0].length;
                continue;
            }

            // Lookarounds are supported by JavaScript; pass them through.
            if (/^\(\?(?:=|!|<=|<!)/.test(rest)) {
                const len = rest.startsWith("(?<") ? 4 : 3;
                out += pattern.slice(i, i + len);
                i += len;
                continue;
            }

            if (rest.startsWith("(?:")) {
                out += "(?:";
                i += 3;
                continue;
            }

            // Inline flag groups: `(?flags)` or `(?flags:…)`.
            const flagMatch = /^\(\?([a-zA-Z]*)(-?)([a-zA-Z]*)(:|\))/.exec(rest);
            if (flagMatch) {
                const enableFlags = flagMatch[1];
                const closing = flagMatch[4];
                if (enableFlags.includes("i")) caseInsensitive = true;
                if (enableFlags.includes("s")) dotAll = true;
                if (enableFlags.includes("m")) multiline = true;
                i += flagMatch[0].length;
                out += closing === ":" ? "(?:" : "";
                continue;
            }
        }

        out += ch;
        i++;
    }

    pattern = out;

    let flags = "g";
    if (caseInsensitive) flags += "i";
    if (dotAll) flags += "s";
    if (multiline) flags += "m";

    pattern = pattern.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

    return { pattern, flags };
}

function escapeForRegExpString(str: string): string {
    return str.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function generateRulesFile(parsedRules: TomlRule[]): string {
    const lines: string[] = [];

    lines.push("import type { Rule } from \"./types.js\";");
    lines.push("");
    lines.push("export type { Rule };");
    lines.push("");
    lines.push("/**");
    lines.push(" * Named rules compiled from gitleaks TOML (MIT) + clean-room additions.");
    lines.push(" * All regexes are pre-compiled at build time.");
    lines.push(" *");
    lines.push(" * Secret detection rules vendored from gitleaks/gitleaks (MIT License)");
    lines.push(" * https://github.com/gitleaks/gitleaks");
    lines.push(" */");
    lines.push("");
    lines.push("export const NAMED_RULES: Rule[] = [");

    for (const rule of parsedRules) {
        if (!rule.id || !rule.regex) continue;

        const keywords = rule.keywords && rule.keywords.length > 0
            ? `[${rule.keywords.map((k) => `"${k}"`).join(", ")}]`
            : "[]";

        const entropy = rule.entropy !== undefined ? `, entropy: ${rule.entropy}` : "";

        const desc = (rule.description || "").replace(/\\/g, "\\\\").replace(/"/g, '\\"');

        const { pattern: regexPattern, flags } = processGitleaksRegex(rule.regex);
        const regexExpr = flags
            ? `new RegExp("${regexPattern}", "${flags}")`
            : `new RegExp("${regexPattern}")`;

        lines.push("  {");
        lines.push(`    id: "${rule.id}",`);
        lines.push(`    description: "${desc}",`);
        lines.push(`    regex: ${regexExpr},`);
        lines.push(`    keywords: ${keywords}${entropy},`);
        lines.push("  },");
    }

    lines.push("];");
    lines.push("");

    lines.push("/**");
    lines.push(" * Clean-room additions for providers not covered by gitleaks.");
    lines.push(" * Independently written — no code copied from any AGPL source.");
    lines.push(" */");
    lines.push("");
    lines.push("export const CLEAN_ROOM_RULES: Rule[] = [");

    const cleanRoomRules = [
        {
            id: "groq-api-key",
            description: "Detected a Groq API key, risking unauthorized access to AI inference services.",
            regex: /\b(gsk_[a-zA-Z0-9]{52})\b/g,
        },
        {
            id: "deepseek-api-key",
            description: "Detected a DeepSeek API key, posing a risk of unauthorized access to AI models.",
            regex: /deepseek[\s\S]{0,30}\b(sk-[a-z0-9]{32})\b/gi,
        },
        {
            id: "replicate-api-token",
            description: "Found a Replicate API token, potentially compromising ML model deployments.",
            regex: /\b(r8_[0-9A-Za-z_-]{37})\b/g,
        },
        {
            id: "elevenlabs-api-key",
            description: "Detected an ElevenLabs API key, risking unauthorized voice synthesis access.",
            regex: /(?:elevenlabs|xi-api-key)[\s\S]{0,30}\b(sk_[a-f0-9]{48})\b/gi,
        },
        {
            id: "wandb-api-key",
            description: "Found a Weights & Biases API key, potentially compromising ML experiment tracking.",
            regex: /(?:wandb|weights\.?and\.?biases)[\s\S]{0,30}\b([a-zA-Z0-9]{40})\b/gi,
            keywords: ["wandb", "weights"],
            entropy: 3.5,
        },
        {
            id: "langsmith-api-key",
            description: "Detected a LangSmith API key, risking unauthorized LLM observability access.",
            regex: /\b(lsv2_[a-zA-Z0-9]+)\b/g,
        },
        {
            id: "langfuse-api-key",
            description: "Found a LangFuse API key, potentially compromising LLM monitoring.",
            regex: /\b(lf-api-[a-zA-Z0-9]+)\b/g,
        },
        {
            id: "supabase-token",
            description: "Detected a Supabase token, risking unauthorized database access.",
            regex: /\b(sbp_[a-zA-Z0-9]{40})\b/g,
        },
        {
            id: "vercel-token",
            description: "Found a Vercel token, potentially compromising deployment access.",
            regex: /\b(vercel_[a-zA-Z0-9_]+)\b/g,
        },
        {
            id: "mongodb-connection-string",
            description: "Detected a MongoDB connection string with embedded credentials.",
            regex: /mongodb(?:\+srv)?:\/\/[^ ]+:[^ ]+@/g,
        },
        {
            id: "postgresql-connection-string",
            description: "Detected a PostgreSQL connection string with embedded credentials.",
            regex: /postgres(?:ql)?:\/\/[^ ]+:[^ ]+@/g,
        },
        {
            id: "redis-connection-string",
            description: "Detected a Redis connection string with embedded credentials.",
            regex: /rediss?:\/\/[^ ]+:[^ ]+@/g,
        },
    ];

    for (const rule of cleanRoomRules) {
        const keywords = rule.keywords ? `[${rule.keywords.map((k) => `"${k}"`).join(", ")}]` : "[]";
        // Get the regex source and flags from the RegExp object directly
        const regexSource = rule.regex.source;
        const flags = rule.regex.flags;
        const entropy = rule.entropy !== undefined ? `, entropy: ${rule.entropy}` : "";
        const desc = rule.description.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
        // Escape for string literal
        const escapedSource = regexSource.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

        lines.push("  {");
        lines.push(`    id: "${rule.id}",`);
        lines.push(`    description: "${desc}",`);
        lines.push(`    regex: new RegExp("${escapedSource}", "${flags}"),`);
        lines.push(`    keywords: ${keywords}${entropy},`);
        lines.push("  },");
    }

    lines.push("];");
    lines.push("");

    lines.push("/**");
    lines.push(" * Entropy-based rules for catching high-entropy strings that don't match named patterns.");
    lines.push(" * Approach inspired by detect-secrets (Apache-2.0), independently implemented.");
    lines.push(" */");
    lines.push("");
    lines.push("export const ENTROPY_RULES: Rule[] = [");

    const entropyRules = [
        {
            id: "entropy-base64",
            description: "Detected a high-entropy Base64-encoded string that may be a secret.",
            regex: /(?:=|:)[ \t]*["']([A-Za-z0-9+/]{20,}={0,2})["']/g,
            entropy: 4.5,
        },
        {
            id: "entropy-hex",
            description: "Detected a high-entropy hex-encoded string that may be a secret.",
            regex: /(?:=|:)[ \t]*["']([0-9a-fA-F]{20,})["']/g,
            entropy: 3.0,
        },
        {
            id: "entropy-alphanumeric",
            description: "Detected a high-entropy alphanumeric string that may be a secret.",
            regex: /(?:=|:)[ \t]*["']([A-Za-z0-9]{30,})["']/g,
            entropy: 4.0,
        },
    ];

    for (const rule of entropyRules) {
        const regexSource = rule.regex.source;
        const escapedSource = regexSource.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
        const desc = rule.description.replace(/\\/g, "\\\\").replace(/"/g, '\\"');

        lines.push("  {");
        lines.push(`    id: "${rule.id}",`);
        lines.push(`    description: "${desc}",`);
        lines.push(`    regex: new RegExp("${escapedSource}", "g"),`);
        lines.push(`    keywords: [],`);
        lines.push(`    entropy: ${rule.entropy},`);
        lines.push("  },");
    }

    lines.push("];");
    lines.push("");
    lines.push(`// Total rules: ${parsedRules.length} (gitleaks) + ${cleanRoomRules.length} (clean-room) + ${entropyRules.length} (entropy)`);

    return lines.join("\n");
}

function main(): void {
    console.log("Compiling rules from gitleaks TOML...");

    const tomlContent = readFileSync(TOML_PATH, "utf8");
    const parsedRules = parseGitleaksToml(tomlContent);

    console.log(`Parsed ${parsedRules.length} rules from gitleaks TOML`);

    const output = generateRulesFile(parsedRules);
    writeFileSync(OUTPUT_PATH, output, "utf8");

    console.log(`Written compiled rules to ${OUTPUT_PATH}`);
}

main();